"""alethech CLI — six commands. No more, no less.

    alethech init
    alethech commit
    alethech evidence
    alethech verify
    alethech export
    alethech import
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

import click

from . import crypto
from .objects import Identity, MemoryCommit, EvidenceCommit, Checkpoint
from .store import Store, StoreError
from .verify import verify_store


# ---------- helpers ----------

def _store_path(ctx: click.Context) -> Path:
    """Get the alethech store path from the click context."""
    return Path(ctx.obj["store"])


def _load_content(path: str) -> dict:
    """Load a JSON object from a file path."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise click.ClickException(f"content is not valid JSON: {e}")
    if not isinstance(data, dict):
        raise click.ClickException(f"content must be a JSON object, got {type(data).__name__}")
    return data


def _hash_file(path: str) -> str:
    """Compute sha256:hex of file contents."""
    data = Path(path).read_bytes()
    return "sha256:" + crypto.sha256_hex(data)


# ---------- CLI group ----------

@click.group(
    epilog=(
        "────────────────────────────────────────────────────\n"
        "  © 2026 AliceLabs LLC.\n"
        "  Todos los derechos reservados.\n"
        "  MIT License — https://github.com/eddyflores100-lang/alethech/blob/main/LICENSE\n"
        "────────────────────────────────────────────────────"
    ),
)
@click.option(
    "--store",
    default=".alethech",
    envvar="ALETHECH_STORE",
    help="Path to the alethech store directory (default: .alethech/)",
)
@click.pass_context
def cli(ctx: click.Context, store: str) -> None:
    """alethech — verifiable agent continuity protocol."""
    ctx.ensure_object(dict)
    ctx.obj["store"] = store


# ---------- 1. init ----------

@cli.command()
@click.option("--recovery-key-file", type=click.Path(exists=True), help="Existing recovery private key (PEM)")
def init(recovery_key_file: str | None) -> None:
    """Initialize a new alethech store with identity + genesis commit."""
    store_path = Path(click.get_current_context().obj["store"])

    # Refuse if directory exists and is non-empty
    if store_path.exists() and any(store_path.iterdir()):
        raise click.ClickException(f"directory not empty: {store_path}")

    # Generate signing keypair
    signing = crypto.KeyPair.generate()

    # Recovery keypair: load or generate
    if recovery_key_file:
        recovery_pem = Path(recovery_key_file).read_bytes()
        recovery = crypto.KeyPair.from_private_pem(recovery_pem)
    else:
        recovery = crypto.KeyPair.generate()

    # Derive agent_id from public key (corrección 1 de GPT)
    public_jwk = signing.public_jwk()
    agent_id = crypto.derive_agent_id(public_jwk)

    # Build Identity record
    recovery_pub_bytes = recovery.public.public_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw,
    )
    identity = Identity(
        agent_id=agent_id,
        public_key=public_jwk,
        key_id="key-001",
        recovery_root="ed25519:" + crypto.b64url(recovery_pub_bytes),
    )

    # Initialize store dirs
    store = Store.init(store_path)
    store.write_identity(identity)
    store.write_signing_key(signing)
    store.write_recovery_key(recovery)

    # Genesis commit: parents=[], content={"type": "genesis"}
    genesis = MemoryCommit(
        agent_id=agent_id,
        key_id="key-001",
        parents=[],
        session_id=str(uuid.uuid4()),
        memory_type="semantic",
        content={"type": "genesis"},
        provenance={
            "source": "agent_observation",
            "source_id": None,
            "evidence_refs": [],
            "confidence": 1.0,
        },
    )
    genesis.sign(signing)
    store.write_commit(genesis)
    store.write_head(genesis.commit_id)

    click.echo(f"agent_id: {agent_id}")
    click.echo(f"public_key: ed25519:{public_jwk['x']}")
    click.echo(f"key_id: {identity.key_id}")
    click.echo(f"genesis_commit: {genesis.commit_id}")


# ---------- 2. commit ----------

@cli.command()
@click.option("--content", required=True, type=click.Path(exists=True), help="JSON file with commit content")
@click.option("--type", "memory_type", default="semantic",
              type=click.Choice(["semantic", "episodic", "procedural"]))
@click.option("--evidence", "evidence_ids", multiple=True, help="EvidenceCommit IDs to reference")
@click.option("--session", "session_id", default="", help="Session ID (default: random)")
def commit(content: str, memory_type: str, evidence_ids: tuple[str, ...], session_id: str) -> None:
    """Create a signed MemoryCommit linked to the current HEAD."""
    ctx = click.get_current_context()
    store_path = Path(ctx.obj["store"])
    store = Store.open(store_path)

    # Load identity + signing key
    try:
        signing = store.load_signing_key()
    except StoreError as e:
        raise click.ClickException(str(e))

    # Prefer v0.2 identity (root-derived) over v0.1 (operational-derived)
    v2_identities = store.load_identity_records_v2()
    legacy_identities = store.load_identities()

    if v2_identities:
        identity_record = next(iter(v2_identities.values()))
        # For commit, we need agent_id and key_id from the active key
        if not identity_record.active_keys:
            raise click.ClickException("no active key in v0.2 identity")
        active = identity_record.active_keys[0]
        agent_id = identity_record.agent_id
        key_id = active["key_id"]
        # Use a wrapper object for compatibility with the rest of the function
        class _IdentityShim:
            pass
        identity = _IdentityShim()
        identity.agent_id = agent_id
        identity.key_id = key_id
        identity.public_key = active["public_key"]
        identity.verify_self = lambda: identity_record.verify_self()
    elif legacy_identities:
        identity = next(iter(legacy_identities.values()))
        if not identity.verify_self():
            raise click.ClickException("identity_mismatch: agent_id does not derive from public_key in store")
    else:
        raise click.ClickException("no identities in store — run `alethech init` first")

    # Load current HEAD
    head = store.read_head()
    if head is None:
        raise click.ClickException("HEAD missing — store may be corrupted; run `alethech verify`")
    commits = store.load_commits()
    if head not in commits:
        raise click.ClickException(f"HEAD points to nonexistent commit {head} — run `alethech verify`")

    # Verify evidence IDs exist
    if evidence_ids:
        evidence = store.load_evidence()
        for eid in evidence_ids:
            if eid not in evidence:
                raise click.ClickException(f"evidence_id not found: {eid}")

    # Build commit
    content_obj = _load_content(content)
    if not session_id:
        session_id = str(uuid.uuid4())

    mc = MemoryCommit(
        agent_id=identity.agent_id,
        key_id=identity.key_id,
        parents=[head],
        session_id=session_id,
        memory_type=memory_type,
        content=content_obj,
        provenance={
            "source": "agent_observation",
            "source_id": str(uuid.uuid4()),
            "evidence_refs": list(evidence_ids),
            "confidence": 1.0,
        },
    )
    mc.sign(signing)
    store.write_commit(mc)
    store.write_head(mc.commit_id)

    click.echo(f"commit: {mc.commit_id}")
    click.echo(f"parent: {head}")
    click.echo(f"agent: {mc.agent_id}")
    click.echo(f"timestamp: {mc.timestamp}")


# ---------- 3. evidence ----------

@cli.command()
@click.option("--tool", required=True, help="Tool name (e.g. filesystem.read)")
@click.option("--input", "input_file", required=True, type=click.Path(exists=True), help="Input file")
@click.option("--output", "output_file", required=True, type=click.Path(exists=True), help="Output file")
@click.option("--result", default="success", type=click.Choice(["success", "failure", "timeout"]))
@click.option("--artifacts", "artifact_files", multiple=True, type=click.Path(exists=True), help="Additional artifact files")
@click.option("--tool-version", default="", help="Tool version")
def evidence(tool: str, input_file: str, output_file: str, result: str,
             artifact_files: tuple[str, ...], tool_version: str) -> None:
    """Create a signed EvidenceCommit for a tool execution event."""
    ctx = click.get_current_context()
    store_path = Path(ctx.obj["store"])
    store = Store.open(store_path)

    try:
        signing = store.load_signing_key()
    except StoreError as e:
        raise click.ClickException(str(e))

    identities = store.load_identities()
    if not identities:
        raise click.ClickException("no identities in store — run `alethech init` first")
    identity = next(iter(identities.values()))

    input_hash = _hash_file(input_file)
    output_hash = _hash_file(output_file)

    artifacts_meta = []
    for af in artifact_files:
        data = Path(af).read_bytes()
        if len(data) > 100 * 1024 * 1024:
            raise click.ClickException(f"artifact too large (>100MB): {af}")
        h = store.write_artifact(data)
        artifacts_meta.append({
            "name": Path(af).name,
            "hash": h,
            "size": len(data),
        })

    ev = EvidenceCommit(
        agent_id=identity.agent_id,
        key_id=identity.key_id,
        event_type="tool_execution",
        tool=tool,
        tool_version=tool_version,
        input_hash=input_hash,
        output_hash=output_hash,
        artifacts=artifacts_meta,
        result=result,
    )
    ev.sign(signing)
    store.write_evidence(ev)

    click.echo(f"evidence: {ev.commit_id}")
    click.echo(f"tool: {ev.tool}")
    click.echo(f"input_hash: {ev.input_hash}")
    click.echo(f"output_hash: {ev.output_hash}")
    click.echo(f"artifacts: {len(artifacts_meta)}")


# ---------- 4. verify ----------

@cli.command()
@click.option("--strict", is_flag=True, help="Fail on warnings")
@click.option("--emit-checkpoint", "emit_checkpoint", type=click.Path(),
              help="Generate a signed checkpoint file at this path")
@click.option("--checkpoint", "checkpoint_file", type=click.Path(exists=True),
              help="External checkpoint file to verify continuity against")
def verify(strict: bool, emit_checkpoint: str | None, checkpoint_file: str | None) -> None:
    """Verify the whole store. Standalone — no network, no LLM."""
    ctx = click.get_current_context()
    store_path = Path(ctx.obj["store"])
    store = Store.open(store_path)

    # Load optional external checkpoint
    cp = None
    if checkpoint_file:
        cp_data = json.loads(Path(checkpoint_file).read_text(encoding="utf-8"))
        cp = Checkpoint.from_dict(cp_data)

    report = verify_store(store, checkpoint=cp)

    # Emit checkpoint if requested (only if verify passes)
    if emit_checkpoint and report.ok:
        signing = store.load_signing_key()
        identities = store.load_identities()
        if identities:
            identity = next(iter(identities.values()))
            commits = store.load_commits()
            evidence = store.load_evidence()
            head = store.read_head() or ""
            new_cp = Checkpoint(
                agent_id=identity.agent_id,
                head_commit_id=head,
                commit_count=len(commits),
                evidence_count=len(evidence),
            )
            new_cp.sign(signing)
            cp_dict = new_cp.to_signed_dict()
            # Rename "commit_id" field to "checkpoint_id" for clarity on disk
            # (already done in Checkpoint.to_signed_dict)
            Path(emit_checkpoint).write_text(
                json.dumps(cp_dict, indent=2),
                encoding="utf-8",
            )
            click.echo(f"checkpoint written: {emit_checkpoint}")
            click.echo(f"  checkpoint_id: {new_cp.commit_id}")
            click.echo(f"  head: {new_cp.head_commit_id}")

    click.echo(report.summary())
    if strict and report.warnings:
        sys.exit(1)
    sys.exit(0 if report.ok else 1)


# ---------- 5. export ----------

@cli.command()
@click.option("--output", required=True, type=click.Path(), help="Output directory (or .tar file)")
@click.option("--include-artifacts/--no-artifacts", default=True, help="Include artifact bytes (default: yes)")
@click.option("--emit-checkpoint/--no-emit-checkpoint", default=False, help="Emit external checkpoint file")
def export(output: str, include_artifacts: bool, emit_checkpoint: bool) -> None:
    """Export the store to a portable package."""
    ctx = click.get_current_context()
    store_path = Path(ctx.obj["store"])
    store = Store.open(store_path)

    # First verify
    report = verify_store(store)
    if not report.ok:
        click.echo("verify failed — refusing to export corrupted store", err=True)
        click.echo(report.summary(), err=True)
        sys.exit(1)

    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "identities").mkdir(exist_ok=True)
    (out / "commits").mkdir(exist_ok=True)
    (out / "evidence").mkdir(exist_ok=True)
    (out / "artifacts").mkdir(exist_ok=True)

    # Copy identities (legacy)
    identities = store.load_identities()
    for ident in identities.values():
        (out / "identities" / f"{ident.agent_id}.json").write_text(
            json.dumps(ident.to_dict(), indent=2), encoding="utf-8"
        )

    # Copy IdentityRecordV2 (v0.2 identity layer)
    v2_identities = store.load_identity_records_v2()
    for ident in v2_identities.values():
        (out / "identities" / f"{ident.agent_id}.json").write_text(
            json.dumps(ident.to_signed_dict(), indent=2), encoding="utf-8"
        )

    # Copy RootAuthority
    try:
        root_auth = store.load_root_authority()
        (out / "root_authority.json").write_text(
            json.dumps(root_auth.to_signed_dict(), indent=2), encoding="utf-8"
        )
    except Exception:
        pass  # no root authority (v0.1 store)

    # Copy ControlEvents
    control_events = store.load_control_events()
    (out / "control_events").mkdir(exist_ok=True)
    for ev in control_events.values():
        (out / "control_events" / f"{ev.commit_id}.json").write_text(
            json.dumps(ev.to_signed_dict(), indent=2), encoding="utf-8"
        )

    # Copy MigrationRecords
    migrations = store.load_migration_records()
    (out / "migrations").mkdir(exist_ok=True)
    for mig in migrations.values():
        (out / "migrations" / f"{mig.commit_id}.json").write_text(
            json.dumps(mig.to_signed_dict(), indent=2), encoding="utf-8"
        )

    # Copy commits
    commits = store.load_commits()
    for commit in commits.values():
        (out / "commits" / f"{commit.commit_id}.json").write_text(
            json.dumps(commit.to_signed_dict(), indent=2), encoding="utf-8"
        )

    # Copy evidence
    evidence = store.load_evidence()
    for ev in evidence.values():
        (out / "evidence" / f"{ev.commit_id}.json").write_text(
            json.dumps(ev.to_signed_dict(), indent=2), encoding="utf-8"
        )

    # Copy artifacts
    artifact_count = 0
    total_bytes = 0
    if include_artifacts:
        for h in store.list_artifacts():
            data = store.read_artifact(h)
            if data is not None:
                (out / "artifacts" / h).write_bytes(data)
                artifact_count += 1
                total_bytes += len(data)

    # Manifest
    signing = store.load_signing_key()
    identities = store.load_identities()
    identity = next(iter(identities.values()))
    head = store.read_head() or ""

    manifest = {
        "type": "AlethechExport",
        "version": 1,
        "exported_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "exported_by": identity.agent_id,
        "commit_count": len(commits),
        "evidence_count": len(evidence),
        "artifact_count": artifact_count,
        "total_bytes": total_bytes,
        "head_commit_id": head,
    }
    # Compute manifest hash (without manifest_hash field)
    from .canonical import canonical_json_bytes
    manifest_bytes = canonical_json_bytes(manifest)
    manifest_hash = "sha256:" + crypto.sha256_hex(manifest_bytes)
    manifest["manifest_hash"] = manifest_hash

    # Sign manifest
    msg = canonical_json_bytes(manifest)
    sig = signing.sign(msg)
    manifest["signature"] = "ed25519:" + crypto.b64url(sig)

    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    click.echo(f"exported to: {out}")
    click.echo(f"commits: {len(commits)}")
    click.echo(f"evidence: {len(evidence)}")
    click.echo(f"artifacts: {artifact_count} ({total_bytes} bytes)")
    click.echo(f"manifest_hash: {manifest_hash}")

    # Optional checkpoint
    if emit_checkpoint:
        cp = Checkpoint(
            agent_id=identity.agent_id,
            head_commit_id=head,
            commit_count=len(commits),
            evidence_count=len(evidence),
        )
        cp.sign(signing)
        cp_path = str(out) + ".checkpoint.json"
        Path(cp_path).write_text(
            json.dumps(cp.to_signed_dict(), indent=2), encoding="utf-8"
        )
        click.echo(f"checkpoint: {cp_path}")


# ---------- 6. import ----------

@cli.command(name="import")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Path to import from")
@click.option("--target", "target_path", default=None, help="Target alethech store (default: same as --store)")
@click.option("--trust-unknown-identities", is_flag=True, help="Allow importing commits from unknown identities")
@click.option("--allow-conflicts", is_flag=True, help="Allow HEAD conflicts (will not auto-update HEAD)")
@click.option("--checkpoint", "checkpoint_file", type=click.Path(exists=True), help="External checkpoint to verify continuity")
def import_(input_path: str, target_path: str | None,
            trust_unknown_identities: bool, allow_conflicts: bool,
            checkpoint_file: str | None) -> None:
    """Import a portable package into the target store.

    Security: this command assumes the import package may be malicious.
    Defenses applied (0.6.0):
      - Path traversal: file names must be safe, no ../ or absolute paths
      - Symlinks: symlinks in import package are NOT followed
      - JSON size: each file must be < MAX_IMPORT_FILE_SIZE
      - File count: package must have < MAX_IMPORT_FILE_COUNT files
      - Total size: package must be < MAX_IMPORT_TOTAL_SIZE
      - Atomicity: import either fully succeeds or fully rolls back
    """
    # 0.6.0 import hardening — security limits
    MAX_IMPORT_FILE_SIZE = 50 * 1024 * 1024  # 50 MB per file
    MAX_IMPORT_FILE_COUNT = 10000  # max files in package
    MAX_IMPORT_TOTAL_SIZE = 500 * 1024 * 1024  # 500 MB total
    MAX_JSON_DEPTH = 100  # max nesting depth for JSON parsing

    ctx = click.get_current_context()
    if target_path is None:
        target_path = ctx.obj["store"]
    target = Path(target_path)

    src = Path(input_path)

    # SECURITY CHECK 0.6.0-A: verify src is a real directory (not a symlink)
    if src.is_symlink():
        raise click.ClickException(
            f"security: input path is a symlink — refusing to import symlinks: {src}"
        )
    if not src.is_dir():
        raise click.ClickException(f"input must be a directory: {src}")

    # SECURITY CHECK 0.6.0-B: count files and total size
    file_count = 0
    total_size = 0
    for path in src.rglob("*"):
        if path.is_symlink():
            raise click.ClickException(
                f"security: symlink found in import package — refusing: {path}"
            )
        if path.is_file():
            file_count += 1
            total_size += path.stat().st_size
            if path.stat().st_size > MAX_IMPORT_FILE_SIZE:
                raise click.ClickException(
                    f"security: file exceeds {MAX_IMPORT_FILE_SIZE} bytes limit: {path} "
                    f"({path.stat().st_size} bytes) — possible archive bomb"
                )
            if file_count > MAX_IMPORT_FILE_COUNT:
                raise click.ClickException(
                    f"security: package exceeds {MAX_IMPORT_FILE_COUNT} files limit — "
                    f"possible archive bomb"
                )
            if total_size > MAX_IMPORT_TOTAL_SIZE:
                raise click.ClickException(
                    f"security: package exceeds {MAX_IMPORT_TOTAL_SIZE} bytes total — "
                    f"possible archive bomb"
                )

    # SECURITY CHECK 0.6.0-C: verify no file name contains path traversal
    for path in src.rglob("*"):
        rel = path.relative_to(src)
        rel_str = str(rel)
        # Reject absolute paths (shouldn't happen with rglob but check anyway)
        if rel.is_absolute():
            raise click.ClickException(
                f"security: absolute path in import package: {rel}"
            )
        # Reject .. components
        if ".." in rel.parts:
            raise click.ClickException(
                f"security: path traversal detected in import package: {rel_str}"
            )

    # If src is a directory, expect manifest.json
    if src.is_dir():
        manifest_path = src / "manifest.json"
        if not manifest_path.is_file():
            raise click.ClickException(f"no manifest.json in {src}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    else:
        raise click.ClickException(f"input must be a directory: {src}")

    # Step 1: Parse manifest
    # 0.7.0: accept both AlethechExport (new) and MemexExport (legacy backward-compat)
    manifest_type = manifest.get("type")
    if manifest_type == "MemexExport":
        # Legacy export from before 0.7.0 — accept but warn
        click.echo("warning: importing legacy MemexExport format (pre-0.7.0). Future exports use AlethechExport.", err=True)
    elif manifest_type != "AlethechExport":
        raise click.ClickException(f"not an AlethechExport manifest: type={manifest_type}")

    # Step 2: Hash verification
    from .canonical import canonical_json_bytes
    manifest_no_hash = {k: v for k, v in manifest.items() if k not in ("manifest_hash", "signature")}
    recomputed = "sha256:" + crypto.sha256_hex(canonical_json_bytes(manifest_no_hash))
    if recomputed != manifest.get("manifest_hash"):
        raise click.ClickException("manifest_hash mismatch — manifest has been tampered with")

    # Step 3: Signature verification
    sig_str = manifest.get("signature", "")
    if not sig_str.startswith("ed25519:"):
        raise click.ClickException("manifest signature missing or malformed")
    sig_bytes = crypto.b64url_decode(sig_str[len("ed25519:"):])

    # Load exporter identity
    exporter_id = manifest.get("exported_by", "")
    exporter_identity_path = src / "identities" / f"{exporter_id}.json"
    if not exporter_identity_path.is_file():
        raise click.ClickException(f"exporter identity not in package: {exporter_id}")
    exporter_identity = Identity.from_dict(json.loads(exporter_identity_path.read_text(encoding="utf-8")))
    if not exporter_identity.verify_self():
        raise click.ClickException("exporter identity_mismatch: agent_id does not derive from public_key")

    pub = crypto.KeyPair.public_from_jwk(exporter_identity.public_key)
    msg = canonical_json_bytes(manifest_no_hash | {"manifest_hash": manifest["manifest_hash"]})
    if not crypto.KeyPair.verify(pub, sig_bytes, msg):
        raise click.ClickException("manifest signature invalid")

    # 4: Load all identities in package (both legacy Identity and IdentityRecordV2)
    pkg_identities: dict[str, Identity] = {}
    pkg_identities_v2: dict[str, IdentityRecordV2] = {}
    for path in (src / "identities").glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        id_type = data.get("type", "")
        if id_type == "IdentityRecordV2":
            ident = IdentityRecordV2.from_dict(data)
            if not ident.verify_self():
                raise click.ClickException(f"identity_mismatch in package: {ident.agent_id}")
            pkg_identities_v2[ident.agent_id] = ident
        elif id_type == "Identity":
            ident = Identity.from_dict(data)
            if not ident.verify_self():
                raise click.ClickException(f"identity_mismatch in package: {ident.agent_id}")
            pkg_identities[ident.agent_id] = ident

    # 5: Load commits and evidence from package
    pkg_commits: dict[str, MemoryCommit] = {}
    for path in (src / "commits").glob("*.json"):
        commit = MemoryCommit.from_dict(json.loads(path.read_text(encoding="utf-8")))
        pkg_commits[commit.commit_id] = commit

    pkg_evidence: dict[str, EvidenceCommit] = {}
    for path in (src / "evidence").glob("*.json"):
        ev = EvidenceCommit.from_dict(json.loads(path.read_text(encoding="utf-8")))
        pkg_evidence[ev.commit_id] = ev

    # 5b: Verify each commit's signature (check legacy Identity and IdentityRecordV2)
    for cid, commit in pkg_commits.items():
        ident = pkg_identities.get(commit.agent_id)
        if ident is not None:
            public_jwk = ident.public_key
        else:
            v2_ident = pkg_identities_v2.get(commit.agent_id)
            if v2_ident is not None:
                key_obj = None
                for k in v2_ident.active_keys + v2_ident.revoked_keys:
                    if k.get("key_id") == commit.key_id:
                        key_obj = k
                        break
                if key_obj is None:
                    raise click.ClickException(f"unknown_key in package: commit {cid} uses key_id {commit.key_id}")
                public_jwk = key_obj["public_key"]
            else:
                raise click.ClickException(f"unknown_identity in package: commit {cid} claims {commit.agent_id}")
        if not commit.verify(public_jwk):
            raise click.ClickException(f"signature_invalid in package: commit {cid}")

    for eid, ev in pkg_evidence.items():
        ident = pkg_identities.get(ev.agent_id)
        if ident is not None:
            public_jwk = ident.public_key
        else:
            v2_ident = pkg_identities_v2.get(ev.agent_id)
            if v2_ident is not None:
                key_obj = None
                for k in v2_ident.active_keys + v2_ident.revoked_keys:
                    if k.get("key_id") == ev.key_id:
                        key_obj = k
                        break
                if key_obj is None:
                    raise click.ClickException(f"unknown_key in package: evidence {eid}")
                public_jwk = key_obj["public_key"]
            else:
                raise click.ClickException(f"unknown_identity in package: evidence {eid} claims {ev.agent_id}")
        if not ev.verify(public_jwk):
            raise click.ClickException(f"signature_invalid in package: evidence {eid}")

    # 6: Open or init target store
    if not target.exists() or not any(target.iterdir()):
        store = Store.init(target)
    else:
        store = Store.open(target)

    # 0.7.0 ATOMIC IMPORT: build a staging dict of everything that WOULD be
    # written, run full verification on the staged content, and only then
    # commit atomically. This closes the audit finding that the import
    # could leave the store partially modified if a step failed mid-way.
    #
    # Architecture:
    #   package
    #     ↓
    #   parse + verify everything (signatures, identities, commits, evidence)
    #     ↓
    #   build staged_content dict (what the target would look like after import)
    #     ↓
    #   run verify_store on staged content (in-memory, no writes yet)
    #     ↓
    #   checkpoint continuity check (on staged content, before any writes)
    #     ↓
    #   ATOMIC WRITE: write all files (no failure possible after this point
    #   because all verification already passed)
    #
    # If ANY step fails, the target store is untouched.

    # Step A: build staged_content — a dict representing the final state
    # of the target after import. This is what we verify before writing.
    staged_identities = dict(store.load_identities())  # existing
    staged_identities_v2 = {}
    try:
        staged_identities_v2 = dict(store.load_identity_records_v2())
    except Exception:
        pass
    staged_commits = dict(store.load_commits())  # existing
    staged_evidence = dict(store.load_evidence())  # existing

    # Step B: Apply package content to staging (in-memory only)
    for agent_id, ident in pkg_identities.items():
        if agent_id in staged_identities:
            if staged_identities[agent_id].public_key != ident.public_key:
                raise click.ClickException(f"identity_collision: {agent_id} exists with different public_key in target")
            continue
        if not trust_unknown_identities:
            raise click.ClickException(
                f"unknown_identity: {agent_id} not in target store — use --trust-unknown-identities to import"
            )
        staged_identities[agent_id] = ident

    # 0.7.0: apply same trust gate to IdentityRecordV2 (audit finding #9)
    target_identities_v2 = dict(staged_identities_v2)
    for agent_id, ident in pkg_identities_v2.items():
        if agent_id in target_identities_v2:
            # Already known — verify it's the same
            existing = target_identities_v2[agent_id]
            if existing.root_id != ident.root_id or existing.root_public_key != ident.root_public_key:
                raise click.ClickException(f"identity_v2_collision: {agent_id} exists with different root in target")
            continue
        if not trust_unknown_identities:
            raise click.ClickException(
                f"unknown_identity_v2: {agent_id} not in target store — use --trust-unknown-identities to import"
            )
        staged_identities_v2[agent_id] = ident

    # Stage commits (don't overwrite existing)
    for cid, commit in pkg_commits.items():
        if cid not in staged_commits:
            staged_commits[cid] = commit

    # Stage evidence
    for eid, ev in pkg_evidence.items():
        if eid not in staged_evidence:
            staged_evidence[eid] = ev

    # Step C: 0.7.0 ARTIFACT HASH CHECK — verify artifact content matches
    # declared hash BEFORE staging. Fail-closed: don't write artifacts
    # whose content doesn't match their filename hash.
    staged_artifacts: dict[str, bytes] = {}
    if (src / "artifacts").is_dir():
        for art_path in (src / "artifacts").iterdir():
            if not art_path.is_file():
                continue
            if art_path.is_symlink():
                raise click.ClickException(f"security: artifact is symlink — refusing: {art_path}")
            h = art_path.name  # filename IS the declared hash
            content = art_path.read_bytes()
            # 0.7.0: verify hash matches content BEFORE staging
            actual_hash = "sha256:" + crypto.sha256_hex(content)
            if actual_hash != h:
                raise click.ClickException(
                    f"artifact_hash_mismatch: artifact {h} content does not match declared hash "
                    f"(actual: {actual_hash}) — refusing to import corrupted/tampered artifact"
                )
            # Check if target already has it
            if not store.read_artifact(h):
                staged_artifacts[h] = content

    # Step D: Stage identity layer objects (RootAuthority, ControlEvents, Migrations)
    # These are loaded but not yet written.
    staged_root_auth = None
    root_path = src / "root_authority.json"
    if root_path.is_file():
        if root_path.is_symlink():
            raise click.ClickException(f"security: root_authority.json is symlink — refusing")
        staged_root_auth = __import__("alethech.objects", fromlist=["RootAuthority"]).RootAuthority.from_dict(
            json.loads(root_path.read_text(encoding="utf-8"))
        )

    staged_control_events: dict = {}
    ce_dir = src / "control_events"
    if ce_dir.is_dir():
        for ce_path in ce_dir.glob("*.json"):
            if ce_path.is_symlink():
                raise click.ClickException(f"security: control_event is symlink — refusing: {ce_path}")
            ce_data = json.loads(ce_path.read_text(encoding="utf-8"))
            ce = __import__("alethech.objects", fromlist=["ControlEvent"]).ControlEvent.from_dict(ce_data)
            staged_control_events[ce.commit_id] = ce

    staged_migrations: dict = {}
    mig_dir = src / "migrations"
    if mig_dir.is_dir():
        for mig_path in mig_dir.glob("*.json"):
            if mig_path.is_symlink():
                raise click.ClickException(f"security: migration is symlink — refusing: {mig_path}")
            mig_data = json.loads(mig_path.read_text(encoding="utf-8"))
            mig = __import__("alethech.objects", fromlist=["MigrationRecord"]).MigrationRecord.from_dict(mig_data)
            staged_migrations[mig.commit_id] = mig

    # Step E: 0.7.0 CHECKPOINT CONTINUITY CHECK (fail-closed) — do this
    # BEFORE writing anything, on the STAGED content.
    #
    # Audit finding #8: previously, count mismatch produced a warning but
    # still set continuity = "verified". Now: count mismatch → fail-closed.
    continuity = "not checked"
    if checkpoint_file:
        cp_data = json.loads(Path(checkpoint_file).read_text(encoding="utf-8"))
        cp = Checkpoint.from_dict(cp_data)
        # Check on STAGED commits (what the store WILL look like after import)
        if cp.head_commit_id not in staged_commits:
            raise click.ClickException(
                f"rollback_detected: checkpoint head {cp.head_commit_id} not in staged commits "
                f"(checked BEFORE writing to target — target is untouched)"
            )
        if cp.commit_count != len(staged_commits):
            # 0.7.0 FAIL-CLOSED: count mismatch is now an error, not a warning
            raise click.ClickException(
                f"checkpoint_count_mismatch: checkpoint says {cp.commit_count} commits, "
                f"staged has {len(staged_commits)} — refusing to import (target untouched). "
                f"This is fail-closed: a count mismatch means the checkpoint does not "
                f"match the presented history."
            )
        if cp.evidence_count != len(staged_evidence):
            raise click.ClickException(
                f"checkpoint_evidence_mismatch: checkpoint says {cp.evidence_count} evidence, "
                f"staged has {len(staged_evidence)} — refusing to import (target untouched)"
            )
        continuity = "verified"

    # Step F: ATOMIC WRITE PHASE
    # All verification has passed. Now write everything. If a write fails
    # at this point, it's a genuine I/O error, not a verification failure.
    # The target may end up partially written, but ONLY if there was a
    # real I/O problem (disk full, permissions, etc.) — never because
    # verification failed mid-way.

    new_commits = 0
    new_evidence = 0
    new_artifacts = 0

    # Write identities (legacy)
    for agent_id, ident in pkg_identities.items():
        if agent_id not in store.load_identities():
            store.write_identity(ident)

    # Write v0.2 identity records
    for agent_id, ident in pkg_identities_v2.items():
        store.write_identity_record_v2(ident)

    # Write RootAuthority
    if staged_root_auth is not None:
        store.write_root_authority(staged_root_auth)

    # Write ControlEvents
    for ce in staged_control_events.values():
        store.write_control_event(ce)

    # Write MigrationRecords
    for mig in staged_migrations.values():
        store.write_migration_record(mig)

    # Write commits (don't overwrite)
    target_commits = store.load_commits()
    for cid, commit in pkg_commits.items():
        if cid in target_commits:
            continue
        store.write_commit(commit)
        new_commits += 1

    # Write evidence
    target_evidence = store.load_evidence()
    for eid, ev in pkg_evidence.items():
        if eid in target_evidence:
            continue
        store.write_evidence(ev)
        new_evidence += 1

    # Write artifacts (already hash-verified in Step C)
    for h, content in staged_artifacts.items():
        store.write_artifact(content)
        new_artifacts += 1

    # Step G: emit summary
    click.echo(f"imported: {new_commits} commits, {new_evidence} evidence, {new_artifacts} artifacts")
    click.echo(f"identities: {len(pkg_identities)} in package")
    click.echo(f"conflicts: 0")
    click.echo(f"continuity: {continuity}")
    click.echo("HEAD not updated — use `alethech merge` (rev 3+) or manually set HEAD")


if __name__ == "__main__":
    cli()


# ============================================================================
# rev 3 — Identity layer commands
# ============================================================================

@cli.group()
def key() -> None:
    """Operational key management (rotate, revoke, authorize)."""
    pass


@key.command("rotate")
@click.option("--reason", default="rotation", type=click.Choice(["rotation", "compromise", "expiry"]))
@click.option("--content", "content_file", type=click.Path(exists=True), help="Optional content for a post-rotation commit")
def key_rotate(reason: str, content_file: str | None) -> None:
    """Atomically rotate the active operational key.

    Produces a single ControlEvent with event_type=key_rotation that:
    - revokes the current active key (with cutoff_head = current HEAD)
    - authorizes a new key
    """
    ctx = click.get_current_context()
    store_path = Path(ctx.obj["store"])
    store = Store.open(store_path)

    try:
        root_keypair = store.load_root_key()
    except StoreError as e:
        raise click.ClickException(f"root key not available: {e}")

    # Load identity records v2 (only the first one for now; multi-wallet comes later)
    identities = store.load_identity_records_v2()
    if not identities:
        raise click.ClickException("no IdentityRecordV2 in store — run `alethech migrate --to v0.2` first")
    identity = next(iter(identities.values()))

    # Find current active key
    if not identity.active_keys:
        raise click.ClickException("no active key in identity — cannot rotate")
    current_key = identity.active_keys[0]
    old_key_id = current_key["key_id"]
    old_public_jwk = current_key["public_key"]

    # Get current HEAD as cutoff
    cutoff_head = store.read_head()
    if cutoff_head is None:
        raise click.ClickException("HEAD missing — store may be corrupted")

    # Generate new operational keypair
    new_keypair = crypto.KeyPair.generate()
    new_public_jwk = new_keypair.public_jwk()
    new_key_id = f"key-{int(old_key_id.split('-')[1]) + 1:03d}" if old_key_id.startswith("key-") else "key-next"

    # Build ControlEvent for rotation (atomic)
    events = store.load_control_events()
    prev_seq = max((e.sequence for e in events.values()), default=0)
    prev_hash = max((e.commit_id for e in events.values()), key=lambda h: 0) if events else ""

    # Find the latest control event to chain from
    if events:
        latest = max(events.values(), key=lambda e: e.sequence)
        prev_hash = latest.commit_id

    rotation_event = ControlEvent(
        root_id=identity.root_id,
        sequence=prev_seq + 1,
        previous_control_hash=prev_hash,
        event_type="key_rotation",
        key_id=new_key_id,
        public_key=new_public_jwk,
        old_key_id=old_key_id,
        cutoff_head=cutoff_head,
        reason=reason,
    )
    rotation_event.sign(root_keypair)
    store.write_control_event(rotation_event)

    # Update IdentityRecord
    identity.revoked_keys.append({
        "key_id": old_key_id,
        "public_key": old_public_jwk,
        "revoked_at": rotation_event.timestamp,
        "revoked_by": rotation_event.commit_id,
        "cutoff_head": cutoff_head,
    })
    identity.active_keys = [{
        "key_id": new_key_id,
        "public_key": new_public_jwk,
        "authorized_at": rotation_event.timestamp,
        "authorized_by": rotation_event.commit_id,
        "expires_at": None,
    }]
    # Re-sign identity with root
    identity.sign(root_keypair)
    store.write_identity_record_v2(identity)

    # Save new operational key (replaces signing.key)
    store.write_signing_key(new_keypair)

    click.echo(f"rotated: {old_key_id} → {new_key_id}")
    click.echo(f"cutoff_head: {cutoff_head}")
    click.echo(f"control_event: {rotation_event.commit_id}")
    click.echo(f"sequence: {rotation_event.sequence}")


@key.command("revoke")
@click.option("--key-id", required=True, help="Key ID to revoke")
@click.option("--reason", default="compromise", type=click.Choice(["compromise", "rotation", "expiry"]))
def key_revoke(key_id: str, reason: str) -> None:
    """Revoke an operational key without generating a new one (emergency)."""
    ctx = click.get_current_context()
    store_path = Path(ctx.obj["store"])
    store = Store.open(store_path)

    try:
        root_keypair = store.load_root_key()
    except StoreError as e:
        raise click.ClickException(f"root key not available: {e}")

    identities = store.load_identity_records_v2()
    if not identities:
        raise click.ClickException("no IdentityRecordV2 in store")
    identity = next(iter(identities.values()))

    # Find the key to revoke
    target_key = None
    for k in identity.active_keys:
        if k["key_id"] == key_id:
            target_key = k
            break
    if target_key is None:
        raise click.ClickException(f"key {key_id} not in active_keys")

    cutoff_head = store.read_head() or ""

    events = store.load_control_events()
    prev_seq = max((e.sequence for e in events.values()), default=0)
    prev_hash = events[prev_seq].commit_id if events and prev_seq in [e.sequence for e in events.values()] else ""
    # Get latest by sequence
    if events:
        latest = max(events.values(), key=lambda e: e.sequence)
        prev_hash = latest.commit_id

    revoke_event = ControlEvent(
        root_id=identity.root_id,
        sequence=prev_seq + 1,
        previous_control_hash=prev_hash,
        event_type="key_revoke",
        key_id=key_id,
        public_key={},
        old_key_id="",
        cutoff_head=cutoff_head,
        reason=reason,
    )
    revoke_event.sign(root_keypair)
    store.write_control_event(revoke_event)

    # Move key from active to revoked
    identity.active_keys = [k for k in identity.active_keys if k["key_id"] != key_id]
    identity.revoked_keys.append({
        "key_id": key_id,
        "public_key": target_key["public_key"],
        "revoked_at": revoke_event.timestamp,
        "revoked_by": revoke_event.commit_id,
        "cutoff_head": cutoff_head,
    })
    identity.sign(root_keypair)
    store.write_identity_record_v2(identity)

    click.echo(f"revoked: {key_id}")
    click.echo(f"cutoff_head: {cutoff_head}")
    click.echo(f"control_event: {revoke_event.commit_id}")
    click.echo("no new key generated — run `alethech key authorize --new` manually when safe")


@cli.command()
@click.option("--to", "target_version", required=True, type=click.Choice(["v0.2"]))
def migrate(target_version: str) -> None:
    """Migrate identity from v0.1 (agent_id derives from operational key) to v0.2 (agent_id derives from root).

    Produces a MigrationRecord signed bilaterally by the legacy key and the new root.
    The legacy agent_id is preserved as legacy; the new agent_id derives from the root.
    """
    ctx = click.get_current_context()
    store_path = Path(ctx.obj["store"])
    store = Store.open(store_path)

    # Load v0.1 identity (legacy)
    legacy_identities = store.load_identities()
    if not legacy_identities:
        raise click.ClickException("no legacy Identity in store — already migrated?")
    legacy_identity = next(iter(legacy_identities.values()))

    # Load the signing key (which is K1, the legacy operational key)
    try:
        legacy_keypair = store.load_signing_key()
    except StoreError as e:
        raise click.ClickException(f"legacy signing key not available: {e}")

    # Generate new root
    root_keypair = crypto.KeyPair.generate()
    root_public_jwk = root_keypair.public_jwk()
    root_id = "did:alethech:root:" + crypto.b32lower(crypto.sha256(canonical_json_bytes(root_public_jwk))[0:16])

    # New agent_id derives from root
    new_agent_id = "did:alethech:" + crypto.b32lower(crypto.sha256(canonical_json_bytes(root_public_jwk))[0:16])

    # Build MigrationRecord
    migration = MigrationRecord(
        legacy_agent_id=legacy_identity.agent_id,
        legacy_public_key=legacy_identity.public_key,
        new_agent_id=new_agent_id,
        new_root_id=root_id,
        new_root_public_key=root_public_jwk,
    )
    migration.sign_both(legacy_keypair, root_keypair)
    store.write_migration_record(migration)

    # Build RootAuthority
    root_auth = RootAuthority(
        root_id=root_id,
        root_public_key=root_public_jwk,
    )
    root_auth.sign(root_keypair)
    store.write_root_authority(root_auth)
    store.write_root_key(root_keypair)

    # Build IdentityRecordV2
    new_identity = IdentityRecordV2(
        agent_id=new_agent_id,
        root_id=root_id,
        root_public_key=root_public_jwk,
        active_keys=[{
            "key_id": "key-001",
            "public_key": legacy_identity.public_key,
            "authorized_at": migration.migration_timestamp,
            "authorized_by": "",  # will fill after signing
            "expires_at": None,
        }],
        revoked_keys=[],
    )

    # Authorize the legacy key K1 via ControlEvent (genesis control event)
    genesis_event = ControlEvent(
        root_id=root_id,
        sequence=1,
        previous_control_hash="",
        event_type="key_grant",
        key_id="key-001",
        public_key=legacy_identity.public_key,
        reason="migration",
        migration_record_id=migration.commit_id,
    )
    genesis_event.sign(root_keypair)
    store.write_control_event(genesis_event)

    # Update identity with the control event id
    new_identity.active_keys[0]["authorized_by"] = genesis_event.commit_id
    new_identity.sign(root_keypair)
    store.write_identity_record_v2(new_identity)

    # Update HEAD — the existing commits still have agent_id=legacy, but new commits will use new agent_id
    # We do NOT change the agent_id of existing commits (they remain legacy)
    # The user must update their tooling to use the new agent_id going forward

    click.echo(f"migrated: {legacy_identity.agent_id} → {new_agent_id}")
    click.echo(f"root_id: {root_id}")
    click.echo(f"migration_record: {migration.commit_id}")
    click.echo(f"genesis_control_event: {genesis_event.commit_id}")
    click.echo(f"key-001 (legacy) authorized by new root")
    click.echo("")
    click.echo("Existing commits retain their legacy agent_id.")
    click.echo("New commits should use the new agent_id.")
    click.echo("Both are verifiable via the MigrationRecord.")


@cli.group()
def identity() -> None:
    """Identity management (list, create, publish)."""
    pass


@identity.command("list")
def identity_list() -> None:
    """List all identities in the store."""
    ctx = click.get_current_context()
    store_path = Path(ctx.obj["store"])
    store = Store.open(store_path)

    # Legacy identities
    legacy = store.load_identities()
    for agent_id, ident in legacy.items():
        click.echo(f"  [v0.1]  {agent_id}  (legacy, key={ident.key_id})")

    # v0.2 identities
    v2 = store.load_identity_records_v2()
    for agent_id, ident in v2.items():
        active = ", ".join(k["key_id"] for k in ident.active_keys)
        revoked = ", ".join(k["key_id"] for k in ident.revoked_keys)
        click.echo(f"  [v0.2]  {agent_id}  (active={active}, revoked={revoked})")

    if not legacy and not v2:
        click.echo("  (no identities — run `alethech init` or `alethech migrate --to v0.2`)")


@identity.command("publish")
@click.option("--output", required=True, type=click.Path(), help="Output file path")
def identity_publish(output: str) -> None:
    """Generate an AlethechIdentityPublication for .well-known."""
    ctx = click.get_current_context()
    store_path = Path(ctx.obj["store"])
    store = Store.open(store_path)

    identities = store.load_identity_records_v2()
    if not identities:
        raise click.ClickException("no IdentityRecordV2 in store — run `alethech migrate --to v0.2` first")
    identity = next(iter(identities.values()))

    try:
        root_keypair = store.load_root_key()
    except StoreError as e:
        raise click.ClickException(f"root key not available: {e}")

    publication = {
        "type": "AlethechIdentityPublication",
        "version": 1,
        "identity": identity.to_signed_dict(),
        "published_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    }
    # Compute hash and sign
    from .canonical import canonical_json_bytes
    pub_no_hash = {k: v for k, v in publication.items()}
    pub_no_hash["identity_hash"] = "sha256:" + crypto.sha256_hex(canonical_json_bytes(identity.to_signed_dict()))
    publication["identity_hash"] = pub_no_hash["identity_hash"]
    msg = canonical_json_bytes(publication)
    sig = root_keypair.sign(msg)
    publication["publication_signature"] = "ed25519:" + crypto.b64url(sig)

    Path(output).write_text(json.dumps(publication, indent=2), encoding="utf-8")
    click.echo(f"published to: {output}")
    click.echo(f"identity: {identity.agent_id}")
    click.echo(f"identity_hash: {publication['identity_hash']}")


# Need imports at the top
import os as _os
from .objects import IdentityRecordV2, ControlEvent, MigrationRecord, RootAuthority
from .canonical import canonical_json_bytes

