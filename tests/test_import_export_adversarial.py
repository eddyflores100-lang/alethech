"""Adversarial tests for import/export — priority #1."""
import json
import shutil
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from alethech.cli import cli
from alethech.store import Store


@pytest.fixture
def tmp_stores():
    d = tempfile.mkdtemp(prefix="alethech-ie-")
    src = Path(d) / "src"
    tgt = Path(d) / "tgt"
    yield src, tgt, d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def populated_store(tmp_stores, runner):
    src, _, _ = tmp_stores
    runner.invoke(cli, ["--store", str(src), "init"])
    runner.invoke(cli, ["--store", str(src), "migrate", "--to", "v0.2"])
    c1 = src / "c1.json"
    c1.write_text(json.dumps({"v": 1}))
    runner.invoke(cli, ["--store", str(src), "commit", "--content", str(c1)])
    c2 = src / "c2.json"
    c2.write_text(json.dumps({"v": 2}))
    runner.invoke(cli, ["--store", str(src), "commit", "--content", str(c2)])
    return src


def _import_and_set_head(runner, tgt, export_dir):
    """Helper: import into target and set HEAD from manifest."""
    r = runner.invoke(cli, [
        "--store", str(tgt), "import", "--input", str(export_dir),
        "--trust-unknown-identities",
    ])
    manifest = json.loads((export_dir / "manifest.json").read_text())
    tgt.mkdir(parents=True, exist_ok=True)
    (tgt / "HEAD").write_text(manifest["head_commit_id"] + "\n")
    return r


class TestRoundtrip:
    def test_export_package_uses_cross_platform_filenames(self, populated_store, tmp_stores, runner):
        src, tgt, _ = tmp_stores
        export_dir = src.parent / "export-portable"
        r = runner.invoke(cli, ["--store", str(src), "export", "--output", str(export_dir)])
        assert r.exit_code == 0, r.output

        for directory in ("identities", "commits", "evidence", "artifacts", "control_events", "migrations"):
            d = export_dir / directory
            if not d.is_dir():
                continue
            for path in d.iterdir():
                if path.is_file():
                    assert ":" not in path.name, f"non-portable filename: {path}"
        assert any("%3A" in p.name for p in (export_dir / "commits").glob("*.json"))

        imported = runner.invoke(cli, [
            "--store", str(tgt), "import", "--input", str(export_dir),
            "--trust-unknown-identities",
        ])
        assert imported.exit_code == 0, imported.output

    def test_roundtrip(self, populated_store, tmp_stores, runner):
        src, tgt, _ = tmp_stores
        assert runner.invoke(cli, ["--store", str(src), "verify"]).exit_code == 0
        export_dir = src.parent / "export"
        assert runner.invoke(cli, ["--store", str(src), "export", "--output", str(export_dir)]).exit_code == 0
        assert _import_and_set_head(runner, tgt, export_dir).exit_code == 0
        r = runner.invoke(cli, ["--store", str(tgt), "verify"])
        assert r.exit_code == 0, f"target verify: {r.output}"
        assert "result: OK" in r.output


class TestModifiedSignature:
    def test_modified_signature_rejected(self, populated_store, tmp_stores, runner):
        """Import should REJECT commits with tampered signatures."""
        src, tgt, _ = tmp_stores
        export_dir = src.parent / "export"
        runner.invoke(cli, ["--store", str(src), "export", "--output", str(export_dir)])
        files = list((export_dir / "commits").glob("*.json"))
        data = json.loads(files[-1].read_text())
        sig = data.get("signature", "")
        data["signature"] = "ed25519:AAAA" + sig[12:] if len(sig) > 12 else "ed25519:AAAA"
        files[-1].write_text(json.dumps(data, indent=2))
        r = runner.invoke(cli, [
            "--store", str(tgt), "import", "--input", str(export_dir),
            "--trust-unknown-identities",
        ])
        assert r.exit_code != 0, "import should reject tampered signature"
        assert "signature_invalid" in r.output or "unknown_identity" in r.output


class TestModifiedCommitId:
    def test_modified_commit_id_rejected(self, populated_store, tmp_stores, runner):
        """Import should REJECT commits with modified commit_id."""
        src, tgt, _ = tmp_stores
        export_dir = src.parent / "export"
        runner.invoke(cli, ["--store", str(src), "export", "--output", str(export_dir)])
        files = list((export_dir / "commits").glob("*.json"))
        data = json.loads(files[-1].read_text())
        data["commit_id"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        files[-1].write_text(json.dumps(data, indent=2))
        r = runner.invoke(cli, [
            "--store", str(tgt), "import", "--input", str(export_dir),
            "--trust-unknown-identities",
        ])
        assert r.exit_code != 0, "import should reject modified commit_id"
        assert "signature_invalid" in r.output or "unknown_identity" in r.output


class TestMissingParent:
    def test_missing_parent_detected(self, populated_store, tmp_stores, runner):
        src, tgt, _ = tmp_stores
        export_dir = src.parent / "export"
        runner.invoke(cli, ["--store", str(src), "export", "--output", str(export_dir)])
        files = sorted((export_dir / "commits").glob("*.json"))
        if len(files) > 2:
            files[1].unlink()
        _import_and_set_head(runner, tgt, export_dir)
        r = runner.invoke(cli, ["--store", str(tgt), "verify"])
        assert "parent_missing" in r.output or "FAIL" in r.output, \
            f"should detect missing parent: {r.output}"


class TestDuplicateCommits:
    def test_duplicate_ignored(self, populated_store, tmp_stores, runner):
        src, tgt, _ = tmp_stores
        export_dir = src.parent / "export"
        runner.invoke(cli, ["--store", str(src), "export", "--output", str(export_dir)])
        files = list((export_dir / "commits").glob("*.json"))
        if files:
            dup = export_dir / "commits" / "dup.json"
            dup.write_text(files[0].read_text())
        r = _import_and_set_head(runner, tgt, export_dir)
        assert r.exit_code == 0, f"duplicate should be handled: {r.output}"


class TestTamperedManifest:
    def test_tampered_manifest_rejected(self, populated_store, tmp_stores, runner):
        src, tgt, _ = tmp_stores
        export_dir = src.parent / "export"
        runner.invoke(cli, ["--store", str(src), "export", "--output", str(export_dir)])
        mpath = export_dir / "manifest.json"
        data = json.loads(mpath.read_text())
        data["manifest_hash"] = "sha256:fake"
        mpath.write_text(json.dumps(data, indent=2))
        r = runner.invoke(cli, [
            "--store", str(tgt), "import", "--input", str(export_dir),
            "--trust-unknown-identities",
        ])
        assert r.exit_code != 0
        assert "manifest_hash mismatch" in r.output


class TestReplayBundle:
    def test_replay_no_duplicate(self, populated_store, tmp_stores, runner):
        src, tgt, _ = tmp_stores
        export_dir = src.parent / "export"
        runner.invoke(cli, ["--store", str(src), "export", "--output", str(export_dir)])
        _import_and_set_head(runner, tgt, export_dir)
        r2 = runner.invoke(cli, [
            "--store", str(tgt), "import", "--input", str(export_dir),
            "--trust-unknown-identities",
        ])
        assert r2.exit_code == 0
        store = Store.open(tgt)
        commits = store.load_commits()
        ids = set(c.commit_id for c in commits.values())
        assert len(commits) == len(ids), "duplicates after replay"


class TestOutOfOrder:
    def test_out_of_order_import(self, populated_store, tmp_stores, runner):
        src, tgt, _ = tmp_stores
        export_dir = src.parent / "export"
        runner.invoke(cli, ["--store", str(src), "export", "--output", str(export_dir)])
        cdir = export_dir / "commits"
        files = list(cdir.glob("*.json"))
        for i, f in enumerate(files):
            f.rename(cdir / f"z{i}_{f.name}")
        _import_and_set_head(runner, tgt, export_dir)
        r = runner.invoke(cli, ["--store", str(tgt), "verify"])
        assert r.exit_code == 0, f"out-of-order import verify: {r.output}"


class TestUnknownIdentity:
    def test_no_trust_fails(self, populated_store, tmp_stores, runner):
        src, tgt, _ = tmp_stores
        export_dir = src.parent / "export"
        runner.invoke(cli, ["--store", str(src), "export", "--output", str(export_dir)])
        r = runner.invoke(cli, ["--store", str(tgt), "import", "--input", str(export_dir)])
        assert r.exit_code != 0


class TestVerifyConsistency:
    def test_same_result_before_and_after(self, populated_store, tmp_stores, runner):
        """Central question: does verify give same result before and after transport?"""
        src, tgt, _ = tmp_stores
        r_src = runner.invoke(cli, ["--store", str(src), "verify"])
        assert "result: OK" in r_src.output
        export_dir = src.parent / "export"
        runner.invoke(cli, ["--store", str(src), "export", "--output", str(export_dir)])
        _import_and_set_head(runner, tgt, export_dir)
        r_tgt = runner.invoke(cli, ["--store", str(tgt), "verify"])
        assert "result: OK" in r_tgt.output, f"target not OK: {r_tgt.output}"
        
        src_store = Store.open(src)
        tgt_store = Store.open(tgt)
        src_c = src_store.load_commits()
        tgt_c = tgt_store.load_commits()
        assert len(src_c) == len(tgt_c)
        assert set(src_c.keys()) == set(tgt_c.keys())
        for cid in src_c:
            assert src_c[cid].commit_id == tgt_c[cid].commit_id
            assert src_c[cid].signature == tgt_c[cid].signature
            assert src_c[cid].content == tgt_c[cid].content
