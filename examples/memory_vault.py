#!/usr/bin/env python3
"""
memory_vault.py — Portable encrypted private-memory layer (Fernet).

This is the pluggable step-1 companion for memory_writeback.sh: pass it via
    VAULT_SYNC_CMD="python3 examples/memory_vault.py sync" bash examples/memory_writeback.sh

Architecture (2 layers, different jobs):
  1. alethech chain — signed, tamper-evident, SECRET-FREE quick recall
     (summaries, indexes, vault pointers). Nothing sensitive here.
  2. THIS vault — encrypted context (Fernet AES-128-CBC + HMAC): complete
     task history, user profile, lessons, pending items, worklog snapshot.
     Its sha256 is bound into the chain via memory-vault pointer commits,
     so it is tamper-evident too.

Vault sections (create whichever you need; sync owns worklog_snapshot):
  user_profile, environment, projects, key_artifacts, lessons_rules,
  pending_items, task_history, worklog_snapshot

Commands:
  status              open the vault, print sha256 + chain-pointer agreement
  read [section]      decrypt and print everything or one section (JSON)
  set <sec> <file>    replace a section with the JSON from a file
  add --id --title [--summary]   append an entry to task_history
  sync                refresh worklog_snapshot from the worklog file;
                      prints the new vault sha256 (feed it to a pointer commit)
  rotate              regenerate the Fernet key and re-encrypt the vault

DISCIPLINE: never store secrets (tokens, passwords, private keys) in the
vault or the chain — credentials live outside both, in chmod-600 files.
The vault carries CONTEXT, not credentials. Append-only mindset: to correct
a fact, write the new value; superseded records stay in snapshots.

Configuration (environment variables):
  ALETHECH_VAULT_DIR  private dir for vault + key   (default ~/.alethech-private)
  ALETHECH_WORKLOG    worklog file for `sync`       (default ./worklog.md)
  ALETHECH_STORE      chain store dir for pointer checks (default ~/.alethech)

Requires: cryptography>=42.0 (already a core alethech dependency).

© 2026 AliceLabs LLC. MIT License.
"""
import sys, os, json, hashlib, glob, argparse
from datetime import datetime, timezone

from cryptography.fernet import Fernet

VAULT_DIR = os.environ.get("ALETHECH_VAULT_DIR",
                           os.path.join(os.path.expanduser("~"), ".alethech-private"))
VAULT_PATH = os.path.join(VAULT_DIR, "memory-vault.enc")
KEY_PATH = os.path.join(VAULT_DIR, "vault.key")
WORKLOG = os.path.abspath(os.environ.get("ALETHECH_WORKLOG", os.path.join(os.getcwd(), "worklog.md")))
CHAIN = os.environ.get("ALETHECH_STORE",
                       os.path.join(os.path.expanduser("~"), ".alethech"))

SECTIONS = ["user_profile", "environment", "projects", "key_artifacts",
            "lessons_rules", "pending_items", "task_history", "worklog_snapshot"]


def _key() -> bytes:
    with open(KEY_PATH, "rb") as f:
        return f.read().strip()


def _load() -> dict:
    if not os.path.exists(VAULT_PATH):
        return {"_meta": {"created": datetime.now(timezone.utc).isoformat(),
                          "note": "new vault"}}
    return json.loads(Fernet(_key()).decrypt(open(VAULT_PATH, "rb").read()).decode("utf-8"))


def _save(d: dict) -> str:
    os.makedirs(VAULT_DIR, exist_ok=True)
    blob = Fernet(_key()).encrypt(json.dumps(d, ensure_ascii=False, sort_keys=True).encode("utf-8"))
    tmp = VAULT_PATH + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
    os.replace(tmp, VAULT_PATH)
    os.chmod(VAULT_PATH, 0o600)
    return hashlib.sha256(open(VAULT_PATH, "rb").read()).hexdigest()


def last_vault_pointer_sha() -> "str | None":
    """Most recent vault sha256 found in memory-vault pointer commits of the chain."""
    best = None
    for p in sorted(glob.glob(os.path.join(CHAIN, "commits", "*.json"))):
        try:
            c = json.load(open(p))
        except Exception:
            continue
        payload = c.get("payload") or c.get("content") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                continue
        if isinstance(payload, dict) and payload.get("type") == "memory-vault":
            sha = payload.get("vault_sha256")
            ts = c.get("timestamp") or c.get("ts") or ""
            if sha and (best is None or ts >= best[1]):
                best = (sha, ts)
    return best[0] if best else None


def cmd_status() -> int:
    if not os.path.exists(VAULT_PATH):
        print("vault: DOES NOT EXIST yet (use set/sync to create it)")
        return 1
    try:
        d = _load()
    except Exception as e:
        print(f"vault: FAILED TO OPEN ({e}) — corruption or wrong key: DO NOT TRUST, report it")
        return 2
    sha = hashlib.sha256(open(VAULT_PATH, "rb").read()).hexdigest()
    ptr = last_vault_pointer_sha()
    match = (ptr == sha) if ptr else None
    secs = {k: (len(v) if isinstance(v, (list, dict, str)) else v) for k, v in d.items()}
    print("vault: OK — opens and decrypts correctly")
    print(f"sha256: {sha}")
    print(f"last chain pointer: {ptr or '(none yet)'}")
    print(f"match: {match if match is not None else 'no pointer yet (commit pending)'}")
    print("sections:", json.dumps(secs, ensure_ascii=False))
    return 0


def cmd_read(section: "str | None") -> int:
    d = _load()
    if section:
        if section not in d and section not in SECTIONS:
            print(f"section '{section}' does not exist. Available: {list(d.keys())}")
            return 1
        print(json.dumps(d.get(section, None), ensure_ascii=False, indent=2))
    else:
        print(json.dumps(d, ensure_ascii=False, indent=2))
    return 0


def cmd_set(section: str, path: str) -> int:
    d = _load()
    with open(path) as f:
        d[section] = json.load(f)
    d.setdefault("_meta", {})["updated"] = datetime.now(timezone.utc).isoformat()
    print(f"new sha256: {_save(d)}")
    print(f"section '{section}' replaced ({os.path.getsize(path)} bytes from source)")
    return 0


def cmd_sync() -> int:
    d = _load()
    if not os.path.exists(WORKLOG):
        print(f"worklog not found at {WORKLOG}")
        return 1
    raw = open(WORKLOG, "rb").read()
    d["worklog_snapshot"] = {
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "content": raw.decode("utf-8", errors="replace"),
    }
    d.setdefault("_meta", {})["updated"] = datetime.now(timezone.utc).isoformat()
    print(f"worklog_snapshot refreshed. new vault sha256: {_save(d)}")
    print("NEXT STEP: sign a pointer commit ->")
    print('  {"type":"memory-vault","vault_sha256":"<sha printed above>"}')
    return 0


def cmd_add(args) -> int:
    d = _load()
    d.setdefault("task_history", [])
    d["task_history"].append({
        "id": args.id, "title": args.title, "summary": args.summary,
        "at": datetime.now(timezone.utc).isoformat(),
    })
    print(f"new sha256: {_save(d)}")
    print(f"task_history += {args.id}")
    return 0


def cmd_rotate() -> int:
    new_key = Fernet.generate_key()
    os.makedirs(VAULT_DIR, exist_ok=True)
    with open(KEY_PATH, "w") as f:
        f.write(new_key.decode())
    os.chmod(KEY_PATH, 0o600)
    d = _load()  # with the new key already written, re-encrypt in place
    print(f"key rotated, vault re-encrypted. sha256: {_save(d)}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Encrypted private-memory vault (alethech layer 2)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    r = sub.add_parser("read"); r.add_argument("section", nargs="?")
    s = sub.add_parser("set"); s.add_argument("section"); s.add_argument("path")
    a = sub.add_parser("add"); a.add_argument("--id", required=True)
    a.add_argument("--title", required=True); a.add_argument("--summary", default="")
    sub.add_parser("sync"); sub.add_parser("rotate")
    args = ap.parse_args()
    if not os.path.exists(KEY_PATH):
        os.makedirs(VAULT_DIR, exist_ok=True)
        with open(KEY_PATH, "w") as f:
            f.write(Fernet.generate_key().decode())
        os.chmod(KEY_PATH, 0o600)
        print(f"new Fernet key generated ({KEY_PATH}, 0600)")
    return {"status": cmd_status, "read": lambda: cmd_read(args.section),
            "set": lambda: cmd_set(args.section, args.path), "sync": cmd_sync,
            "add": lambda: cmd_add(args), "rotate": cmd_rotate}[args.cmd]()


if __name__ == "__main__":
    sys.exit(main())
