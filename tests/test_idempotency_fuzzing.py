"""Adversarial tests for idempotency conflicts (#4) and fuzzing (#5)."""
import json
import shutil
import tempfile
import uuid
from pathlib import Path

import pytest
from click.testing import CliRunner

from alethech.cli import cli
from alethech.integrations.memex.hook import MemexAlethechHook
from alethech.store import Store


class MockMemexStore:
    def __init__(self):
        self.writes = []
    def add(self, text, user_id="agent", metadata=None):
        mid = str(uuid.uuid4())
        self.writes.append({"id": mid, "text": text})
        return {"id": mid, "text": text}
    def delete(self, memory_id):
        self.writes = [w for w in self.writes if w["id"] != memory_id]
    def get_all(self, user_id="agent", limit=100000):
        return {"results": self.writes[:limit]}


def _make_store():
    d = tempfile.mkdtemp(prefix="alethech-")
    p = Path(d) / "alethech"
    runner = CliRunner()
    runner.invoke(cli, ["--store", str(p), "init"])
    runner.invoke(cli, ["--store", str(p), "migrate", "--to", "v0.2"])
    return p, d


class TestIdempotencyConflict:
    def test_same_key_different_text(self):
        """FIXED: Same idempotency_key with different text now returns conflict."""
        p, d = _make_store()
        try:
            memex = MockMemexStore()
            hook = MemexAlethechHook(memex_store=memex, alethech_store_path=p)
            key = "conflict-001"
            r1 = hook.add("hello", idempotency_key=key)
            assert r1["success"]
            r2 = hook.add("world", idempotency_key=key)
            assert not r2["success"], "should detect conflict"
            assert "idempotency_conflict" in (r2.get("error") or "")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_same_key_same_text_returns_existing(self):
        p, d = _make_store()
        try:
            memex = MockMemexStore()
            hook = MemexAlethechHook(memex_store=memex, alethech_store_path=p)
            key = "same-001"
            r1 = hook.add("hello", idempotency_key=key)
            r2 = hook.add("hello", idempotency_key=key)
            assert r2["success"]
            assert r2["id"] == r1["id"]
            assert len(memex.writes) == 1
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestFuzzing:
    def test_commit_missing_fields(self):
        p, d = _make_store()
        try:
            bad = p / "commits" / "sha256:bad.json"
            bad.write_text(json.dumps({"type": "MemoryCommit", "commit_id": "sha256:bad"}))
            r = CliRunner().invoke(cli, ["--store", str(p), "verify"])
            assert r.exit_code != 0 or "FAIL" in r.output
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_commit_wrong_type(self):
        p, d = _make_store()
        try:
            bad = p / "commits" / "sha256:wt.json"
            bad.write_text(json.dumps({"type": "NotACommit", "commit_id": "sha256:wt", "signature": "ed25519:x"}))
            r = CliRunner().invoke(cli, ["--store", str(p), "verify"])
            assert r.exit_code != 0 or "FAIL" in r.output
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_commit_array_not_object(self):
        p, d = _make_store()
        try:
            bad = p / "commits" / "sha256:arr.json"
            bad.write_text(json.dumps([1, 2, 3]))
            r = CliRunner().invoke(cli, ["--store", str(p), "verify"])
            assert r.exit_code != 0 or "FAIL" in r.output
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_extra_fields_no_crash(self):
        p, d = _make_store()
        try:
            store = Store.open(p)
            commits = store.load_commits()
            if commits:
                existing = list(commits.values())[0]
                data = existing.to_signed_dict()
                data["extra_field"] = "test"
                (p / "commits" / f"{existing.commit_id}.json").write_text(json.dumps(data, indent=2))
                r = CliRunner().invoke(cli, ["--store", str(p), "verify"])
                assert "Traceback" not in r.output
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_invalid_jwk(self):
        """FIXED: Invalid JWK now detected by verify_self."""
        p, d = _make_store()
        try:
            # Corrupt the IdentityRecordV2 file (not the legacy Identity)
            id_files = list((p / "identities").glob("*.json"))
            v2_file = None
            for f in id_files:
                data = json.loads(f.read_text())
                if data.get("type") == "IdentityRecordV2":
                    v2_file = f
                    break
            if v2_file is None:
                v2_file = id_files[0] if id_files else None
            if v2_file:
                data = json.loads(v2_file.read_text())
                data["root_public_key"] = {"kty": "INVALID", "crv": "bad", "x": "not_base64"}
                v2_file.write_text(json.dumps(data, indent=2))
            r = CliRunner().invoke(cli, ["--store", str(p), "verify"])
            assert r.exit_code != 0 or "FAIL" in r.output, \
                f"should detect invalid JWK: {r.output}"
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_unicode_content(self):
        p, d = _make_store()
        try:
            runner = CliRunner()
            c = p / "u.json"
            c.write_text(json.dumps({"text": "café 日本語 🤖"}))
            assert runner.invoke(cli, ["--store", str(p), "commit", "--content", str(c)]).exit_code == 0
            assert runner.invoke(cli, ["--store", str(p), "verify"]).exit_code == 0
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_large_content(self):
        p, d = _make_store()
        try:
            runner = CliRunner()
            c = p / "l.json"
            c.write_text(json.dumps({"data": "x" * 100000}))
            assert runner.invoke(cli, ["--store", str(p), "commit", "--content", str(c)]).exit_code == 0
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_null_values(self):
        p, d = _make_store()
        try:
            runner = CliRunner()
            c = p / "n.json"
            c.write_text(json.dumps({"a": None, "b": [None, 1]}))
            assert runner.invoke(cli, ["--store", str(p), "commit", "--content", str(c)]).exit_code == 0
            assert runner.invoke(cli, ["--store", str(p), "verify"]).exit_code == 0
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_deep_nesting(self):
        p, d = _make_store()
        try:
            runner = CliRunner()
            data = {"level": 0}
            cur = data
            for i in range(50):
                cur["nested"] = {"level": i + 1}
                cur = cur["nested"]
            c = p / "d.json"
            c.write_text(json.dumps(data))
            assert runner.invoke(cli, ["--store", str(p), "commit", "--content", str(c)]).exit_code == 0
            assert runner.invoke(cli, ["--store", str(p), "verify"]).exit_code == 0
        finally:
            shutil.rmtree(d, ignore_errors=True)
