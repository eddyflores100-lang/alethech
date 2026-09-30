"""Exercise all ALETH002 writers against all readers and verified history."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import tempfile

from alethech import Alethech
from alethech.container import _collect, seal_store
from alethech.container_v2 import (
    _parse_v2, _seal_payload_v2, decode_recovery_secret,
    recover_container_v2, migrate_v1_to_v2,
)
from alethech.crypto import b64url, b64url_decode

ROOT = Path(__file__).resolve().parents[2]
PASS = "public-matrix-passphrase"
NEXT = "public-matrix-new-passphrase"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", action="append", choices=["python", "typescript", "rust"])
    parser.add_argument("--typescript-command", default="npx --yes tsx")
    args = parser.parse_args()
    runtimes = args.runtime or ["python", "typescript", "rust"]
    commands = {
        "typescript": shlex.split(args.typescript_command) + [str(ROOT / "alethech-ts/aleth-container-v2.ts")],
        "rust": [str(ROOT / "alethech-rs/target/release/alethech-container-v2")],
    }

    def command(runtime, arguments, valid=True):
        process = subprocess.run(commands[runtime] + list(map(str, arguments)),
                                 cwd=ROOT, text=True, capture_output=True, timeout=180)
        if (process.returncode == 0) != valid:
            raise AssertionError(f"{runtime}/{arguments[0]} unexpected result: {process.stderr[:1000]}")
        if not valid:
            assert not process.stdout.strip(), "plaintext/output on failure"
            return None
        return json.loads(process.stdout)

    with tempfile.TemporaryDirectory(prefix="alethech-writers-") as tmp:
        base = Path(tmp)
        source = Alethech.initialize(base / "source")
        evidence = source.evidence(tool="matrix", input_bytes=b"input", output_bytes=b"output",
                                   artifacts={"proof.bin": b"proof"})
        ancestor = source.commit({"memory": "portable — 日本語"}, evidence_refs=[evidence.commit_id])
        source.commit({"memory": "valid descendant"})
        payload = {"payload_version": 1, "files": _collect(source.path)}
        payload_path = base / "payload.json"
        payload_path.write_text(json.dumps(payload))
        v1 = seal_store(source.store, base / "original-v1.aleth", PASS)
        v1_bytes = v1.read_bytes()
        raw_secret = bytes([255]) * 32
        secret_arg = b64url(raw_secret)
        counter = 0

        def readers(path, passphrase, recovery, expected_id=None):
            nonlocal counter
            for reader in runtimes:
                for mode, credential in (("open-pass", passphrase), ("open-recovery", recovery)):
                    if reader == "python":
                        kwargs = {"passphrase" if mode == "open-pass" else "recovery_code": credential}
                        actual, header = _parse_v2(path.read_bytes(), **kwargs)
                        result = {"payload": actual, "container_id": header["container_id"]}
                    else:
                        result = command(reader, [mode, path, credential])
                    assert result["payload"] == payload, f"{reader}: payload changed"
                    if expected_id:
                        assert result["container_id"] == expected_id
                    counter += 1
            restored = Alethech.open_aleth(path, base / f"restored-{counter}", passphrase)
            assert restored.head == source.head
            assert restored.verify().ok
            assert restored.store.load_evidence()[evidence.commit_id].to_signed_dict() == evidence.to_signed_dict()

        for writer in runtimes:
            path = base / (writer + ".aleth")
            if writer == "python":
                _, recovery = source.seal_v2(path, PASS)
                _, header = _parse_v2(path.read_bytes(), passphrase=PASS)
                container_id = header["container_id"]
            else:
                metadata = command(writer, ["seal", payload_path, path, PASS, secret_arg])
                recovery, container_id = metadata["recoveryCode"], metadata["containerId"]
            readers(path, PASS, recovery)
            original = path.read_bytes()
            for rotate in (False, True):
                recovered = base / f"{writer}-recovered-{rotate}.aleth"
                if writer == "python":
                    _, new_code = recover_container_v2(path, recovered, recovery, NEXT, rotate_recovery=rotate)
                else:
                    flags = ["--rotate-recovery"] if rotate else []
                    metadata = command(writer, ["recover", path, recovered, recovery, NEXT, *flags])
                    new_code = metadata["recoveryCode"]
                assert (new_code != recovery) == rotate
                readers(recovered, NEXT, new_code, container_id)
                for reader in runtimes:
                    if reader == "python":
                        try:
                            _parse_v2(recovered.read_bytes(), passphrase=PASS)
                        except Exception:
                            pass
                        else:
                            raise AssertionError("old passphrase accepted")
                    else:
                        command(reader, ["open-pass", recovered, PASS], valid=False)
                        if rotate:
                            command(reader, ["open-recovery", recovered, recovery], valid=False)
                assert path.read_bytes() == original
            migrated = base / (writer + "-migrated.aleth")
            if writer == "python":
                _, code = migrate_v1_to_v2(v1, migrated, PASS, NEXT)
            else:
                code = command(writer, ["migrate", v1, migrated, PASS, NEXT])["recoveryCode"]
            readers(migrated, NEXT, code)
            assert v1.read_bytes() == v1_bytes

            # Authenticated forged ancestor: a valid HEAD alone is insufficient.
            forged = json.loads(json.dumps(payload))
            name = next(p for p in forged["files"] if p.startswith("commits/") and ancestor.commit_id in p)
            commit = json.loads(b64url_decode(forged["files"][name]))
            commit["content"] = {"forged": True}
            forged["files"][name] = b64url(json.dumps(commit).encode())
            bad = base / (writer + "-invalid.aleth")
            bad.write_bytes(_seal_payload_v2(forged, PASS, recovery_secret=raw_secret))
            sentinel = base / (writer + "-sentinel.aleth")
            sentinel.write_bytes(b"existing destination")
            if writer == "python":
                try:
                    recover_container_v2(bad, sentinel, "aleth-recovery-v1:" + secret_arg, NEXT)
                except Exception:
                    pass
                else:
                    raise AssertionError("forged ancestor recovered")
            else:
                command(writer, ["recover", bad, sentinel, "aleth-recovery-v1:" + secret_arg, NEXT], valid=False)
            assert sentinel.read_bytes() == b"existing destination"
            print(f"{writer}: seal, recover, rotate, migrate and forged-ancestor rejection passed")
        print(f"{counter} cross-reader payload checks passed")


if __name__ == "__main__":
    main()
