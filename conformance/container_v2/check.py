"""Frozen ALETH002 reader conformance. All runtimes are required by default."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import shlex
import tempfile

from alethech.container import ContainerError
from alethech.container_v2 import _parse_v2
from alethech.crypto import b64url_decode

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", action="append", choices=["python", "typescript", "rust"])
    parser.add_argument("--typescript-command", default="npx --yes tsx",
                        help="TypeScript runner, e.g. 'node --experimental-strip-types' on Node 24")
    args = parser.parse_args()
    runtimes = args.runtime or ["python", "typescript", "rust"]
    fixture = json.loads(Path(__file__).with_name("golden.vector").read_text())
    blob = b64url_decode(fixture["container_base64url"])
    if hashlib.sha256(blob).hexdigest() != fixture["sha256"]:
        raise RuntimeError("golden container digest mismatch")
    commands = {
        "typescript": shlex.split(args.typescript_command) + [str(ROOT / "alethech-ts/aleth-container-v2.ts")],
        "rust": [str(ROOT / "alethech-rs/target/release/alethech-container-v2")],
    }
    cases = [
        ("passphrase", blob, "passphrase", fixture["passphrase"], True),
        ("recovery", blob, "recovery_code", fixture["recovery_code"], True),
        ("wrong-passphrase", blob, "passphrase", "wrong", False),
        ("wrong-recovery", blob, "recovery_code", "aleth-recovery-v1:" + "A" * 43, False),
        ("modified-tag", blob[:-1] + bytes([blob[-1] ^ 1]), "passphrase", fixture["passphrase"], False),
        ("truncated", blob[:-16], "recovery_code", fixture["recovery_code"], False),
    ]
    with tempfile.TemporaryDirectory(prefix="alethech-golden-") as tmp:
        for runtime in runtimes:
            for name, data, kind, credential, valid in cases:
                path = Path(tmp) / (name + ".aleth")
                path.write_bytes(data)
                if runtime == "python":
                    try:
                        payload, header = _parse_v2(data, **{kind: credential})
                        result = {"payload": payload, "container_id": header["container_id"],
                                  "slot_types": sorted(s["type"] for s in header["slots"])}
                        accepted = True
                    except ContainerError:
                        accepted, result = False, None
                else:
                    mode = "open-pass" if kind == "passphrase" else "open-recovery"
                    process = subprocess.run(commands[runtime] + [mode, str(path), credential],
                                             capture_output=True, text=True, timeout=120, cwd=ROOT)
                    accepted = process.returncode == 0
                    result = json.loads(process.stdout) if accepted else None
                    if not accepted and process.stdout.strip():
                        raise RuntimeError(f"{runtime}/{name}: output exposed on rejection")
                if accepted != valid or (valid and result != fixture["expected"]):
                    raise RuntimeError(f"{runtime}/{name}: conformance failed")
            print(f"{runtime}: {len(cases)} ALETH002 cases passed")


if __name__ == "__main__":
    main()
