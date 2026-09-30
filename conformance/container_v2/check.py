"""Frozen ALETH002 reader conformance. All runtimes are required by default."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import shlex
import tempfile
import struct
from copy import deepcopy

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from alethech.canonical import canonical_json_bytes

from alethech.container import ContainerError
from alethech.container_v2 import _parse_v2, _parse_header_v2, _unlock_dek_with_recovery
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
    # Authenticate deliberately invalid schemas: rejecting these must come
    # from validation, rather than a ciphertext tag mismatch.
    header, _, _ = _parse_header_v2(blob)
    dek = _unlock_dek_with_recovery(header, fixture["recovery_code"])

    def authenticated(h, payload):
        hb = canonical_json_bytes(h)
        ciphertext = AESGCM(dek).encrypt(b64url_decode(h["payload_nonce"]),
                                        canonical_json_bytes(payload), hb)
        return b"ALETH002" + struct.pack(">I", len(hb)) + hb + ciphertext

    bad_payloads = []
    extra = deepcopy(fixture["expected"]["payload"])
    extra["unsupported"] = True
    bad_payloads.append(("payload-extra-field", extra))
    bad_payloads.append(("payload-boolean-version", {"payload_version": True, "files": {}}))
    bad_payloads.append(("payload-traversal", {"payload_version": 1, "files": {"../escape": "AA"}}))
    bad_payloads.append(("payload-authority", {"payload_version": 1, "files": {"keys/root.key": "AA"}}))
    bad_payloads.append(("payload-invalid-base64", {"payload_version": 1, "files": {"HEAD": "!"}}))
    for name, payload in bad_payloads:
        cases.append((name, authenticated(header, payload), "recovery_code", fixture["recovery_code"], False))
    duplicate = deepcopy(header)
    duplicate["slots"].append(deepcopy(duplicate["slots"][0]))
    cases.append(("duplicate-slot", authenticated(duplicate, fixture["expected"]["payload"]),
                  "recovery_code", fixture["recovery_code"], False))
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
