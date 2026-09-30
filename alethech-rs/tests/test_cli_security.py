"""Adversarial CLI contract tests; run after cargo build --bins from repository root."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from alethech import Alethech
from alethech.container import _collect, _seal_payload_bytes
from alethech.container_v2 import _seal_payload_v2, encode_recovery_secret

BIN = Path(os.environ.get('ALETHECH_TEST_BINARY', str(Path(__file__).resolve().parents[1] / 'target/debug/alethech-container-v2')))


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / 'out.aleth'
        self.out.write_bytes(b'existing output')

    def run_cli(self, *args, env=None):
        return subprocess.run([str(BIN), *map(str, args)], capture_output=True, env=env)

    def rejected(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(self.out.read_bytes(), b'existing output')
        self.assertNotIn(b'panicked', result.stderr)

    def test_invalid_history_seal_is_rejected_before_overwrite(self):
        payload = self.root / 'payload.json'
        payload.write_text(json.dumps({'payload_version': 1, 'files': {}}))
        self.rejected(self.run_cli('seal', payload, self.out, 'pass'))

    def test_authenticated_invalid_history_recovery_is_rejected(self):
        secret = b'x' * 32
        source = self.root / 'bad.aleth'
        source.write_bytes(_seal_payload_v2({'payload_version': 1, 'files': {}}, 'pass', recovery_secret=secret))
        self.rejected(self.run_cli('recover', source, self.out, encode_recovery_secret(secret), 'new'))

    def test_authenticated_invalid_history_migration_is_rejected(self):
        source = self.root / 'bad.aleth'
        source.write_bytes(_seal_payload_bytes({'payload_version': 1, 'files': {}}, 'pass'))
        self.rejected(self.run_cli('migrate', source, self.out, 'pass', 'new'))

    def test_oversized_recovery_header_fails_without_panic(self):
        source = self.root / 'bad.aleth'
        source.write_bytes(b'ALETH002' + b'\xff' * 4)
        self.rejected(self.run_cli('recover', source, self.out, 'bad-code', 'new'))

    def test_authenticated_extra_and_noncanonical_v1_headers_are_rejected(self):
        from alethech.canonical import canonical_json_bytes
        from alethech.container import _derive
        from alethech.crypto import b64url
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import struct
        agent = Alethech.initialize(self.root / 'source')
        payload = {'payload_version': 1, 'files': _collect(agent.store.root)}
        header = {'cipher': 'AES-256-GCM', 'format': 'aleth', 'kdf': 'scrypt',
                  'nonce': b64url(b'n' * 12), 'salt': b64url(b's' * 16),
                  'scrypt_n': 32768, 'scrypt_p': 1, 'scrypt_r': 8, 'version': 1}
        source = self.root / 'v1.aleth'
        for extra, canonical in [(True, True), (False, False)]:
            fields = {**header, **({'extra': 'unexpected'} if extra else {})}
            hb = canonical_json_bytes(fields) if canonical else json.dumps(fields).encode()
            ciphertext = AESGCM(_derive('pass', b's' * 16)).encrypt(b'n' * 12, canonical_json_bytes(payload), hb)
            source.write_bytes(b'ALETH001' + struct.pack('>I', len(hb)) + hb + ciphertext)
            self.rejected(self.run_cli('migrate', source, self.out, 'pass', 'new'))

    def test_extra_schema_and_authority_paths_are_rejected(self):
        for payload in [
            {'payload_version': 1, 'files': {}, 'extra': 1},
            {'payload_version': 1, 'files': {'authorities/key.json': 'eA'}},
            {'payload_version': 1, 'files': {'artifacts/a\x00b': 'eA'}},
            {'payload_version': 1, 'files': {'HEAD': 'eA=='}},
        ]:
            source = self.root / 'payload.json'
            source.write_text(json.dumps(payload))
            self.rejected(self.run_cli('seal', source, self.out, 'pass'))

    def test_full_roundtrip_recovery_migration_single_json_and_key_binding(self):
        agent = Alethech.initialize(self.root / 'source')
        agent.commit({'memory': 'verified'})
        payload = {'payload_version': 1, 'files': _collect(agent.store.root)}
        source = self.root / 'payload.json'
        source.write_text(json.dumps(payload))
        secret = b'x' * 32
        from alethech.crypto import b64url
        result = self.run_cli('seal', source, self.out, 'pass', b64url(secret))
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata = json.loads(result.stdout)
        recovered = self.root / 'recovered.aleth'
        result = self.run_cli('recover', self.out, recovered, metadata['recoveryCode'], 'new', '--rotate-recovery')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['containerId'], metadata['containerId'])
        result = self.run_cli('open-pass', recovered, 'new')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['payload'], payload)
        v1 = self.root / 'v1.aleth'
        v1.write_bytes(_seal_payload_bytes(payload, 'pass'))
        result = self.run_cli('migrate', v1, self.out, 'pass', 'new')
        self.assertEqual(result.returncode, 0, result.stderr)
        json.loads(result.stdout)  # exactly one JSON response
        other = Alethech.initialize(self.root / 'other')
        payload['files']['keys/signing.key'] = _collect(other.store.root)['keys/signing.key']
        source.write_text(json.dumps(payload))
        self.out.write_bytes(b'existing output')
        self.rejected(self.run_cli('seal', source, self.out, 'pass'))

    def test_recovery_rejects_authenticated_multi_slot_envelope(self):
        from alethech.canonical import canonical_json_bytes
        from alethech.crypto import b64url_decode
        from alethech.container_v2 import (_parse_header_v2, _unlock_dek_with_passphrase,
                                            _passphrase_slot, _derive_passphrase_kek, _wrap_dek)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import struct
        agent = Alethech.initialize(self.root / 'source')
        payload = {'payload_version': 1, 'files': _collect(agent.store.root)}
        secret = b'x' * 32
        blob = _seal_payload_v2(payload, 'pass', recovery_secret=secret)
        header, _, _ = _parse_header_v2(blob)
        dek = _unlock_dek_with_passphrase(header, 'pass')
        extra = _passphrase_slot(dek, 'additional-pass', header['container_id'])
        extra['id'] = 'passphrase-2'
        extra['wrapped_key'] = _wrap_dek(dek,
            _derive_passphrase_kek('additional-pass', b64url_decode(extra['salt'])),
            container_id=header['container_id'], slot_id=extra['id'],
            slot_type=extra['type'], nonce=b64url_decode(extra['nonce']))
        header['slots'].append(extra)
        hb = canonical_json_bytes(header)
        ciphertext = AESGCM(dek).encrypt(b64url_decode(header['payload_nonce']), canonical_json_bytes(payload), hb)
        source = self.root / 'multi.aleth'
        source.write_bytes(b'ALETH002' + struct.pack('>I', len(hb)) + hb + ciphertext)
        # Prove the extra slot itself is usable, so rejection cannot be due to AEAD.
        result = self.run_cli('open-pass', source, 'additional-pass')
        self.assertEqual(result.returncode, 0, result.stderr)
        for flags in [(), ('--rotate-recovery',)]:
            self.rejected(self.run_cli('recover', source, self.out, encode_recovery_secret(secret), 'new', *flags))

    def test_migration_source_aliases_require_explicit_replacement(self):
        agent = Alethech.initialize(self.root / 'source')
        payload = {'payload_version': 1, 'files': _collect(agent.store.root)}
        original = _seal_payload_bytes(payload, 'pass')
        source = self.root / 'v1.aleth'
        source.write_bytes(original)
        aliases = [source]
        if os.name == 'posix':
            hardlink = self.root / 'hardlink.aleth'
            os.link(source, hardlink)
            symlink = self.root / 'symlink.aleth'
            symlink.symlink_to(source)
            aliases += [hardlink, symlink]
        for output in aliases:
            result = self.run_cli('migrate', source, output, 'pass', 'new')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(source.read_bytes(), original)
            self.assertIn(b'--replace-source', result.stderr)
        result = self.run_cli('migrate', source, source, 'pass', 'new', '--replace-source', '--no-recovery')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(json.loads(result.stdout)['recoveryCode'])
        self.assertTrue(source.read_bytes().startswith(b'ALETH002'))
        result = self.run_cli('open-pass', source, 'new')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['payload'], payload)

    def test_verified_readonly_archive_recovers_and_migrates_without_signing_key(self):
        agent = Alethech.initialize(self.root / 'source')
        agent.commit({'archive': 'read-only verified history'})
        files = _collect(agent.store.root)
        del files['keys/signing.key']
        payload = {'payload_version': 1, 'files': files}
        secret = b'x' * 32
        source = self.root / 'archive.aleth'
        source.write_bytes(_seal_payload_v2(payload, 'pass', recovery_secret=secret))
        result = self.run_cli('recover', source, self.out, encode_recovery_secret(secret), 'new')
        self.assertEqual(result.returncode, 0, result.stderr)
        json.loads(result.stdout)
        result = self.run_cli('open-pass', self.out, 'new')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['payload'], payload)
        v1 = self.root / 'archive-v1.aleth'
        v1.write_bytes(_seal_payload_bytes(payload, 'pass'))
        result = self.run_cli('migrate', v1, self.out, 'pass', 'new', '--no-recovery')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(json.loads(result.stdout)['recoveryCode'])
        result = self.run_cli('open-pass', self.out, 'new')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['payload'], payload)

    def test_atomic_write_failure_removes_temp_without_output(self):
        agent = Alethech.initialize(self.root / 'source')
        source = self.root / 'payload.json'
        source.write_text(json.dumps({'payload_version': 1, 'files': _collect(agent.store.root)}))
        target = self.root / 'directory.aleth'
        target.mkdir()
        marker = target / 'preserved'
        marker.write_bytes(b'preserved')
        result = self.run_cli('seal', source, target, 'pass')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(marker.read_bytes(), b'preserved')
        self.assertEqual(list(self.root.glob('.alethech-*.tmp')), [])

    def test_missing_python_verifier_fails_closed(self):
        agent = Alethech.initialize(self.root / 'source')
        source = self.root / 'payload.json'
        source.write_text(json.dumps({'payload_version': 1, 'files': _collect(agent.store.root)}))
        self.rejected(self.run_cli('seal', source, self.out, 'pass', env={**os.environ, 'PATH': str(self.root)}))


if __name__ == '__main__':
    unittest.main()
