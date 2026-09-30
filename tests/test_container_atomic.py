"""Publication failures must never destroy accepted encrypted or plaintext state."""
import os
import pytest
from alethech import Alethech
from alethech import container, container_v2
from alethech.container import ContainerError

@pytest.mark.parametrize('operation', ['seal1', 'seal2', 'rekey1', 'rekey2', 'recover', 'migrate'])
@pytest.mark.parametrize('failure', ['fsync', 'replace'])
def test_encrypted_publication_failure_preserves_output(tmp_path, monkeypatch, operation, failure):
    agent = Alethech.initialize(tmp_path / 'store')
    source = agent.seal(tmp_path / 'v1.aleth', 'old')
    v2, code = agent.seal_v2(tmp_path / 'v2.aleth', 'old')
    output = tmp_path / 'output.aleth'
    output.write_bytes(b'accepted previous output')
    before = set(tmp_path.iterdir())
    def fail(*args, **kwargs):
        raise OSError('injected publication failure')
    monkeypatch.setattr(os, failure, fail)
    with pytest.raises(OSError, match='injected'):
        if operation == 'seal1': agent.seal(output, 'new')
        elif operation == 'seal2': agent.seal_v2(output, 'new')
        elif operation == 'rekey1': agent.rekey_aleth(source, output, 'old', 'new')
        elif operation == 'rekey2': agent.rekey_aleth(v2, output, 'old', 'new', recovery_code=code)
        elif operation == 'recover': agent.recover_aleth_v2(v2, output, code, 'new')
        else: agent.migrate_aleth_v1_to_v2(source, output, 'old', 'new')
    assert output.read_bytes() == b'accepted previous output'
    assert set(tmp_path.iterdir()) == before

@pytest.mark.skipif(os.name != 'posix', reason='POSIX permission bits are not Windows ACLs')
@pytest.mark.parametrize('v2', [False, True])
def test_seal_publishes_private_file(tmp_path, v2):
    agent = Alethech.initialize(tmp_path / 'store')
    output = tmp_path / 'memory.aleth'
    if v2: agent.seal_v2(output, 'secret')
    else: agent.seal(output, 'secret')
    assert output.stat().st_mode & 0o777 == 0o600


def test_migration_requires_explicit_inplace_authorization(tmp_path):
    agent = Alethech.initialize(tmp_path / 'store')
    source = agent.seal(tmp_path / 'memory.aleth', 'old')
    before = source.read_bytes()
    with pytest.raises(ContainerError, match='replace_source'):
        agent.migrate_aleth_v1_to_v2(source, source, 'old', 'new')
    assert source.read_bytes() == before
    agent.migrate_aleth_v1_to_v2(source, source, 'old', 'new', replace_source=True)
    assert source.read_bytes()[:8] == b'ALETH002'


def test_v2_rekey_preserves_recovery_and_requires_credential(tmp_path):
    agent = Alethech.initialize(tmp_path / 'store')
    source, code = agent.seal_v2(tmp_path / 'memory.aleth', 'old')
    output = tmp_path / 'rotated.aleth'
    with pytest.raises(ContainerError, match='recovery_code'):
        agent.rekey_aleth(source, output, 'old', 'new')
    assert not output.exists()
    agent.rekey_aleth(source, output, 'old', 'new', recovery_code=code)
    assert agent.open_aleth_v2(output, tmp_path / 'opened', recovery_code=code).head == agent.head
    with pytest.raises(ContainerError):
        agent.open_aleth(output, tmp_path / 'bad', 'old')

@pytest.mark.parametrize('v2', [False, True])
def test_plaintext_destination_stays_empty_until_verified(tmp_path, monkeypatch, v2):
    agent = Alethech.initialize(tmp_path / 'store')
    source = tmp_path / 'memory.aleth'
    if v2: agent.seal_v2(source, 'secret')
    else: agent.seal(source, 'secret')
    destination = tmp_path / 'opened'
    destination.mkdir()
    real_verify = container.verify_store
    def observing_verify(store):
        assert list(destination.iterdir()) == []
        assert store.root != destination
        return real_verify(store)
    monkeypatch.setattr(container, 'verify_store', observing_verify)
    monkeypatch.setattr(container_v2, 'verify_store', observing_verify)
    opened = agent.open_aleth(source, destination, 'secret')
    assert opened.head == agent.head


@pytest.mark.parametrize('v2', [False, True])
def test_invalid_authenticated_history_cannot_replace_existing_output(tmp_path, v2):
    from alethech.crypto import b64url
    from alethech.store import portable_fs_name
    agent = Alethech.initialize(tmp_path / 'store')
    ancestor = agent.commit({'memory': 'ancestor'})
    agent.commit({'memory': 'head'})
    payload = {'payload_version': 1, 'files': container._collect(agent.path)}
    # Corrupt the ancestor, deterministically, while leaving the signed HEAD intact.
    ancestor_path = agent.path / 'commits' / (portable_fs_name(ancestor.commit_id) + '.json')
    import json
    damaged = json.loads(ancestor_path.read_text())
    damaged['content'] = {'memory': 'tampered ancestor'}
    payload['files']['commits/' + ancestor.commit_id + '.json'] = b64url(json.dumps(damaged).encode())
    source = tmp_path / 'bad.aleth'
    if v2:
        secret = b'x' * 32
        source.write_bytes(container_v2._seal_payload_v2(payload, 'old', recovery_secret=secret))
        code = container_v2.encode_recovery_secret(secret)
    else:
        source.write_bytes(container._seal_payload_bytes(payload, 'old'))
    output = tmp_path / 'accepted.aleth'
    output.write_bytes(b'previous valid output')
    with pytest.raises(ContainerError, match='verification'):
        Alethech.rekey_aleth(source, output, 'old', 'new', **({'recovery_code': code} if v2 else {}))
    assert output.read_bytes() == b'previous valid output'
    with pytest.raises(ContainerError, match='verification'):
        if v2:
            Alethech.recover_aleth_v2(source, output, code, 'new')
        else:
            Alethech.migrate_aleth_v1_to_v2(source, output, 'old', 'new')
    assert output.read_bytes() == b'previous valid output'


@pytest.mark.parametrize('payload', [[], None, {'files': {}, 'payload_version': True},
    {'files': {}, 'payload_version': 1, 'extra': 1},
    {'files': {'keys//signing.key': 'YQ'}, 'payload_version': 1},
    {'files': {'HEAD': 'YQ=='}, 'payload_version': 1}])
def test_payload_schema_rejects_ambiguous_encodings(payload):
    with pytest.raises(ContainerError):
        container._decode_payload_files(payload)


@pytest.mark.parametrize('v2', [False, True])
def test_plaintext_publication_failure_preserves_empty_destination(tmp_path, monkeypatch, v2):
    agent = Alethech.initialize(tmp_path / 'store')
    source = tmp_path / 'memory.aleth'
    if v2: agent.seal_v2(source, 'secret')
    else: agent.seal(source, 'secret')
    destination = tmp_path / 'opened'
    destination.mkdir()
    before = set(tmp_path.iterdir())
    def fail(*args): raise OSError('rename failed')
    monkeypatch.setattr(os, 'replace', fail)
    with pytest.raises(OSError, match='rename failed'):
        agent.open_aleth(source, destination, 'secret')
    assert destination.exists() and list(destination.iterdir()) == []
    assert set(tmp_path.iterdir()) == before


@pytest.mark.parametrize('v2', [False, True])
def test_seal_verifies_collected_snapshot_before_publication(tmp_path, monkeypatch, v2):
    agent = Alethech.initialize(tmp_path / 'store')
    output = tmp_path / 'existing.aleth'
    output.write_bytes(b'accepted output')
    collect = container._collect
    def mutated_collect(root):
        files = collect(root)
        from alethech.crypto import b64url
        files['HEAD'] = b64url(b'sha256:' + b'0' * 64)
        return files
    monkeypatch.setattr(container, '_collect', mutated_collect)
    monkeypatch.setattr(container_v2, '_collect', mutated_collect)
    with pytest.raises(ContainerError, match='verification'):
        if v2: agent.seal_v2(output, 'secret')
        else: agent.seal(output, 'secret')
    assert output.read_bytes() == b'accepted output'


def test_committed_output_returns_recovery_when_directory_fsync_fails(tmp_path, monkeypatch):
    import stat
    agent = Alethech.initialize(tmp_path / 'store')
    real_fsync = os.fsync
    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError('directory fsync unsupported')
        return real_fsync(fd)
    monkeypatch.setattr(os, 'fsync', fail_directory)
    output, code = agent.seal_v2(tmp_path / 'committed.aleth', 'secret')
    assert code is not None
    assert container_v2.inspect_container_v2(output, recovery_code=code)['version'] == 2


def test_container_seal_and_open_without_posix_fchmod(tmp_path, monkeypatch):
    agent = Alethech.initialize(tmp_path / 'store')
    monkeypatch.delattr(os, 'fchmod', raising=False)
    source, code = agent.seal_v2(tmp_path / 'memory.aleth', 'secret')
    assert agent.open_aleth_v2(source, tmp_path / 'opened', recovery_code=code).head == agent.head


def test_migration_rejects_hardlinked_source_alias(tmp_path):
    agent = Alethech.initialize(tmp_path / 'store')
    source = agent.seal(tmp_path / 'memory.aleth', 'old')
    alias = tmp_path / 'alias.aleth'
    os.link(source, alias)
    before = source.read_bytes()
    with pytest.raises(ContainerError, match='replace_source'):
        agent.migrate_aleth_v1_to_v2(source, alias, 'old', 'new')
    assert source.read_bytes() == alias.read_bytes() == before


@pytest.mark.parametrize('extra_type', ['passphrase', 'recovery-secret'])
def test_recovery_rejects_authenticated_extra_slots_without_output_loss(tmp_path, extra_type):
    import copy
    import struct
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from alethech.canonical import canonical_json_bytes
    agent = Alethech.initialize(tmp_path / 'store')
    source, code = agent.seal_v2(tmp_path / 'source.aleth', 'old')
    header, hb, ciphertext = container_v2._parse_header_v2(source.read_bytes())
    dek = container_v2._unlock_dek_with_passphrase(header, 'old')
    nonce = container._strict_b64(header['payload_nonce'])
    plain = AESGCM(dek).decrypt(nonce, ciphertext, hb)
    extra = copy.deepcopy(next(s for s in header['slots'] if s['type'] == extra_type))
    extra['id'] += '-extra'
    salt = container._strict_b64(extra['salt'])
    if extra_type == 'passphrase':
        kek = container_v2._derive_passphrase_kek('old', salt)
    else:
        kek = container_v2._derive_recovery_kek(container_v2.decode_recovery_secret(code), salt)
    extra['wrapped_key'] = container_v2._wrap_dek(dek, kek, container_id=header['container_id'],
        slot_id=extra['id'], slot_type=extra_type, nonce=container._strict_b64(extra['nonce']))
    header['slots'].append(extra)
    hb = canonical_json_bytes(header)
    source.write_bytes(container_v2.MAGIC_V2 + struct.pack('>I', len(hb)) + hb +
        AESGCM(dek).encrypt(nonce, plain, hb))
    output = tmp_path / 'existing.aleth'
    output.write_bytes(b'accepted output')
    with pytest.raises(ContainerError, match='exactly one passphrase and one recovery'):
        Alethech.recover_aleth_v2(source, output, code, 'new')
    assert output.read_bytes() == b'accepted output'


@pytest.mark.parametrize('v2', [False, True])
@pytest.mark.parametrize('fail_replace', [False, True])
def test_windows_existing_empty_destination_publication(tmp_path, monkeypatch, v2, fail_replace):
    agent = Alethech.initialize(tmp_path / 'store')
    source = tmp_path / 'memory.aleth'
    if v2: agent.seal_v2(source, 'secret')
    else: agent.seal(source, 'secret')
    destination = tmp_path / 'opened'
    destination.mkdir()
    monkeypatch.setattr(container.sys, 'platform', 'win32')
    real_replace = os.replace
    def windows_replace(stage, target):
        if target == destination:
            assert not destination.exists(), 'Windows rename requires an absent destination'
            if fail_replace:
                raise OSError('Windows publication failure')
        return real_replace(stage, target)
    monkeypatch.setattr(os, 'replace', windows_replace)
    before = set(tmp_path.iterdir())
    if fail_replace:
        with pytest.raises(OSError, match='Windows publication failure'):
            agent.open_aleth(source, destination, 'secret')
        assert destination.is_dir() and list(destination.iterdir()) == []
        assert set(tmp_path.iterdir()) == before
    else:
        assert agent.open_aleth(source, destination, 'secret').head == agent.head
