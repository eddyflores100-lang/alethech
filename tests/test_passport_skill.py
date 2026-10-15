"""Real encrypted skill workflows; no remote model, service or mocks."""
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest
from alethech.api import Alethech

SCRIPTS = Path(__file__).resolve().parents[1] / '.agents/skills/alethech/scripts'
sys.path.insert(0, str(SCRIPTS))


def passport_module():
    spec = importlib.util.find_spec('passport')
    assert spec is not None, 'The installable skill needs a standalone passport helper'
    import passport
    return passport


@pytest.fixture
def memory(tmp_path):
    return passport_module().Passport(tmp_path / 'device', 'project-a')


def test_first_save_is_encrypted_and_recall_survives_restart(memory):
    saved = memory.save({'goal': 'continue the release', 'next_steps': ['verify signing']})
    assert saved['saved'] is True
    assert memory.path.read_bytes().startswith(b'ALETH002')
    assert b'continue the release' not in memory.path.read_bytes()
    restarted = passport_module().Passport(memory.home, memory.space)
    view = restarted.recall()
    assert view['verified'] is True
    assert view['entries'][0]['content']['goal'] == 'continue the release'
    assert list(memory.home.rglob('commits')) == []
    assert list(memory.home.rglob('signing.key')) == []
    if os.name != 'nt':
        assert memory.key_path.stat().st_mode & 0o077 == 0


def test_consecutive_save_is_idempotent(memory):
    first = memory.save({'summary': 'same checkpoint'})
    second = memory.save({'summary': 'same checkpoint'})
    assert second['duplicate'] is True
    assert second['head'] == first['head']
    assert len(memory.recall()['entries']) == 1


def test_space_isolation_and_path_rejection(memory):
    memory.save({'summary': 'private project A'})
    other = passport_module().Passport(memory.home, 'project-b')
    assert other.recall()['entries'] == []
    for name in ('../escape', '/absolute', 'a/b', 'a\\b', '', '..'):
        with pytest.raises(ValueError):
            passport_module().Passport(memory.home, name)


def test_tampered_file_never_returns_content(memory):
    memory.save({'summary': 'confidential'})
    blob = bytearray(memory.path.read_bytes())
    blob[-1] ^= 1
    memory.path.write_bytes(blob)
    with pytest.raises(Exception):
        memory.recall()


def test_signed_but_old_file_is_rejected_by_local_checkpoint(memory):
    memory.save({'summary': 'first'})
    old = memory.path.read_bytes()
    memory.save({'summary': 'second'})
    memory.path.write_bytes(old)
    with pytest.raises(ValueError, match='continuity'):
        memory.recall()


@pytest.mark.parametrize('value', [
    {'api_key': 'sensitive-value'},
    {'notes': '-----BEGIN PRIVATE KEY-----\nsecret'},
    {'notes': 'ghp_' + 'a' * 36},
])
def test_common_secrets_are_rejected_without_saving(memory, value):
    with pytest.raises(ValueError, match='credential'):
        memory.save(value)
    assert not memory.path.exists()


def test_budget_covers_entire_unicode_response_and_skips_large_entries(memory):
    memory.save({'summary': '界' * 2500})
    memory.save({'summary': 'small and recent'})
    view = memory.recall(max_bytes=1100)
    assert len(json.dumps(view, ensure_ascii=False).encode()) <= 1100
    assert view['entries'][0]['content']['summary'] == 'small and recent'
    assert view['omitted'] == 1
    assert view['trust'] == 'untrusted-data'
    with pytest.raises(ValueError):
        memory.recall(max_bytes=12)


def test_lexical_recall_is_local_and_preserves_citations(memory):
    memory.save({'summary': 'Puebla deployment rollback plan'})
    memory.save({'summary': 'Ecuador billing invoice'})
    view = memory.recall(query='Puebla rollback')
    assert len(view['entries']) == 1
    assert 'Puebla' in view['entries'][0]['content']['summary']
    assert view['entries'][0]['commit_id'].startswith('sha256:')


def test_lock_refuses_a_second_writer(memory):
    memory.save({'summary': 'before'})
    memory.lock_path.write_text('occupied')
    with pytest.raises(ValueError, match='busy'):
        memory.save({'summary': 'after'})
    memory.lock_path.unlink()
    assert len(memory.recall()['entries']) == 1


def test_symlink_credential_is_rejected(memory, tmp_path):
    if os.name == 'nt':
        pytest.skip('symlink creation requires Windows developer permissions')
    memory.save({'summary': 'before'})
    key = memory.key_path.read_bytes()
    memory.key_path.unlink()
    target = tmp_path / 'foreign'
    target.write_bytes(key)
    memory.key_path.symlink_to(target)
    with pytest.raises(ValueError, match='symlink'):
        memory.recall()


def test_export_import_continue_signed_history_and_keep_credentials_local(memory, tmp_path):
    first = memory.save({'goal': 'launch AliceLabs'})
    output = tmp_path / 'transfer' / 'memory.aleth'
    recovery = tmp_path / 'private' / 'recovery.txt'
    result = memory.export_file(output, 'human portable password', recovery)
    assert 'recovery' not in json.dumps(result).lower().replace(str(recovery).lower(), '')
    assert recovery.read_text().startswith('aleth-recovery-v1:')
    assert b'human portable password' not in output.read_bytes()
    target = passport_module().Passport(tmp_path / 'second-device', 'project-a')
    target.import_file(output, 'human portable password')
    assert target.recall()['head'] == first['head']
    continued = target.save({'next_steps': ['finish release']})
    assert continued['head'] != first['head']
    assert len(target.recall()['entries']) == 2
    recovery_store = Alethech.open_aleth_v2(output, tmp_path / 'recover-store', recovery_code=recovery.read_text().strip())
    assert recovery_store.head == first['head']


def test_wrong_password_import_is_atomic(memory, tmp_path):
    memory.save({'summary': 'source'})
    output = tmp_path / 'transfer.aleth'
    memory.export_file(output, 'correct-password', tmp_path / 'private' / 'local-recovery')
    target = passport_module().Passport(tmp_path / 'target', 'default')
    with pytest.raises(Exception):
        target.import_file(output, 'incorrect-password')
    assert not target.path.exists()
    assert not target.key_path.exists()
    assert not target.state_path.exists()


def test_import_never_replaces_existing_space(memory, tmp_path):
    memory.save({'summary': 'source'})
    with pytest.raises(ValueError, match='exists'):
        memory.import_file(memory.path, 'anything')


def test_cloud_copies_ciphertext_only_and_refuses_changed_remote(memory, tmp_path):
    memory.save({'summary': 'before cloud'})
    folder = tmp_path / 'Synced folder'
    memory.connect_cloud(folder, 'portable cloud password')
    remote = folder / 'project-a.aleth'
    assert {p.name for p in folder.iterdir()} == {'project-a.aleth'}
    assert b'before cloud' not in remote.read_bytes()
    memory.save({'summary': 'new change'})
    remote_view = Alethech.drop_context(remote, 'portable cloud password')
    assert len(remote_view['entries']) == 2
    remote.write_bytes(b'other device revision')
    saved = memory.save({'summary': 'keep my local work'})
    assert saved['saved'] is True
    assert saved['cloud']['status'] == 'conflict'
    assert remote.read_bytes() == b'other device revision'
    assert len(memory.recall()['entries']) == 3


def test_cloud_rejects_credential_directory_and_existing_foreign_memory(memory):
    memory.save({'summary': 'source'})
    with pytest.raises(ValueError, match='separate'):
        memory.connect_cloud(memory.home, 'password')


def test_empty_status_and_recall_do_not_create_a_passport(memory):
    assert memory.status()['exists'] is False
    assert memory.recall()['entries'] == []
    assert not memory.path.exists()


def test_interrupted_first_checkpoint_leaves_no_partial_install(memory, monkeypatch):
    module = passport_module()
    original = module.atomic_write
    def interrupted(path, blob, **kwargs):
        if path.name in ('project-a.json', 'checkpoint.json'):
            raise OSError('simulated disk failure writing checkpoint')
        return original(path, blob, **kwargs)
    monkeypatch.setattr(module, 'atomic_write', interrupted)
    with pytest.raises(OSError):
        memory.save({'summary': 'must be installed as a complete unit'})
    assert not memory.path.exists()
    assert not memory.key_path.exists()
    assert not memory.state_path.exists()
    monkeypatch.setattr(module, 'atomic_write', original)
    assert memory.save({'summary': 'retry after interruption'})['saved'] is True


def test_interrupted_update_checkpoint_recovers_verified_new_head(memory, monkeypatch):
    module = passport_module()
    memory.save({'summary': 'old checkpoint'})
    original = module.atomic_write
    def interrupted(path, blob, **kwargs):
        if path == memory.state_path:
            raise OSError('simulated checkpoint failure after ciphertext commit')
        return original(path, blob, **kwargs)
    monkeypatch.setattr(module, 'atomic_write', interrupted)
    with pytest.raises(OSError):
        memory.save({'summary': 'new checkpoint'})
    monkeypatch.setattr(module, 'atomic_write', original)
    assert len(memory.recall()['entries']) == 2
    assert json.loads(memory.state_path.read_text())['head'] == memory.recall()['head']


def test_cloud_does_not_adopt_a_concurrent_revision_as_its_own(memory, tmp_path, monkeypatch):
    module = passport_module()
    memory.save({'summary': 'first'})
    folder = tmp_path / 'cloud'
    memory.connect_cloud(folder, 'portable cloud password')
    destination = folder / 'project-a.aleth'
    original = module.atomic_write
    def another_writer(path, blob, **kwargs):
        result = original(path, blob, **kwargs)
        if path == destination:
            path.write_bytes(b'concurrent cloud revision')
        return result
    monkeypatch.setattr(module, 'atomic_write', another_writer)
    memory.save({'summary': 'second'})
    monkeypatch.setattr(module, 'atomic_write', original)
    result = memory.save({'summary': 'third'})
    assert result['cloud']['status'] == 'conflict'
    assert destination.read_bytes() == b'concurrent cloud revision'


def test_cloud_cannot_hide_credential_directory_behind_dotdot(memory):
    memory.save({'summary': 'private'})
    aliased = memory.home.parent / 'unused' / '..' / memory.home.name
    with pytest.raises(ValueError, match='separate'):
        memory.connect_cloud(aliased, 'portable cloud password')
    assert not (memory.home / f'{memory.space}.aleth').exists()


def test_export_cannot_hide_recovery_directory_behind_dotdot(memory, tmp_path):
    memory.save({'summary': 'private'})
    output = tmp_path / 'transfer' / 'memory.aleth'
    recovery = tmp_path / 'unused' / '..' / 'transfer' / 'recovery.txt'
    with pytest.raises(ValueError, match='separate'):
        memory.export_file(output, 'portable password', recovery)
    assert not output.exists()


def test_internal_temporary_workflows_support_os_temp_aliases(memory, tmp_path, monkeypatch):
    if os.name == 'nt':
        pytest.skip('requires creating an OS-style temporary symlink')
    import tempfile
    physical = tmp_path / 'physical-temp'
    physical.mkdir()
    alias = tmp_path / 'system-temp-alias'
    alias.symlink_to(physical, target_is_directory=True)
    monkeypatch.setattr(tempfile, 'tempdir', str(alias))
    memory.save({'summary': 'macOS style temporary root'})
    assert memory.recall()['verified'] is True
    output = tmp_path / 'transfer' / 'memory.aleth'
    memory.export_file(output, 'portable password', tmp_path / 'private' / 'recovery')
    other = passport_module().Passport(tmp_path / 'second-device', memory.space)
    other.import_file(output, 'portable password')
    assert other.recall()['verified'] is True
    assert memory.connect_cloud(tmp_path / 'cloud', 'portable password')['status'] == 'copied'
