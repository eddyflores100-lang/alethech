"""The installed skill runs without the source checkout or hidden dependencies."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / '.agents/skills/alethech'


def run_skill(skill, home, *args, content=None):
    return subprocess.run([sys.executable, str(skill / 'scripts/memory.py'),
                           '--home', str(home), '--space', 'demo', *args],
                          input=content, text=True, capture_output=True, timeout=30,
                          cwd=home.parent,
                          env={**os.environ, 'ALETHECH_NO_BOOTSTRAP': '1'})


def test_standalone_skill_saves_stdin_and_recalls(tmp_path):
    installed = tmp_path / 'installed' / 'alethech'
    shutil.copytree(SKILL, installed, ignore=shutil.ignore_patterns('__pycache__'))
    saved = run_skill(installed, tmp_path / 'device', 'save',
                      content=json.dumps({'goal': 'carry memory', 'next_steps': ['deploy']}))
    assert saved.returncode == 0, saved.stderr
    assert json.loads(saved.stdout)['saved'] is True
    recalled = run_skill(installed, tmp_path / 'device', 'recall', '--max-bytes', '1500')
    assert recalled.returncode == 0, recalled.stderr
    assert len(recalled.stdout.encode()) <= 1500
    assert json.loads(recalled.stdout)['entries'][0]['content']['goal'] == 'carry memory'


def test_invalid_json_produces_safe_json_error(tmp_path):
    response = run_skill(SKILL, tmp_path / 'device', 'save', content='not JSON')
    assert response.returncode == 1
    assert json.loads(response.stdout)['error'] == 'save requires valid JSON'
    assert 'Traceback' not in response.stderr


def test_secret_never_appears_in_error_output(tmp_path):
    secret = 'ghp_' + 'x' * 36
    response = run_skill(SKILL, tmp_path / 'device', 'save',
                         content=json.dumps({'notes': secret}))
    assert response.returncode == 1
    assert secret not in response.stdout + response.stderr


def test_noninteractive_export_explains_local_unlock(tmp_path):
    run_skill(SKILL, tmp_path / 'device', 'save', content='{"goal":"continue"}')
    response = run_skill(SKILL, tmp_path / 'device', 'export', str(tmp_path / 'memory.aleth'))
    assert response.returncode == 1
    assert 'credential-file' in json.loads(response.stdout)['error']
    assert not (tmp_path / 'memory.aleth').exists()


def test_help_does_not_require_protocol_or_install_anything(tmp_path):
    response = subprocess.run([sys.executable, '-S', str(SKILL / 'scripts/memory.py'), '--help'],
                              text=True, capture_output=True, timeout=10)
    assert response.returncode == 0, response.stderr
    assert 'recall' in response.stdout


def test_duplicate_json_keys_are_rejected(tmp_path):
    response = run_skill(SKILL, tmp_path / 'device', 'save', content='{"goal":"one","goal":"two"}')
    assert response.returncode == 1
    assert 'valid JSON' in json.loads(response.stdout)['error']


def test_old_protocol_is_detected_before_attempting_memory_operation(tmp_path):
    old = tmp_path / 'old-runtime' / 'alethech'
    old.mkdir(parents=True)
    (old / '__init__.py').write_text('__version__ = "0.9.0"\n')
    response = subprocess.run([sys.executable, str(SKILL / 'scripts/memory.py'),
                               '--home', str(tmp_path / 'device'), 'status'],
                              text=True, capture_output=True, timeout=10,
                              env={**os.environ, 'ALETHECH_NO_BOOTSTRAP': '1',
                                   'PYTHONPATH': str(old.parent)})
    assert response.returncode == 1
    assert 'protocol unavailable' in json.loads(response.stdout)['error']
    assert not (tmp_path / 'device').exists()
