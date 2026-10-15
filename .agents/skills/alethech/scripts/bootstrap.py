"""Resolve an isolated protocol runtime; never modify global Python packages."""
from __future__ import annotations

import importlib
import os
from pathlib import Path
import subprocess
import sys
import venv

PROTOCOL = 'alethech==0.9.5'


def protocol_available() -> bool:
    try:
        protocol = importlib.import_module('alethech')
        api = importlib.import_module('alethech.api')
        search = importlib.import_module('alethech.search')
        importlib.import_module('click')
        importlib.import_module('cryptography')
        return (getattr(protocol, '__version__', None) == '0.9.5'
                and all(hasattr(api.Alethech, name) for name in
                        ('initialize', 'open_aleth', 'seal_v2', 'drop_context'))
                and hasattr(search, 'TFIDFEmbedder') and hasattr(search, 'LocalSearch'))
    except (ImportError, AttributeError):
        return False


def ensure_runtime() -> None:
    if sys.version_info < (3, 10):
        raise ValueError('Python 3.10 or newer is required')
    if protocol_available():
        return
    if os.environ.get('ALETHECH_NO_BOOTSTRAP') == '1':
        raise ValueError('protocol unavailable; install alethech==0.9.5 in this Python environment')
    # Install once, only if the current runtime cannot execute the protocol.
    cache = Path(os.environ.get('ALETHECH_SKILL_RUNTIME',
                 str(Path.home() / '.cache' / 'alethech-skill' / f'py{sys.version_info.major}{sys.version_info.minor}'))).expanduser().absolute()
    for path in (cache, *cache.parents):
        if path.is_symlink():
            raise ValueError('runtime cache cannot use symlink paths')
    python = cache / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    marker = cache / '.alethech-ready'
    cache.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    lock = cache.with_suffix('.lock')
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ValueError('runtime setup busy; retry after installation completes') from None
    try:
        os.close(fd)
        if not marker.is_file() or not python.is_file():
            print('Preparing private Alethech runtime (one-time package download; no API key).', file=sys.stderr)
            venv.EnvBuilder(with_pip=True).create(cache)
            subprocess.run([str(python), '-I', '-m', 'pip', '--isolated', 'install',
                            '--disable-pip-version-check', '--no-input', PROTOCOL],
                           stdout=sys.stderr, stderr=sys.stderr, check=True, timeout=180)
            marker.write_text(PROTOCOL, encoding='utf-8')
    finally:
        lock.unlink(missing_ok=True)
    child_env = {**os.environ, 'ALETHECH_NO_BOOTSTRAP': '1'}
    child_env.pop('PYTHONPATH', None)
    child_env.pop('PYTHONHOME', None)
    result = subprocess.run([str(python), '-I', str(Path(__file__).with_name('memory.py')), *sys.argv[1:]],
                            env=child_env)
    raise SystemExit(result.returncode)
