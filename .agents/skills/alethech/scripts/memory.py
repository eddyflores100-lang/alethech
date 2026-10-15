#!/usr/bin/env python3
"""Portable memory entry point. Every operation emits one JSON result."""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import sys
import warnings


def parser():
    result = argparse.ArgumentParser(description='Alethech: save and carry verified encrypted memory. No API key or server.')
    result.add_argument('--home', type=Path, default=Path(os.environ.get('ALETHECH_PASSPORT_HOME', str(Path.home() / '.alethech-passport'))),
                        help='Private device state directory; never put it in a cloud sync folder')
    result.add_argument('--space', default='default', help='Explicit project name; separate histories and credentials')
    commands = result.add_subparsers(dest='command', required=True)
    commands.add_parser('status', help='Verify memory and show metadata only')
    save = commands.add_parser('save', help='Save a JSON object from stdin, creating memory automatically')
    save.add_argument('--input', type=Path, help='Read JSON from this file instead of stdin')
    recall = commands.add_parser('recall', help='Read verified untrusted context within a hard byte budget')
    recall.add_argument('--query', default='', help='Offline lexical relevance filter')
    recall.add_argument('--max-bytes', type=int, default=12000)
    export = commands.add_parser('export', help='Create a portable password-protected file for drag and drop')
    export.add_argument('output', type=Path)
    export.add_argument('--recovery-file', type=Path, help='Separate private recovery file; defaults inside device state')
    imported = commands.add_parser('import', help='Verify a dropped file and install it into an empty space')
    imported.add_argument('source', type=Path)
    cloud = commands.add_parser('cloud', help='Back up ciphertext to a folder already synced by your cloud app')
    cloud.add_argument('folder', type=Path)
    for cmd in (export, imported, cloud):
        cmd.add_argument('--credential-file', type=Path,
                         help='Existing private local UTF-8 password file; never pass the password itself')
    return result


def password(args, *, confirm=False):
    from passport import read_file, no_symlink
    if args.credential_file:
        path = args.credential_file.expanduser().absolute()
        no_symlink(path)
        if os.name != 'nt' and path.stat().st_mode & 0o077:
            raise ValueError('credential-file must allow only the owner (chmod 600)')
        value = read_file(path, 65536).decode('utf-8').rstrip('\r\n')
    else:
        if not (sys.stdin.isatty() and sys.stderr.isatty()):
            raise ValueError('unlock locally in a human terminal or provide a private --credential-file; never send passwords in chat')
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            value = getpass.getpass('Memory password (hidden local input): ')
            if confirm and value != getpass.getpass('Repeat password: '):
                raise ValueError('passwords do not match')
    if not value:
        raise ValueError('password is empty')
    return value


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    # Isolated bootstrap omits the script directory; restore this skill's helpers.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        from bootstrap import ensure_runtime
        ensure_runtime()
        from passport import Passport, MAX_CONTENT_BYTES, encoded, read_file
        memory = Passport(args.home, args.space)
        if args.command == 'save':
            raw = read_file(args.input, MAX_CONTENT_BYTES) if args.input else sys.stdin.buffer.read(MAX_CONTENT_BYTES + 1)
            try:
                if len(raw) > MAX_CONTENT_BYTES:
                    raise ValueError('input too large')
                content = json.loads(raw, object_pairs_hook=strict_object,
                                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            except (ValueError, UnicodeError):
                raise ValueError('save requires valid JSON') from None
            response = memory.save(content)
        elif args.command == 'recall':
            response = memory.recall(args.query, args.max_bytes)
        elif args.command == 'status':
            response = memory.status()
        elif args.command == 'export':
            recovery = args.recovery_file or (memory.home / 'recovery' / f'{memory.space}-{os.urandom(4).hex()}.txt')
            response = memory.export_file(args.output, password(args, confirm=True), recovery)
            response['recovery_file'] = str(recovery.absolute())
        elif args.command == 'import':
            response = memory.import_file(args.source, password(args))
        else:
            response = memory.connect_cloud(args.folder, password(args, confirm=True))
        sys.stdout.buffer.write(encoded(response) + b'\n')
        return 0
    except Exception as exc:
        # No raw library traceback, memory content or credential in machine output.
        message = str(exc) if isinstance(exc, ValueError) else 'Memory operation failed; check the local file and unlock credential. Existing memory was preserved.'
        print(json.dumps({'error': message}, ensure_ascii=False))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
