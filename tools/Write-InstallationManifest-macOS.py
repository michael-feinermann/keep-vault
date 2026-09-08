#!/usr/bin/python3
"""Create the build-side inventory; the signed native verifier is the consumer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import unicodedata


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--build', required=True)
    args = parser.parse_args()
    root = Path(args.root)
    if str(root.absolute()) != str(root.resolve(strict=True)) or not root.is_dir():
        raise ValueError('The inventory root must be a physical absolute directory.')
    manifest = 'installation-manifest.json'
    suffixes = ['', '.sha3', '.skein', '.khsig', '.sha3.khsig', '.skein.khsig']
    excluded = {manifest + suffix for suffix in suffixes}
    expected = {'Keep Vault.app', 'QR-Scanner.app', 'Keep Vault Installer.app', 'INSTALLATION.txt'}
    expected.update('Keep Vault.app.launcher' + s for s in suffixes[1:])
    expected.update('QR-Scanner.app' + s for s in suffixes[1:])
    if {item.name for item in root.iterdir()} != expected:
        raise ValueError('The fresh stage does not contain exactly the distribution payload.')
    entries = []
    normalized = set()
    physical = set()
    for path in sorted(root.rglob('*'), key=lambda p: p.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            raise ValueError('An inventory file already exists in the fresh stage.')
        key = unicodedata.normalize('NFC', relative).casefold()
        if key in normalized:
            raise ValueError('An ambiguous inventory path was found.')
        normalized.add(key)
        before = path.lstat()
        mode = stat.S_IMODE(before.st_mode)
        if mode & 0o7022:
            raise ValueError('Special or group/other writable modes are forbidden: ' + relative)
        if stat.S_ISDIR(before.st_mode):
            entries.append({'path': relative, 'kind': 'directory', 'mode': mode})
            continue
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('Only ordinary single-link files are allowed: ' + relative)
        inode = (before.st_dev, before.st_ino)
        if inode in physical:
            raise ValueError('A physical file identity is duplicated.')
        physical.add(inode)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if identity(before) != identity(os.fstat(descriptor)):
                raise ValueError('A file changed before inventory hashing.')
            digest = hashlib.sha256()
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
            if identity(before) != identity(os.fstat(descriptor)) or identity(before) != identity(path.lstat()):
                raise ValueError('A file changed during inventory hashing.')
        finally:
            os.close(descriptor)
        entries.append({'path': relative, 'kind': 'file', 'size': before.st_size,
                        'sha256': digest.hexdigest(), 'mode': mode})
    data = {'schemaVersion': 1, 'version': args.version, 'build': args.build, 'entries': entries}
    descriptor = os.open(root / manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
        json.dump(data, output, ensure_ascii=False, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


if __name__ == '__main__':
    main()
