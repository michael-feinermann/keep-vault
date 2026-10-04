#!/usr/bin/python3
"""Definition-only L3 administration helpers; PREPARED / NOT RUN.\n\nCopied inventory and receipt helpers, with expanded public source binding.\nNo case launcher or product implementation exists in this module.\n"""
import argparse
import datetime
import hashlib
import json
import math
import os
import pathlib
import re
import shutil
import subprocess
import sys
import uuid

REPO = pathlib.Path('/Users/michael/Developer/GPT-Codex/Kalyna')
BASE = pathlib.Path(__file__).resolve().parent
DRIVER = BASE / 'run-development.py'
SDK = REPO / 'work/v13-evidence/rev11-release-b41144e/resume-harness/sdk/dotnet'
ROOT_ZPAQ = pathlib.Path('/Library/Application Support/Keep Vault/v13/zpaq')
BYTES = 1_073_741_824
SUITES = {
    'standard': 'StandardCascade', 'xchacha-aes': 'XChaChaOverAes', 'mixed': 'MixedCascade',
    'paranoia': 'ParanoiaCascade', 'threefish1024': 'Threefish1024', 'kalyna512-512': 'Kalyna512_512',
    'shacal2-512': 'Shacal2_512', 'mars448': 'Mars448', 'aes256': 'Aes256',
    'camellia': 'Camellia256', 'serpent': 'Serpent256', 'xchacha20-poly1305': 'XChaCha20Poly1305',
}
TESTS = [f'performance.rev12-workflow-1gib-{name}-auto' for name in SUITES]
GENERATED = {'.test-results.json', '.test-timings.json'}

def owned_fixture_names(build):
    return sorted(path.name for path in (build / 'tmp').glob('keep-vault-rev12-workflow-*'))

def remaining_group_processes(group_id):
    result = subprocess.run(['/bin/ps', '-axo', 'pid=,pgid=,stat='], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(result.returncode == 0, 'Owned process-group observation failed')
    return [{'pid': int(parts[0]), 'state': parts[2]} for line in result.stdout.splitlines() if len(parts := line.split()) == 3 and int(parts[1]) == group_id and not parts[2].startswith('Z')]
HEX64 = re.compile(r'^[0-9a-fA-F]{64}$')
NATIVE_NAMES = ('zpaq', 'libkalyna_v13.dylib', 'libthreefish_ref.dylib', 'libmars_ref.dylib',
    'libcamellia_v13.dylib', 'libserpent_v13.dylib', 'libshacal2_ref.dylib',
    'libaes_ref.dylib', 'libxchachapoly_v13.dylib', 'libargon2_ref.dylib')

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha(path):
    require(path.is_file() and not path.is_symlink(), 'Hash input must be a direct regular file: ' + str(path))
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()

def parse_json(raw):
    def invalid_number(token):
        raise ValueError('Non-finite JSON number: ' + token)
    def finite_float(token):
        value = float(token)
        require(math.isfinite(value), 'Non-finite JSON exponent: ' + token)
        return value
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'Duplicate JSON field: ' + key)
            value[key] = item
        return value
    return json.loads(raw, parse_constant=invalid_number, parse_float=finite_float, object_pairs_hook=unique_object)

def read_json(path):
    require(path.is_file() and not path.is_symlink(), 'JSON input must be a direct regular file: ' + str(path))
    return parse_json(path.read_bytes())

def save(path, value):
    # The destination belongs to this newly created private evidence directory.
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.partial')
    try:
        with temporary.open('x', encoding='utf-8') as stream:
            json.dump(value, stream, indent=2, allow_nan=False)
            stream.write('\n')
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()

def problem(row, stage, error):
    row['errors'].append({'stage': stage, 'type': type(error).__name__, 'message': str(error)})

def host(row, stage):
    observations = {}
    for name, command in {'os': ['/usr/bin/sw_vers'], 'battery': ['/usr/bin/pmset', '-g', 'batt'],
                          'thermal': ['/usr/bin/pmset', '-g', 'therm']}.items():
        try:
            result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            observations[name] = {'exitCode': result.returncode, 'output': result.stdout}
            require(result.returncode == 0, 'Host observation failed: ' + name)
        except Exception as error:
            problem(row, stage + '/' + name, error)
    return observations

def sources():
    rg_command = shutil.which('rg')
    require(rg_command is not None, 'rg is unavailable for the source inventory')
    files = subprocess.check_output([rg_command, '--files', '--hidden', '-g', '!work/**', '-g', '!.git/**',
        '-g', '*.cs', '-g', '*.csproj', '-g', '*.axaml', '-g', '*.json', '-g', '*.props',
        '-g', '*.md', '-g', '*.txt', '-g', '*.png',
        'KeepVaultMac', 'KeepVaultMac.Tests', 'KalynaArchiver', 'KalynaArchiver.Tests', 'KalynaArchiver.Signing'],
        cwd=REPO, text=True).splitlines()
    # This exact embedded public pin is the only extra .key input. No key glob.
    files.append('KeepVaultMac/Packaging/Keys/mldsa87-public.key')
    result = {}
    for name in sorted(set(files)):
        path = REPO / name
        require(path.is_file() and not path.is_symlink() and path.resolve(strict=True) == path,
                'Source input must be a direct regular repository file: ' + name)
        require(path.is_relative_to(REPO), 'Source input escaped repository')
        result[name] = sha(path)
    return result

def binaries(harness):
    # All harness inputs, dependencies, manifests, apphosts and native files;
    # only the two outputs deliberately replaced by the coordinator are excluded.
    require(SDK.is_file() and not SDK.is_symlink(), 'Unexpected retained SDK launcher')
    result = {'sdk/dotnet': {'type': 'file', 'bytes': SDK.stat().st_size, 'sha256': sha(SDK)}}
    # Framework-dependent test execution uses hostfxr/coreclr and shared .NET
    # assemblies from the retained SDK, in addition to the complete harness.
    roots = {'harness': harness, 'sdk/host': SDK.parent / 'host', 'sdk/shared': SDK.parent / 'shared'}
    for prefix, directory in roots.items():
        require(directory.is_dir() and not directory.is_symlink() and directory.resolve(strict=True) == directory,
                'Unsafe binary inventory root or ancestor: ' + prefix)
        for path in sorted(directory.rglob('*')):
            if prefix == 'harness' and path.name in GENERATED and path.parent == harness:
                continue
            name = prefix + '/' + path.relative_to(directory).as_posix()
            if path.is_symlink():
                target = path.resolve(strict=True)
                require(target.is_relative_to(directory) and target.is_file(), 'Unsafe binary symlink: ' + name)
                result[name] = {'type': 'symlink', 'target': os.readlink(path),
                                'bytes': target.stat().st_size, 'sha256': sha(target)}
            elif path.is_file():
                result[name] = {'type': 'file', 'bytes': path.stat().st_size, 'sha256': sha(path)}
            else:
                require(path.is_dir(), 'Unexpected binary input object: ' + name)
    # Only this fixed, public installed executable set is read. No key stores or
    # private cache/user state are inventoried. The product verifies this anchor
    # against the sealed harness copy before every actual ZPAQ launch.
    for suffix in ('', '.sha3', '.skein', '.khsig', '.sha3.khsig', '.skein.khsig'):
        path = pathlib.Path(str(ROOT_ZPAQ) + suffix)
        require(path.resolve(strict=True) == path, 'Public ZPAQ anchor has an alias ancestor')
        info = path.stat()
        result['root-zpaq/zpaq' + suffix] = {'type': 'file', 'bytes': info.st_size, 'sha256': sha(path),
            'uid': info.st_uid, 'gid': info.st_gid, 'mode': info.st_mode & 0o777, 'linkCount': info.st_nlink}
    require(result['root-zpaq/zpaq']['sha256'] == result['harness/Native/zpaq']['sha256'],
            'Installed public ZPAQ anchor differs from pinned harness copy')
    return result

def build_metadata(build):
    return {name: sha(build / name) for name in ('build-result.json', 'source-inputs-before.json',
        'source-inputs-after.json', 'toolchain.json')}

def finite(value, label, positive=False):
    require(type(value) in (int, float) and math.isfinite(value) and (value > 0 if positive else value >= 0),
            'Invalid finite public measurement: ' + label)

def count(value, label, positive=False):
    require(type(value) is int and (value > 0 if positive else value >= 0), 'Invalid public count: ' + label)

