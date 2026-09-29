import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import time

ROOT = Path('/Users/michael/Developer/GPT-Codex/Kalyna')
OUT = Path(__file__).resolve().parent
TMP = OUT / 'temporary'
TMP.mkdir(mode=0o700)
SCRIPT = ROOT / 'tools/Test-InstallerBoundDelete-macOS.sh'
SOURCE = ROOT / 'tools/InstallerBoundDelete.c'

def digest(data):
    return hashlib.sha256(data).hexdigest().upper()

def source_hashes():
    return {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in (SCRIPT, SOURCE)}

before = source_hashes()
environment = {key: value for key, value in os.environ.items() if not key.startswith('KEEPVAULT_')}
environment['TMPDIR'] = str(TMP) + '/'
command = ['/bin/zsh', '-f', '-x', str(SCRIPT)]
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
start = time.monotonic()
helper_fd = None
helper_metadata = None
captured = None
with (OUT / 'test.log').open('xb') as log:
    process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT)
    while process.poll() is None:
        if helper_fd is None:
            for candidate in TMP.glob('keep-vault-bound-delete-test.*/installer-bound-delete'):
                try:
                    metadata = candidate.lstat()
                    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o500:
                        continue
                    helper_fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW)
                    current = os.fstat(helper_fd)
                    if (current.st_dev, current.st_ino, current.st_mode) != (metadata.st_dev, metadata.st_ino, metadata.st_mode):
                        os.close(helper_fd)
                        helper_fd = None
                        continue
                    helper_metadata = {'path_during_test': str(candidate), 'device': current.st_dev, 'inode': current.st_ino, 'size': current.st_size, 'mode': oct(stat.S_IMODE(current.st_mode))}
                    with os.fdopen(os.dup(helper_fd), 'rb') as helper:
                        captured = helper.read()
                    break
                except FileNotFoundError:
                    continue
        time.sleep(0.002)
    return_code = process.wait()
elapsed = time.monotonic() - start
if helper_fd is not None:
    os.lseek(helper_fd, 0, os.SEEK_SET)
    with os.fdopen(helper_fd, 'rb') as helper:
        final_bytes = helper.read()
    helper_metadata['sha256'] = digest(captured)
    helper_metadata['unchanged_through_exit'] = captured == final_bytes
    (OUT / 'InstallerBoundDelete.test').write_bytes(final_bytes)
    (OUT / 'InstallerBoundDelete.test').chmod(0o400)
after = source_hashes()
log_bytes = (OUT / 'test.log').read_bytes()
markers = [
    'installer_bound_delete_file=true',
    'installer_bound_delete_recursive_nofollow=true',
    'installer_bound_delete_identity_mismatch_preserved=true',
    'installer_bound_delete_directory_guards=true',
]
marker_results = {marker: marker.encode() in log_bytes.splitlines() for marker in markers}
result = {
    'schema': 1,
    'started_utc': started,
    'duration_seconds': elapsed,
    'repository_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
    'command': command,
    'cwd': str(ROOT),
    'environment_overrides': {'TMPDIR': str(TMP) + '/', 'KEEPVAULT_variables': 'all removed'},
    'host_architecture': platform.machine(),
    'compiler_version': subprocess.check_output(['/usr/bin/xcrun', 'clang', '--version'], text=True),
    'return_code': return_code,
    'source_sha256_before': before,
    'source_sha256_after': after,
    'source_unchanged': before == after,
    'actual_test_helper': helper_metadata,
    'log_sha256': digest(log_bytes),
    'markers': marker_results,
    'temporary_directory_empty_after_cleanup': not any(TMP.iterdir()),
    'scope': 'Synthetic file and directory operations using an isolated compiled helper; no product build, release keys, signing, installed application, or GUI checks.',
}
result['passed'] = return_code == 0 and all(marker_results.values()) and before == after and helper_metadata is not None and helper_metadata['unchanged_through_exit'] and result['temporary_directory_empty_after_cleanup']
(OUT / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
raise SystemExit(0 if result['passed'] else 1)
