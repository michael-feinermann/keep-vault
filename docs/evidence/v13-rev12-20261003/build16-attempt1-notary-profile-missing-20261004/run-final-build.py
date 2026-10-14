#!/usr/bin/env python3
"""Run one actual release builder; preserve its exit and public source binding."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import subprocess
import sys

REPO = Path('/Users/michael/Developer/GPT-Codex/Kalyna')
OUT = Path(__file__).resolve().parent
KEYS = Path('/Volumes/Keep Vault Keys 5.0.3 Secure/Keys')
BASELINE = REPO / 'work/v13-evidence/rev11-release-b41144e/publication/historical-536d7c2-macos27-primitive-baseline.json'

def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def source_map():
    roots = ['KalynaArchiver', 'KalynaArchiver.Tests', 'KeepVaultMac', 'KeepVaultMac.Tests',
             'KeepVaultMac.ReleaseVerifier', 'KalynaArchiver.Signing']
    allowed = {'.cs', '.csproj', '.axaml', '.json', '.props', '.md', '.txt', '.png'}
    result = {}
    for root in roots:
        for p in sorted((REPO/root).rglob('*')):
            if not p.is_file() or p.is_symlink() or p.suffix not in allowed:
                continue
            if any(part in {'bin', 'obj'} for part in p.relative_to(REPO/root).parts):
                continue
            result[p.relative_to(REPO).as_posix()] = sha(p)
    public_pin = REPO/'KeepVaultMac/Packaging/Keys/mldsa87-public.key'
    result[public_pin.relative_to(REPO).as_posix()] = sha(public_pin)
    return dict(sorted(result.items()))

def save(name, value):
    with (OUT/name).open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')

def main():
    os.umask(0o077)
    assert subprocess.check_output(['git','status','--porcelain'],cwd=REPO)==b'', 'Source must be committed and clean.'
    assert sha(BASELINE)=='0caa36a1f5cbf165118eaf731cc7fdc9e1d4829663b3dcb07d9cf63d4c3fd822'
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO).decode().strip()
    before=source_map()
    save('source-inputs-before.json',before)
    env=os.environ.copy()
    env['KEEPVAULT_PERF_BASELINE']=str(BASELINE)
    env['KEEPVAULT_MLDSA_WRAPPING_KEY_FILE']=str(KEYS/'mldsa-v12-wrapping-key.b64')
    env['KEEPVAULT_PFX_WRAPPING_KEY_FILE']=str(KEYS/'pfx-v12-wrapping-key.b64')
    args=['/bin/zsh','-f',str(REPO/'tools/Build-KeepVault-macOS.sh'),
          '--architecture','universal','--version','5.0.3','--build-number','16',
          '--identity','E8C06D4E89287BEC082E0EAD8DB01DD810A302AD',
          '--mldsa-public-key',str(REPO/'KeepVaultMac/Packaging/Keys/mldsa87-public.key'),
          '--pfx',str(KEYS/'hybrid-rsa4096.pfx'),
          '--mldsa-private-key-encrypted',str(KEYS/'mldsa87-private.key.v12.enc'),
          '--pfx-password-encrypted',str(KEYS/'hybrid-rsa4096.pfx.password.v12.enc'),
          '--notary-profile','Keep Vault v13','--release','--install-for-tests']
    start={'startedUtc':stamp(),'sourceHead':head,'sourceFileCount':len(before),
           'sourceMapSha256':sha(OUT/'source-inputs-before.json'),
           'launcherPid':os.getpid(),'launcherSha256':sha(Path(__file__)),
           'builderSha256':sha(REPO/'tools/Build-KeepVault-macOS.sh'),
           'scope':'Declared project sources plus one explicitly public pin; private key contents are neither copied nor recorded.',
           'compressionTestLevel':3,'requestedBuild':16,'status':'STARTED'}
    with (OUT/'build.log').open('xb') as log:
        child=subprocess.Popen(args,cwd=REPO,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        start['builderPid']=child.pid
        save('build-start.json',start)
        print('actual_builder_pid='+str(child.pid),flush=True)
        for chunk in iter(lambda:child.stdout.read1(65536),b''):
            log.write(chunk);log.flush()
            sys.stdout.buffer.write(chunk);sys.stdout.buffer.flush()
        code=child.wait()
    after=source_map();save('source-inputs-after.json',after)
    after_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO).decode().strip()
    git_clean=subprocess.check_output(['git','status','--porcelain'],cwd=REPO)==b''
    stable=before==after and head==after_head and git_clean
    save('build-exit.json',{'completedUtc':stamp(),'builderExitCode':code,
         'sourceHeadBefore':head,'sourceHeadAfter':after_head,'sourcesStable':stable,'gitCleanAfter':git_clean,
         'buildLogSha256':sha(OUT/'build.log'),'status':'PASS' if code==0 and stable else 'FAIL',
         'scope':'Actual builder result only; installed native GUI and final release verification remain separate.'})
    return code if code else (0 if stable else 2)

if __name__=='__main__':
    raise SystemExit(main())
