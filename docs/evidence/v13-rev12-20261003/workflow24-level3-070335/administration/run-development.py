#!/usr/bin/python3
"""Retained, isolated REV12 development harness; never a release approval."""
import datetime, hashlib, json, os, pathlib, shutil, subprocess, sys, uuid

REPO = pathlib.Path('/Users/michael/Developer/GPT-Codex/Kalyna')
BASE = pathlib.Path(__file__).resolve().parent
TOOLCHAIN = REPO / 'work/v13-evidence/rev11-release-b41144e/resume-harness'
SDK = TOOLCHAIN / 'sdk/dotnet'

def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()

def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

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

def verify_inventory(directory, manifest):
    rows = json.loads(manifest.read_text())
    for name, row in rows.items():
        path = directory/name
        if row['type'] == 'file':
            require(path.is_file() and not path.is_symlink() and sha(path) == row['sha256'], 'Bound toolchain input changed: '+name)
        elif row['type'] == 'symlink':
            require(path.is_symlink() and os.readlink(path) == row['target'], 'Bound toolchain symlink changed: '+name)
    return len(rows)

BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
if sys.argv[1:] == ['build']:
    root = BASE / ('build-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    root.mkdir(mode=0o700)
    for name in ['cli-home', 'http-cache', 'scratch', 'tmp', 'artifacts']:
        (root/name).mkdir(mode=0o700)
    sdk_count = verify_inventory(TOOLCHAIN/'sdk', TOOLCHAIN/'sdk-copy.json')
    package_count = verify_inventory(TOOLCHAIN/'packages', TOOLCHAIN/'packages-copy.json')
    shutil.copytree(TOOLCHAIN/'packages', root/'packages', symlinks=True)
    before = sources()
    save(root/'source-inputs-before.json', before)
    save(root/'toolchain.json', {'sdkInventorySha256': sha(TOOLCHAIN/'sdk-copy.json'), 'sdkEntries': sdk_count,
        'packageInventorySha256': sha(TOOLCHAIN/'packages-copy.json'), 'packageEntries': package_count,
        'provenance': 'Preserved previously verified official SDK 10.0.400; copied public package cache; fresh private artifact tree.'})
    (BASE/'latest-build.txt').write_text(str(root)+'\n')
    action = 'build'
else:
    require(len(sys.argv)>1 and sys.argv[1]=='test', 'Usage: run-development.py build | test [harness options]')
    root = pathlib.Path(os.environ['KEEPVAULT_TEST_BUILD_ROOT']) if os.environ.get('KEEPVAULT_TEST_BUILD_ROOT') else pathlib.Path((BASE/'latest-build.txt').read_text().strip())
    require(root.is_absolute(), 'The pinned test build must be an absolute path')
    require(root.parent==BASE and root.is_dir() and not root.is_symlink(), 'Unsafe retained build')
    require(json.loads((root/'build-result.json').read_text())['status']=='PASS', 'No successful isolated build')
    require(sources()==json.loads((root/'source-inputs-before.json').read_text()), 'Sources changed after compilation; compile again')
    action='test'

env = {'HOME': str(root/'cli-home'), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'TMPDIR': str(root/'tmp'),
    'DOTNET_CLI_HOME': str(root/'cli-home'), 'DOTNET_ROOT': str(TOOLCHAIN/'sdk'), 'NUGET_PACKAGES': str(root/'packages'),
    'NUGET_HTTP_CACHE_PATH': str(root/'http-cache'), 'NUGET_SCRATCH': str(root/'scratch'),
    'DOTNET_EnableDiagnostics': '0', 'COMPlus_EnableDiagnostics': '0', 'DOTNET_CLI_TELEMETRY_OPTOUT':'1',
    'DOTNET_NOLOGO':'1', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE':'1', 'DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE':'1',
    'DOTNET_GENERATE_ASPNET_CERTIFICATE':'false', 'DOTNET_ADD_GLOBAL_TOOLS_TO_PATH':'false', 'MSBUILDDISABLENODEREUSE':'1',
    'KEEPVAULT_TEST_REPOSITORY_ROOT':str(REPO), 'KEEPVAULT_TEST_RELEASE_ROOT':'/Applications'}
require(subprocess.check_output([str(SDK), '--version'], cwd=REPO/'KeepVaultMac', env=env, text=True).strip()=='10.0.400', 'SDK version drift')

if action=='build':
    lock_names=['KeepVaultMac/packages.lock.json','KeepVaultMac.Tests/packages.lock.json']
    locks={name:sha(REPO/name) for name in lock_names}
    commands=[
        [str(SDK),'restore',str(REPO/'KeepVaultMac.Tests/KeepVaultMac.Tests.csproj'),'--artifacts-path',str(root/'artifacts'),
            '--locked-mode','--force','-p:RestoreForceEvaluate=false','--no-http-cache','--disable-build-servers','--nologo'],
        [str(SDK),'build',str(REPO/'KeepVaultMac.Tests/KeepVaultMac.Tests.csproj'),'-c','Release','--no-restore','--no-incremental',
            '--artifacts-path',str(root/'artifacts'),'--disable-build-servers','-p:UseSharedCompilation=false','--nologo'],
        [str(REPO/'tools/Stage-TestNatives-macOS.sh'),'--app','/Applications/Keep Vault.app','--destination',
            str(root/'artifacts/bin/KeepVaultMac.Tests/release_osx-arm64/Native')]]
    status=0
    for number, command in enumerate(commands):
        with (root/f'build-{number}.log').open('x') as log:
            result=subprocess.run(command,cwd=REPO/'KeepVaultMac',env=env,stdout=log,stderr=subprocess.STDOUT)
        print(f'build_step={number} exit={result.returncode} log={root/f"build-{number}.log"}',flush=True)
        if result.returncode:
            status=result.returncode
            break
        require(locks=={name:sha(REPO/name) for name in lock_names},'Dependency locks changed')
    after=sources()
    save(root/'source-inputs-after.json',after)
    stable=before==after
    save(root/'build-result.json',{'status':'PASS' if status==0 and stable else 'FAIL','exitCode':status,
        'sourcesStable':stable,'scope':'Managed development build with installed build15 signed natives, not a new signed product/release.'})
    require(stable,'Sources changed during compilation; artifact is not authoritative')
    raise SystemExit(status)

out=root/('run-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8])
out.mkdir(mode=0o700)
harness=root/'artifacts/bin/KeepVaultMac.Tests/release_osx-arm64'
# A selector error or direct worker run produces no coordinator result file.
# Remove only our previous generated outputs before launching, so an old
# result cannot be copied as evidence of a later, unexecuted selection.
for generated in ['.test-results.json', '.test-timings.json']:
    path = harness/generated
    require(not path.is_symlink(), 'Unexpected symlink in generated test output')
    if path.exists():
        require(path.is_file(), 'Unexpected generated test-output object')
        path.unlink()
args=[str(SDK),str(harness/'KeepVaultMac.Tests.dll'),*sys.argv[2:]]
for key in ['KEEPVAULT_PERF_BASELINE']:
    if os.environ.get(key):
        baseline=pathlib.Path(os.environ[key])
        if not baseline.is_absolute(): baseline=REPO/baseline
        baseline=baseline.resolve(strict=True)
        require(baseline.is_file(), 'Performance baseline is not a regular file')
        env[key]=str(baseline)
        save(out/'baseline-input.json', {'path':str(baseline),'sha256':sha(baseline)})
started=datetime.datetime.now(datetime.timezone.utc).isoformat()
with (out/'run.log').open('x') as log:
    result=subprocess.run(args,cwd=REPO/'KeepVaultMac',env=env,stdout=log,stderr=subprocess.STDOUT)
files={}
for name in ['.test-results.json','.test-timings.json']:
    path=harness/name
    if path.is_file() and not path.is_symlink():
        shutil.copy2(path,out/name[1:])
        files[name[1:]]=sha(out/name[1:])
save(out/'execution.json',{'startedUtc':started,'completedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'command':args,'exitCode':result.returncode,'logSha256':sha(out/'run.log'),'files':files,
    'sourceInputsSha256':sha(root/'source-inputs-before.json'),'scope':'REV12 development evidence; no installed GUI or release approval.'})
print(f'test_exit={result.returncode} evidence={out}',flush=True)
require(sources()==json.loads((root/'source-inputs-before.json').read_text()),'Source drift during tests')
raise SystemExit(result.returncode)
