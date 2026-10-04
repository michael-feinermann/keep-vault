#!/usr/bin/python3
"""Twelve pinned, serial production-KDF workflows with retained outcomes."""
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
    rg = shutil.which('rg')
    require(rg is not None, 'rg is unavailable for the source inventory')
    paths = subprocess.check_output([rg, '--files', '--hidden', '-g', '!work/**', '-g', '!.git/**',
        '-g', '*.cs', '-g', '*.csproj', '-g', '*.axaml', '-g', '*.json', '-g', '*.props',
        'KeepVaultMac', 'KeepVaultMac.Tests', 'KalynaArchiver', 'KalynaArchiver.Tests', 'KalynaArchiver.Signing'],
        cwd=REPO, text=True).splitlines()
    result = {}
    for name in sorted(paths):
        path = REPO / name
        require(path.is_file() and not path.is_symlink(), 'Unexpected source input: ' + name)
        require(path.resolve().is_relative_to(REPO.resolve()), 'Source input escaped repository')
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

def validate_artifact(data, test_id, suite, expected):
    require(data['testId'] == test_id and data['suite'] == suite and data['schemaVersion'] == 1,
            'Wrong workflow artifact identity/schema')
    for name, value in (('schemaVersion', 1), ('measuredWorkflows', 1), ('repetitions', 1), ('warmups', 0), ('compressionLevel', 5)):
        count(data[name], name)
        require(data[name] == value, 'Wrong actual workflow/schema/repetition count: ' + name)
    require(data['compressionLevel'] == 5 and data['requestedCpuMode'] == 'Auto'
            and data['requestedWorkers'] is None and data['leaseCleanupVerified'] is True,
            'Workflow has wrong compression, preference or cleanup scope')
    require(data['processArchitecture'].lower() == 'arm64' and data['osArchitecture'].lower() == 'arm64',
            'Unexpected actual architecture for the pinned arm64 workflow')
    require(data['assemblySha256'].lower() == expected['harness/Keep Vault.dll']['sha256'],
            'Reported product assembly differs from the pinned binary')
    receipt = data['receipt']
    for name in ('InputBytes', 'InputFiles', 'InputDirectories'):
        count(receipt[name], name)
    require(receipt['InputBytes'] == BYTES and receipt['InputFiles'] == 3 and receipt['InputDirectories'] == 5,
            'Wrong exact source byte count or fixture topology')
    for name in ('CompressedPayloadBytesDuringCreation', 'ContainerBytes', 'RecoveryBytes', 'InitialCpuCeiling'):
        count(receipt[name], name, positive=True)
    for name in ('InputManifestSha256', 'ContainerSha256'):
        require(HEX64.fullmatch(receipt[name]) is not None, 'Invalid hash: ' + name)
    require('entire payload.bin remainder' in data['fixturePattern'] and 'SplitMix64' in data['fixturePattern'],
            'Wrong explicitly authorized one-GiB fixture pattern')
    for name in ('setupSeconds', 'preparationSeconds', 'managedProcessCpuSecondsThroughOriginalComparison'):
        finite(data[name], name)
    combined = data['processAndObservedZpaqChildCpuSecondsThroughOriginalComparison']
    if combined is not None:
        finite(combined, 'sampled parent/child CPU')
    finite(data['workflowWallSeconds'], 'workflow wall', positive=True)
    required_phases = ('originalCreationSnapshot', 'archiveAndEncrypt', 'supplementalContainerHash',
        'recoveryCreate', 'supplementalRecoveryHealthyVerification', 'decryptAndExtractForOriginalComparison',
        'originalComparisonAndIndependentHashTopologyCheck', 'fixtureCleanup')
    require(set(data['phaseWallSeconds']) == set(required_phases), 'Missing or duplicate outer service phase')
    for name, value in data['phaseWallSeconds'].items():
        finite(value, name, positive=name != 'fixtureCleanup')
    for name, wall in (('sourceMiBPerSecondCompleteWorkflow', data['workflowWallSeconds']),
                       ('sourceMiBPerSecondArchiveAndEncrypt', data['phaseWallSeconds']['archiveAndEncrypt'])):
        finite(data[name], name, positive=True)
        require(math.isclose(data[name], 1024 / wall, rel_tol=1e-8), 'Wrong source-byte throughput denominator')
    outer = data['outerWorkflowTimeline']
    names = ('memoryAdmissionAndOriginalCreationSnapshot', 'archiveAndEncrypt', 'supplementalContainerHash',
        'recoveryCreate', 'supplementalRecoveryHealthyVerification', 'decryptAndExtractForOriginalComparison',
        'originalComparisonAndIndependentHashTopologyCheck', 'ownedResourcesAndFixtureCleanup')
    require(len(outer) == 8 and tuple(item['Phase'] for item in outer) == names, 'Wrong bounded macro timeline')
    previous = 0.0
    for item in outer:
        for key in ('StartSeconds', 'EndSeconds', 'DurationSeconds'):
            finite(item[key], key)
        require(item['EndSeconds'] >= item['StartSeconds']
                and math.isclose(item['StartSeconds'], previous, rel_tol=0.0, abs_tol=1e-7)
                and math.isclose(item['EndSeconds'] - item['StartSeconds'], item['DurationSeconds'], rel_tol=0.0, abs_tol=1e-7),
                'Outer workflow intervals do not partition real monotonic walltime')
        previous = item['EndSeconds']
    require(math.isclose(previous, data['workflowWallSeconds'], rel_tol=0.0, abs_tol=1e-7)
            and math.isclose(sum(item['DurationSeconds'] for item in outer), data['workflowWallSeconds'], rel_tol=0.0, abs_tol=1e-7),
            'Outer timeline does not cover cleanup')
    profile = data['phaseProfile']
    require(profile['ObservationAvailable'] is True, 'Unavailable actual phase observation')
    aggregates = {item['Phase']: item for item in profile['Aggregates']}
    require(len(aggregates) == len(profile['Aggregates']), 'Duplicate aggregate phase')
    for item in aggregates.values():
        count(item['Calls'], item['Phase']); count(item['PublicBytesSum'], item['Phase'])
        finite(item['WallSecondsSum'], item['Phase'])
    branch_names = ('KdfRound1', 'KdfRound2', 'Argon2Sha3Round1', 'Argon2SkeinRound1',
                    'Argon2Sha3Round2', 'Argon2SkeinRound2')
    branch = {item['Phase']: item['Calls'] for item in data['observedKdfBranchCalls']}
    require(len(branch) == 6 and len(data['observedKdfBranchCalls']) == 6, 'Wrong public branch-call inventory')
    for name in branch_names:
        count(branch[name], name)
        require(branch[name] == aggregates[name]['Calls'], 'Branch counts disagree with actual phase observation')
        active = name.endswith('1') or suite == 'ParanoiaCascade'
        require((aggregates[name]['Calls'] > 0) == active, 'Actual production KDF round/branch contract differs')
        if active:
            finite(aggregates[name]['WallSecondsSum'], name, positive=True)
    schedule = data['nativeScheduling']
    require(schedule['observationAvailable'] is True, 'Native scheduling observation unavailable')
    for name in ('batches', 'completedCallbacks', 'activeCallbacks', 'minimumGrant', 'maximumGrant', 'peakActiveCallbacks'):
        count(schedule[name], name)
    require(schedule['activeCallbacks'] == 0 and schedule['minimumGrant'] <= schedule['maximumGrant'],
            'Native callbacks unfinished or grant bounds inconsistent')
    for name in ('maximumGrant', 'peakActiveCallbacks'):
        require(schedule[name] <= receipt['InitialCpuCeiling'], 'Native grant exceeds the admitted CPU ceiling')
    for name in ('submissionToCallbackSecondsSum', 'callbackWallSecondsSum', 'callerJoinWallSecondsSum'):
        finite(schedule[name], name)
    if schedule['batches'] == 0:
        require(all(schedule[name] == 0 for name in ('completedCallbacks', 'minimumGrant', 'maximumGrant', 'peakActiveCallbacks')),
                'Empty native scheduling snapshot has nonempty counters')
    else:
        require(schedule['minimumGrant'] >= 1, 'A real native batch has no positive CPU grant')
    native = data['nativeTrustedInputSha256']
    require(set(native) == set(NATIVE_NAMES) and all(HEX64.fullmatch(value) for value in native.values()), 'Wrong native input inventory')
    require(all(value.lower() == expected['harness/Native/' + name]['sha256'] for name, value in native.items()),
            'A reported native input differs from its exact pinned native file')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True, help='Absolute retained successful build, pinned for all twelve cases')
    args = parser.parse_args()
    require(len(TESTS) == 12 and len(set(TESTS)) == 12, 'Invalid closed suite plan')
    out = BASE / ('workflow-1gib-matrix-pinned-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(mode=0o700)
    rows = [{'testId': test_id, 'attempted': False, 'status': 'NOT RUN', 'errors': []} for test_id in TESTS]
    save(out / 'plan.json', {'createdUtc': utc(), 'testIds': TESTS, 'sourceBytesPerCase': BYTES,
        'measuredWorkflowsPerCase': 1, 'warmups': 0, 'requestedBuild': args.build,
        'scope': 'One complete managed Release service/native workflow per suite, production KDF, compression 5, KPAR2 and actual original comparison. No installed AOT GUI approval. Prior Standard attempt is separate evidence, never silently imported.'})
    def checkpoint():
        save(out / 'executions.json', {'plan': 'plan.json', 'executions': rows})
    checkpoint()
    print('matrix_evidence=' + str(out), flush=True)
    try:
        build_arg = pathlib.Path(args.build)
        require(build_arg.is_absolute() and not build_arg.is_symlink(), 'Pinned build must be absolute and direct')
        build = build_arg.resolve(strict=True)
        require(build.parent == BASE and build.is_dir(), 'Unsafe pinned build location')
        result = read_json(build / 'build-result.json')
        require(result['status'] == 'PASS' and result['exitCode'] == 0 and result['sourcesStable'] is True,
                'Pinned build is not a successful source-stable development build')
        expected_sources = read_json(build / 'source-inputs-before.json')
        require(expected_sources == read_json(build / 'source-inputs-after.json') == sources(), 'Source snapshot drift before matrix')
        harness = build / 'artifacts/bin/KeepVaultMac.Tests/release_osx-arm64'
        require(harness.is_dir() and not harness.is_symlink() and harness.resolve(strict=True) == harness,
                'Unsafe pinned harness or ancestor')
        expected_binaries = binaries(harness)
        expected_metadata = build_metadata(build)
        require('harness/Keep Vault.dll' in expected_binaries and 'harness/KeepVaultMac.Tests.dll' in expected_binaries,
                'Pinned product or test assembly is missing')
        expected_driver = sha(DRIVER)
        require('KEEPVAULT_TEST_BUILD_ROOT' in DRIVER.read_text(), 'Driver has not received the explicit build-pin support')
        save(out / 'source-inputs.expected.json', expected_sources)
        save(out / 'binary-inputs.expected.json', expected_binaries)
        save(out / 'build-metadata.expected.json', expected_metadata)
        save(out / 'binding.json', {'build': str(build), 'buildResultSha256': sha(build / 'build-result.json'),
            'sourceInputsSha256': sha(build / 'source-inputs-before.json'), 'binaryInputsSha256': sha(out / 'binary-inputs.expected.json'),
            'buildMetadataSha256': sha(out / 'build-metadata.expected.json'),
            'driverSha256': expected_driver, 'launcherSha256': sha(pathlib.Path(__file__)),
            'productAssemblySha256': expected_binaries['harness/Keep Vault.dll']['sha256'],
            'testAssemblySha256': expected_binaries['harness/KeepVaultMac.Tests.dll']['sha256']})
    except Exception as error:
        for row in rows:
            problem(row, 'matrix-preflight', error)
        checkpoint()
        print('matrix_preflight_failed=' + str(error), flush=True)
        return 1
    common_manifest = None
    binding_block = None
    for row, suite in zip(rows, SUITES.values()):
        case = out / row['testId']
        row['startedUtc'] = utc()
        if binding_block is not None:
            problem(row, 'blocked-after-global-binding-or-cleanup-failure', RuntimeError(binding_block))
            row['completedUtc'] = utc()
            try:
                case.mkdir(mode=0o700)
                save(case / 'case-result.json', row)
                checkpoint()
            except Exception as error:
                problem(row, 'receipt-storage', error)
            print('workflow_case_result=' + json.dumps(row, allow_nan=False), flush=True)
            continue
        try:
            case.mkdir(mode=0o700)
            row['hostBefore'] = host(row, 'host-before')
            try:
                current_sources, current_binaries = sources(), binaries(harness)
                current_metadata = build_metadata(build)
                binding_ok = (current_sources == expected_sources and current_binaries == expected_binaries
                              and current_metadata == expected_metadata and sha(DRIVER) == expected_driver)
            except Exception as error:
                binding_block = 'Pinned input binding failed before ' + row['testId'] + ': ' + str(error)
                raise
            if not binding_ok:
                binding_block = 'Source/binary/build-receipt/driver drift before ' + row['testId']
            save(case / 'source-inputs-before.json', current_sources)
            save(case / 'binary-inputs-before.json', current_binaries)
            save(case / 'build-metadata-before.json', current_metadata)
            require(binding_ok, binding_block)
            env = os.environ.copy()
            env['KEEPVAULT_TEST_BUILD_ROOT'] = str(build)
            command = ['/usr/bin/python3', str(DRIVER), 'test', '--performance', '--only', row['testId'], '--parallel', '1']
            row['command'] = command
            row['attempted'] = True
            checkpoint()  # A crash after launch still leaves an explicit incomplete case.
            fixtures_before = owned_fixture_names(build)
            with subprocess.Popen(command, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True) as process:
                row['ownedProcessGroupId'] = process.pid
                checkpoint()
                launcher_output, _ = process.communicate()
                launcher_exit = process.returncode
            row['launcherExit'] = launcher_exit
            (case / 'launcher-output.txt').write_text(launcher_output)
            candidates = [line.split('evidence=', 1)[1] for line in launcher_output.splitlines()
                          if line.startswith('test_exit=') and 'evidence=' in line]
            if len(candidates) == 1:
                row['reportedEvidence'] = candidates[0]
            try:
                row['remainingOwnedProcesses'] = remaining_group_processes(row['ownedProcessGroupId'])
                row['newOwnedFixturesAfterCase'] = sorted(set(owned_fixture_names(build)) - set(fixtures_before))
                require(not row['remainingOwnedProcesses'] and not row['newOwnedFixturesAfterCase'],
                        'Unresolved owned workflow process/fixture cleanup')
            except Exception as error:
                binding_block = 'Owned cleanup cannot be confirmed after ' + row['testId'] + ': ' + str(error)
                problem(row, 'owned-cleanup', error)
            require(len(candidates) == 1, 'Missing or ambiguous actual driver receipt')
            run = pathlib.Path(candidates[0])
            require(run.is_absolute() and not run.is_symlink() and run.is_dir() and run.resolve().parent == build,
                    'Driver evidence belongs to another build')
            row['evidence'] = str(run)
            execution = read_json(run / 'execution.json')
            expected_command = [str(SDK), str(harness / 'KeepVaultMac.Tests.dll'), '--performance',
                '--only', row['testId'], '--parallel', '1']
            require(execution['command'] == expected_command
                    and execution['sourceInputsSha256'] == expected_metadata['source-inputs-before.json'],
                    'Execution does not bind the pinned test assembly/source snapshot')
            require(execution['logSha256'] == sha(run / 'run.log'), 'Run log hash differs from execution receipt')
            require(set(execution['files']) == {'test-results.json', 'test-timings.json'}, 'Incomplete coordinator receipt inventory')
            for name, digest in execution['files'].items():
                require(name in ('test-results.json', 'test-timings.json') and sha(run / name) == digest,
                        'Coordinator output hash mismatch')
            row['executionSha256'] = sha(run / 'execution.json')
            coordinator = read_json(run / 'test-results.json')
            selected = coordinator['tests']
            require(len(selected) == 1 and selected[0]['id'] == row['testId'], 'Wrong actual selected test result')
            row['testResult'] = selected[0]
            row['testResultsSha256'] = sha(run / 'test-results.json')
            row['status'] = 'PASS' if selected[0]['status'] == 'PASS' else ('NOT RUN' if selected[0]['status'] == 'BLOCKED' else 'FAIL')
            require(launcher_exit == execution['exitCode'], 'Driver failed after the coordinator receipt; result is not authoritative')
            if row['status'] == 'PASS':
                require(launcher_exit == 0, 'Successful test receipt has a failed launcher')
                markers = [line.split('=', 1)[1] for line in (run / 'run.log').read_text().splitlines()
                           if line.startswith('REV12_WORKFLOW_PROFILE_ARTIFACT=')]
                require(len(markers) == 1, 'Missing or ambiguous actual workflow artifact')
                artifact = pathlib.Path(markers[0])
                require(artifact.is_absolute() and not artifact.is_symlink()
                        and artifact.resolve().parent == REPO / 'work/v13-evidence'
                        and artifact.name.startswith(row['testId'] + '-') and artifact.suffix == '.json',
                        'Unexpected workflow artifact location or name')
                raw = artifact.read_bytes()
                (case / 'workflow-profile.json').write_bytes(raw)
                row['artifact'] = {'path': str(artifact), 'sha256': hashlib.sha256(raw).hexdigest()}
                data = parse_json(raw)
                validate_artifact(data, row['testId'], suite, expected_binaries)
                if common_manifest is None:
                    common_manifest = data['receipt']['InputManifestSha256']
                require(data['receipt']['InputManifestSha256'] == common_manifest, 'The deterministic public corpus differs across suites')
                row['summary'] = {name: data[name] for name in ('suite', 'workflowWallSeconds',
                    'sourceMiBPerSecondCompleteWorkflow', 'sourceMiBPerSecondArchiveAndEncrypt',
                    'phaseWallSeconds', 'receipt', 'managedProcessCpuSecondsThroughOriginalComparison',
                    'processAndObservedZpaqChildCpuSecondsThroughOriginalComparison', 'observedKdfBranchCalls')}
        except Exception as error:
            row['status'] = 'FAIL' if row['attempted'] else 'NOT RUN'
            problem(row, 'case', error)
        finally:
            try:
                row['hostAfter'] = host(row, 'host-after')
                try:
                    after_sources, after_binaries = sources(), binaries(harness)
                    after_metadata = build_metadata(build)
                    binding_ok = (after_sources == expected_sources and after_binaries == expected_binaries
                                  and after_metadata == expected_metadata and sha(DRIVER) == expected_driver)
                except Exception as error:
                    binding_block = 'Pinned input binding failed after ' + row['testId'] + ': ' + str(error)
                    raise
                if not binding_ok:
                    binding_block = 'Source/binary/build-receipt/driver drift after ' + row['testId']
                save(case / 'source-inputs-after.json', after_sources)
                save(case / 'binary-inputs-after.json', after_binaries)
                save(case / 'build-metadata-after.json', after_metadata)
                require(binding_ok, binding_block)
                row['inputBindingVerified'] = True
            except Exception as error:
                problem(row, 'case-final-binding', error)
            row['completedUtc'] = utc()
            if row['errors']:
                row['status'] = 'FAIL' if row['attempted'] else 'NOT RUN'
            try:
                save(case / 'case-result.json', row)
                checkpoint()
            except Exception as error:
                problem(row, 'receipt-storage', error)
                row['status'] = 'FAIL' if row['attempted'] else 'NOT RUN'
            # Terminal stdout survives a receipt-volume failure; later cases are
            # still attempted. No fixture cleanup or prior-evidence edit here.
            print('workflow_case_result=' + json.dumps(row, allow_nan=False), flush=True)
    checkpoint()
    print('matrix_evidence=' + str(out), flush=True)
    return 0 if len(rows) == 12 and all(row['status'] == 'PASS' for row in rows) else 1

if __name__ == '__main__':
    sys.exit(main())
