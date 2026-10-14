#!/usr/bin/python3
"""PREPARED / NOT RUN: 24 existing workflows with a future fresh L3 build.

The operator must provide a READY binding after the new build exists. The
unmodified preceding L5 matrix is a terminal predecessor, never an L3 input.
No test, fixture, product configuration, KDF or cipher is implemented here.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
import pathlib
import re
import subprocess

BASE = pathlib.Path(__file__).resolve().parent
REPO = pathlib.Path('/Users/michael/Developer/GPT-Codex/Kalyna')
OLD_BASE = REPO / 'work/v13-evidence/rev12-development-20261003'
ANCHOR = OLD_BASE / 'workflow-1gib-matrix-pinned-20261003T172229Z-c571f026'
OLD_BUILD = OLD_BASE / 'build-20261003T171619Z'
HELPER = BASE / 'workflow24-helpers.py'
CAMPAIGN = BASE / 'run-campaign.py'
SCRIPT_NAMES = {'run-development.py', 'run-campaign.py', 'workflow24-helpers.py',
                'run-workflow24-level3-pinned.py'}
HEX64 = re.compile(r'^[0-9a-f]{64}$')
HEX40 = re.compile(r'^[0-9a-f]{40}$')
SUITES = {'standard': 'StandardCascade', 'paranoia': 'ParanoiaCascade',
          'camellia': 'Camellia256', 'serpent': 'Serpent256'}
PLAN = [dict(testId=f'performance.rev12-workflow-{size}-{suite}-{mode}', suite=kind,
             sourceBytes=4096 if size == '4kib' else 268435456, requestedWorkers=workers)
        for suite, kind in SUITES.items() for size in ('4kib', '256mib')
        for mode, workers in (('auto', None), ('manual1', 1), ('manual4', 4))]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def direct_path(value, directory=False):
    require(type(value) is str, 'An absolute direct input path is required')
    path = pathlib.Path(value)
    require(path.is_absolute() and not path.is_symlink()
            and path.resolve(strict=True) == path
            and (path.is_dir() if directory else path.is_file()),
            'Not a direct pinned input: ' + value)
    return path


def direct_sha(path):
    direct_path(str(path))
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def strict_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate binding field: ' + key)
            result[key] = value
        return result

    def invalid(token):
        raise ValueError('Non-finite binding number: ' + token)

    def finite_float(token):
        value = float(token)
        require(math.isfinite(value), 'Non-finite binding exponent: ' + token)
        return value

    return json.loads(direct_path(str(path)).read_bytes(), object_pairs_hook=unique,
                      parse_constant=invalid, parse_float=finite_float)


def load_ready_binding(path):
    path = direct_path(str(path))
    require(path.parent.is_relative_to(BASE), 'Binding file must belong to the new L3 preparation root')
    config = strict_json(path)
    require(type(config['schemaVersion']) is int and config['schemaVersion'] == 1
            and config['status'] == 'READY' and type(config['compressionLevel']) is int
            and config['compressionLevel'] == 3,
            'Only an explicitly completed READY level-3 binding is executable; the template is NOT RUN')
    build = direct_path(config['build'], directory=True)
    require(build.parent == BASE and build.name.startswith('build-') and build != OLD_BUILD,
            'A fresh isolated build in the new L3 root is required')
    require(type(config['gitHead']) is str and HEX40.fullmatch(config['gitHead']), 'Invalid fresh HEAD pin')
    require(config['predecessorMatrix'] == str(ANCHOR), 'Wrong original L5 predecessor')
    for name in ('sourceInputsSha256', 'productAssemblySha256', 'testAssemblySha256',
                 'predecessorExecutionsSha256', 'predecessorPlanSha256'):
        require(type(config[name]) is str and HEX64.fullmatch(config[name]), 'Missing fresh digest: ' + name)
    require(set(config['scriptSha256']) == SCRIPT_NAMES, 'Incomplete administration script pins')
    for name, digest in config['scriptSha256'].items():
        require(type(digest) is str and HEX64.fullmatch(digest)
                and direct_sha(BASE / name) == digest, 'Administration input drift: ' + name)
    maps = {}
    for name in ('binaryInputsExpected', 'buildMetadataExpected'):
        record = config[name]
        require(set(record) == {'path', 'sha256'} and type(record['sha256']) is str
                and HEX64.fullmatch(record['sha256']), 'Missing fresh expected-map pin: ' + name)
        target = direct_path(record['path'])
        require(target.parent.is_relative_to(BASE) and direct_sha(target) == record['sha256'],
                'Expected map must be newly bound inside the L3 root: ' + name)
        maps[name] = target
    return path, direct_sha(path), config, build, maps


def pinned_inputs(path, digest, config, maps):
    require(direct_sha(path) == digest, 'READY binding changed')
    for name, expected in config['scriptSha256'].items():
        require(direct_sha(BASE / name) == expected, 'Administration input drift: ' + name)
    for name, target in maps.items():
        require(direct_sha(target) == config[name]['sha256'], 'Expected inventory changed: ' + name)
    require(direct_sha(ANCHOR / 'executions.json') == config['predecessorExecutionsSha256']
            and direct_sha(ANCHOR / 'plan.json') == config['predecessorPlanSha256'],
            'The original terminal L5 predecessor changed')


def artifact_contract(p, data, plan, expected):
    p.require(data['testId'] == plan['testId'] and data['suite'] == plan['suite'], 'Wrong actual workflow identity')
    for name, value in (('schemaVersion', 1), ('measuredWorkflows', 1), ('repetitions', 1),
                        ('warmups', 0), ('compressionLevel', 3)):
        p.count(data[name], name)
        p.require(data[name] == value, 'Wrong actual workflow count/level: ' + name)
    p.require(data['requestedCpuMode'] == ('Auto' if plan['requestedWorkers'] is None else 'Manual')
              and data['requestedWorkers'] == plan['requestedWorkers']
              and data['leaseCleanupVerified'] is True, 'Wrong requested CPU mode/cleanup')
    if plan['requestedWorkers'] is not None:
        p.count(data['requestedWorkers'], 'requestedWorkers', positive=True)
    p.require(data['processArchitecture'].lower() == data['osArchitecture'].lower() == 'arm64', 'Wrong actual architecture')
    p.require(data['assemblySha256'].lower() == expected['harness/Keep Vault.dll']['sha256'], 'Wrong built product assembly')
    receipt = data['receipt']
    for name, value in (('InputBytes', plan['sourceBytes']), ('InputFiles', 3), ('InputDirectories', 5)):
        p.count(receipt[name], name)
        p.require(receipt[name] == value, 'Wrong fixture bytes/topology: ' + name)
    pattern = data['fixturePattern']
    p.require(type(pattern) is str and
              (('Exact 4 KiB source size' in pattern and 'fixed repeating bytes' in pattern)
               if plan['sourceBytes'] == 4096 else
               ('Exact 256 MiB source size' in pattern and '75%' in pattern and '25%' in pattern)),
              'The existing control fixture pattern changed')
    for name in ('CompressedPayloadBytesDuringCreation', 'ContainerBytes', 'RecoveryBytes', 'InitialCpuCeiling'):
        p.count(receipt[name], name, positive=True)
    if plan['requestedWorkers'] is not None:
        p.require(receipt['InitialCpuCeiling'] <= plan['requestedWorkers'], 'Manual admitted CPU ceiling exceeds request')
    for name in ('InputManifestSha256', 'ContainerSha256'):
        p.require(p.HEX64.fullmatch(receipt[name]) is not None, 'Invalid public hash: ' + name)
    for name in ('setupSeconds', 'preparationSeconds', 'managedProcessCpuSecondsThroughOriginalComparison'):
        p.finite(data[name], name)
    if data['processAndObservedZpaqChildCpuSecondsThroughOriginalComparison'] is not None:
        p.finite(data['processAndObservedZpaqChildCpuSecondsThroughOriginalComparison'], 'sampled parent/child CPU')
    p.finite(data['workflowWallSeconds'], 'complete workflow walltime', positive=True)
    phases = ('originalCreationSnapshot', 'archiveAndEncrypt', 'supplementalContainerHash',
              'recoveryCreate', 'supplementalRecoveryHealthyVerification',
              'decryptAndExtractForOriginalComparison',
              'originalComparisonAndIndependentHashTopologyCheck', 'fixtureCleanup')
    p.require(set(data['phaseWallSeconds']) == set(phases), 'Wrong outer service phase inventory')
    for name, wall in data['phaseWallSeconds'].items():
        p.finite(wall, name, positive=name != 'fixtureCleanup')
    for name, wall in (('sourceMiBPerSecondCompleteWorkflow', data['workflowWallSeconds']),
                       ('sourceMiBPerSecondArchiveAndEncrypt', data['phaseWallSeconds']['archiveAndEncrypt'])):
        p.finite(data[name], name, positive=True)
        p.require(math.isclose(data[name], plan['sourceBytes'] / (1 << 20) / wall, rel_tol=1e-8),
                  'Wrong source-byte throughput denominator')
    macro_names = ('memoryAdmissionAndOriginalCreationSnapshot', 'archiveAndEncrypt',
                   'supplementalContainerHash', 'recoveryCreate', 'supplementalRecoveryHealthyVerification',
                   'decryptAndExtractForOriginalComparison',
                   'originalComparisonAndIndependentHashTopologyCheck', 'ownedResourcesAndFixtureCleanup')
    outer = data['outerWorkflowTimeline']
    p.require(len(outer) == 8 and tuple(item['Phase'] for item in outer) == macro_names, 'Wrong bounded macro timeline')
    previous = 0.0
    for item in outer:
        for name in ('StartSeconds', 'EndSeconds', 'DurationSeconds'):
            p.finite(item[name], name)
        p.require(item['EndSeconds'] >= item['StartSeconds']
                  and math.isclose(item['StartSeconds'], previous, rel_tol=0.0, abs_tol=1e-7)
                  and math.isclose(item['EndSeconds'] - item['StartSeconds'], item['DurationSeconds'],
                                   rel_tol=0.0, abs_tol=1e-7), 'Outer intervals do not partition real walltime')
        previous = item['EndSeconds']
    p.require(math.isclose(previous, data['workflowWallSeconds'], rel_tol=0.0, abs_tol=1e-7)
              and math.isclose(sum(item['DurationSeconds'] for item in outer), data['workflowWallSeconds'],
                               rel_tol=0.0, abs_tol=1e-7), 'Outer timeline does not cover owner/fixture cleanup')
    native = data['nativeTrustedInputSha256']
    p.require(set(native) == set(p.NATIVE_NAMES)
              and all(p.HEX64.fullmatch(value) for value in native.values()), 'Wrong native inventory')
    p.require(all(value.lower() == expected['harness/Native/' + name]['sha256']
                  for name, value in native.items()), 'Reported native bytes differ from fixed build')
    profile = data['phaseProfile']
    aggregates = {item['Phase']: item for item in profile['Aggregates']}
    p.require(profile['ObservationAvailable'] is True and len(aggregates) == len(profile['Aggregates']),
              'Invalid actual phase observation')
    for item in aggregates.values():
        p.count(item['Calls'], item['Phase'])
        p.count(item['PublicBytesSum'], item['Phase'])
        p.finite(item['WallSecondsSum'], item['Phase'])
    branches = {item['Phase']: item['Calls'] for item in data['observedKdfBranchCalls']}
    branch_names = ('KdfRound1', 'KdfRound2', 'Argon2Sha3Round1', 'Argon2SkeinRound1',
                    'Argon2Sha3Round2', 'Argon2SkeinRound2')
    p.require(set(branches) == set(branch_names) and len(data['observedKdfBranchCalls']) == 6,
              'Wrong real KDF branch inventory')
    for name in branch_names:
        p.count(branches[name], name)
        p.require(branches[name] == aggregates[name]['Calls'], 'KDF branch counters disagree')
        active = name.endswith('1') or plan['suite'] == 'ParanoiaCascade'
        p.require((branches[name] > 0) == active, 'Wrong actual productive KDF branch')
        p.finite(aggregates[name]['WallSecondsSum'], name, positive=active)
    schedule = data['nativeScheduling']
    p.require(schedule['observationAvailable'] is True, 'Missing actual native scheduling observation')
    for name in ('batches', 'completedCallbacks', 'activeCallbacks', 'minimumGrant', 'maximumGrant', 'peakActiveCallbacks'):
        p.count(schedule[name], name)
    p.require(schedule['activeCallbacks'] == 0
              and schedule['minimumGrant'] <= schedule['maximumGrant'] <= receipt['InitialCpuCeiling']
              and schedule['peakActiveCallbacks'] <= receipt['InitialCpuCeiling'],
              'Native callbacks/grants violate admitted ceiling')
    for name in ('submissionToCallbackSecondsSum', 'callbackWallSecondsSum', 'callerJoinWallSecondsSum'):
        p.finite(schedule[name], name)
    if schedule['batches'] == 0:
        p.require(all(schedule[name] == 0 for name in
                      ('completedCallbacks', 'minimumGrant', 'maximumGrant', 'peakActiveCallbacks')),
                  'Empty native snapshot has nonempty counters')
    else:
        p.require(schedule['minimumGrant'] >= 1, 'Real native batch has no positive grant')
    # Unchanged product TestCases enforce MACs, KPAR2, the actual original
    # comparison, independent hash/topology checks, and owned cleanup.


def relevant_processes(p):
    command = ['/bin/ps', '-axo', 'pid=,ppid=,pgid=,stat=,command=']
    observed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.require(observed.returncode == 0, 'Cannot observe concurrent test/SDK/native processes')
    names = (str(p.SDK), 'KeepVaultMac.Tests.dll', str(p.ROOT_ZPAQ), '/Native/zpaq',
             'run-development.py', 'run-campaign.py', 'run-workflow-matrix.py',
             'run-workflow-1gib-matrix', 'run-workflow24', 'Build-KeepVault-macOS.sh',
             'Stage-TestNatives-macOS.sh')
    processes = {}
    for line in observed.stdout.splitlines():
        parts = line.split(None, 4)
        p.require(len(parts) == 5, 'Unexpected process observation row')
        pid, ppid, pgid = (int(value) for value in parts[:3])
        processes[pid] = {'pid': pid, 'ppid': ppid, 'pgid': pgid,
                          'state': parts[3], 'command': parts[4]}
    # A shell/caffeinate ancestor can legitimately contain this exact wrapper
    # command. It is administration of this invocation, not a second test.
    # Do not exempt SDK/ZPAQ ancestors or any independent process.
    own_administration = {os.getpid()}
    seen = set()
    parent = os.getppid()
    while parent in processes and parent not in seen:
        seen.add(parent)
        record = processes[parent]
        executable_name = pathlib.Path(record['command'].split(None, 1)[0]).name
        if str(BASE / 'run-workflow24-level3-pinned.py') in record['command'] \
                and executable_name in ('zsh', 'bash', 'sh', 'python3', 'caffeinate'):
            own_administration.add(parent)
        parent = record['ppid']
    found = []
    executable = re.compile(r'(^|\s)(?:\S*/)?(?:dotnet|zpaq)(?:\s|$)')
    for pid, record in processes.items():
        if pid in own_administration or record['state'].startswith('Z'):
            continue
        if any(name in record['command'] for name in names) or executable.search(record['command']):
            found.append(record)
    return {'observedUtc': p.utc(), 'command': command, 'exitCode': observed.returncode,
            'ownAdministrationPids': sorted(own_administration),
            'relevantLiveProcesses': found}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binding-json', type=pathlib.Path, required=True,
                        help='Fresh READY binding created only after the level-3 build exists')
    args = parser.parse_args()
    binding_path, binding_sha, config, build, maps = load_ready_binding(args.binding_json)
    # Both source reviewed helper and all other scripts were hash verified
    # before importing this definition-only module. This preparation never ran.
    spec = importlib.util.spec_from_file_location('bound_level3_workflow_helpers', HELPER)
    p = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(p)
    p.require(len(PLAN) == 24 and len({item['testId'] for item in PLAN}) == 24, 'Wrong closed control matrix')
    out = BASE / ('workflow24-level3-pinned-' + p.datetime.datetime.now(p.datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
                  + '-' + p.uuid.uuid4().hex[:8])
    out.mkdir(mode=0o700)
    rows = [dict(**plan, attempted=False, status='NOT RUN', errors=[]) for plan in PLAN]

    def checkpoint():
        p.save(out / 'executions.json', {
            'scope': '24 actual L3 managed development controls; installed/AOT/release approval is separate',
            'compressionLevel': 3, 'executions': rows})

    def store_row(case, row):
        errors = []
        try:
            case.mkdir(mode=0o700, exist_ok=True)
            p.save(case / 'case-result.json', row)
        except Exception as error:
            p.problem(row, 'case-receipt-storage', error)
            errors.append(error)
        try:
            checkpoint()
        except Exception as error:
            p.problem(row, 'matrix-receipt-storage', error)
            errors.append(error)
        if errors:
            row['status'] = 'FAIL' if row['attempted'] else 'NOT RUN'
            # Best effort only; if storage itself is unavailable, the printed
            # outcome still preserves the actual error and no PASS is issued.
            try:
                p.save(case / 'case-result.json', row)
                checkpoint()
            except Exception as error:
                p.problem(row, 'receipt-storage-retry', error)
        print('workflow_case_result=' + p.json.dumps(row, allow_nan=False), flush=True)
        return bool(errors)

    p.save(out / 'plan.json', {
        'build': str(build), 'predecessorMatrix': str(ANCHOR), 'cases': PLAN,
        'compressionLevel': 3, 'measuredWorkflowsPerCase': 1, 'warmups': 0,
        'bindingPath': str(binding_path), 'bindingSha256': binding_sha,
        'scope': 'One new execution for each existing ID; no imported or retried PASS and no median'})
    checkpoint()
    print('matrix_evidence=' + str(out), flush=True)
    try:
        pinned_inputs(binding_path, binding_sha, config, maps)
        predecessor = p.read_json(ANCHOR / 'executions.json')['executions']
        predecessor_plan = p.read_json(ANCHOR / 'plan.json')
        p.require(predecessor_plan['requestedBuild'] == str(OLD_BUILD)
                  and predecessor_plan['sourceBytesPerCase'] == 1073741824
                  and predecessor_plan['measuredWorkflowsPerCase'] == 1
                  and predecessor_plan['warmups'] == 0
                  and len(predecessor) == 12
                  and {row['testId'] for row in predecessor} == set(p.TESTS)
                  and predecessor_plan['testIds'] == p.TESTS,
                  'Wrong original closed L5 predecessor')
        for row in predecessor:
            p.require(row['status'] in ('PASS', 'FAIL', 'NOT RUN') and row.get('completedUtc')
                      and type(row['attempted']) is bool
                      and p.read_json(ANCHOR / row['testId'] / 'case-result.json') == row,
                      'Predecessor checkpoint is not an independently stored terminal case')
            if row['attempted']:
                p.count(row['ownedProcessGroupId'], 'predecessor owned group', positive=True)
                p.require(not p.remaining_group_processes(row['ownedProcessGroupId']),
                          'Predecessor owned process group is still live')
        p.require(not p.owned_fixture_names(OLD_BUILD), 'Original L5 predecessor has unresolved owned fixtures')
        p.save(out / 'predecessor-terminal-status.json', {
            'matrix': str(ANCHOR), 'executionsSha256': config['predecessorExecutionsSha256'],
            'planSha256': config['predecessorPlanSha256'],
            'observedUtc': p.utc(), 'statuses': {row['testId']: row['status'] for row in predecessor},
            'scope': 'Terminal predecessor and no live owned groups/fixtures; predecessor FAILs remain FAILs'})
        result = p.read_json(build / 'build-result.json')
        p.require(result['status'] == 'PASS' and result['exitCode'] == 0
                  and result['sourcesStable'] is True, 'No successful new level-3 development build')
        p.require(direct_sha(build / 'source-inputs-before.json') == config['sourceInputsSha256'],
                  'Wrong new source inventory digest')
        expected_sources = p.read_json(build / 'source-inputs-before.json')
        expected_binaries = p.read_json(maps['binaryInputsExpected'])
        expected_metadata = p.read_json(maps['buildMetadataExpected'])
        harness = direct_path(str(build / 'artifacts/bin/KeepVaultMac.Tests/release_osx-arm64'), directory=True)
        p.require(expected_sources == p.read_json(build / 'source-inputs-after.json'), 'New build source receipts disagree')
        p.require(expected_metadata['source-inputs-before.json'] == config['sourceInputsSha256'], 'Source/map pins disagree')
        p.require(expected_binaries['harness/Keep Vault.dll']['sha256'] == config['productAssemblySha256']
                  and expected_binaries['harness/KeepVaultMac.Tests.dll']['sha256'] == config['testAssemblySha256'],
                  'Fresh product/test assembly pins disagree with the binary map')
        p.require(not os.environ.get('KEEPVAULT_PERF_BASELINE'), 'Unbound inherited performance baseline is not allowed')
        p.save(out / 'binding.json', {
            'bindingPath': str(binding_path), 'bindingSha256': binding_sha, 'readyBinding': config,
            'scope': 'Fresh L3 source/resources, full managed/native/runtime inputs and public ZPAQ anchor; no release approval'})
        for name, path in (('source-inputs.expected.json', build / 'source-inputs-before.json'),
                           ('binary-inputs.expected.json', maps['binaryInputsExpected']),
                           ('build-metadata.expected.json', maps['buildMetadataExpected'])):
            (out / name).write_bytes(path.read_bytes())
    except Exception as error:
        for row in rows:
            row['startedUtc'] = row['completedUtc'] = p.utc()
            p.problem(row, 'matrix-preflight', error)
            store_row(out / row['testId'], row)
        return 1

    blocked = None
    manifests = {}

    def binding(case, stage):
        pinned_inputs(binding_path, binding_sha, config, maps)
        head = subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
        p.require(head == config['gitHead'], 'Git HEAD changed from the fresh L3 binding')
        current = {'sources': p.sources(), 'binaries': p.binaries(harness), 'metadata': p.build_metadata(build)}
        for name, value in current.items():
            p.save(case / (name + '-' + stage + '.json'), value)
        p.require(current['sources'] == expected_sources and current['binaries'] == expected_binaries
                  and current['metadata'] == expected_metadata, 'Fresh source/resource/binary/build binding drift')

    for row in rows:
        case = out / row['testId']
        row['startedUtc'] = p.utc()
        if blocked is not None:
            p.problem(row, 'blocked-after-binding-or-cleanup-failure', ValueError(blocked))
            row['completedUtc'] = p.utc()
            store_row(case, row)
            continue
        fixtures = None
        try:
            case.mkdir(mode=0o700)
            try:
                binding(case, 'before')
                observation = relevant_processes(p)
                p.save(case / 'concurrent-processes-before.json', observation)
                p.require(not observation['relevantLiveProcesses'], 'Another test/SDK/ZPAQ or workflow administration process is live')
                p.require(not p.owned_fixture_names(OLD_BUILD), 'Original predecessor fixtures reappeared')
                fixtures = p.owned_fixture_names(build)
                p.require(not fixtures, 'Preexisting new-build workflow fixtures require ownership review')
            except Exception as error:
                blocked = str(error)
                raise
            row['hostBefore'] = p.host(row, 'host-before')
            env = os.environ.copy()
            env['KEEPVAULT_TEST_BUILD_ROOT'] = str(build)
            command = ['/usr/bin/python3', str(CAMPAIGN), '--performance', row['testId']]
            row['command'] = command
            checkpoint()  # A failed pre-launch checkpoint cannot start a test.
            process = subprocess.Popen(command, env=env, text=True, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            row['attempted'] = True
            row['ownedProcessGroupId'] = process.pid
            try:
                checkpoint()
            except Exception as error:
                blocked = 'Started child checkpoint storage failed: ' + str(error)
                p.problem(row, 'started-child-checkpoint', error)
            # Always drain a started child's stdout even if its checkpoint
            # write failed. Never terminate, suspend or silently retry a case.
            output, _ = process.communicate()
            row['campaignExit'] = process.returncode
            (case / 'campaign-output.txt').write_text(output)
            row['campaignOutputSha256'] = p.sha(case / 'campaign-output.txt')
            markers = [line.split('=', 1)[1] for line in output.splitlines() if line.startswith('campaign_evidence=')]
            p.require(len(markers) == 1, 'Missing or ambiguous actual campaign receipt')
            campaign = direct_path(markers[0])
            p.require(campaign.parent == BASE, 'Wrong actual campaign receipt location')
            campaign_data = p.read_json(campaign)
            selected = campaign_data['executions']
            p.require(campaign_data['performance'] is True and len(selected) == 1
                      and selected[0]['testId'] == row['testId'], 'Wrong actual campaign selection')
            launch = selected[0]
            row['campaignEvidence'] = str(campaign)
            row['campaignReceiptSha256'] = p.sha(campaign)
            (case / 'campaign-receipt.json').write_bytes(campaign.read_bytes())
            driver_markers = [re.fullmatch(r'test_exit=(-?\d+) evidence=(.+)', line)
                              for line in launch['launcherOutput'].splitlines() if line.startswith('test_exit=')]
            p.require(len(driver_markers) == 1 and driver_markers[0] is not None,
                      'Missing or ambiguous actual driver exit/evidence marker')
            marker = driver_markers[0]
            p.require(marker.group(2) == launch['evidence'], 'Campaign and driver evidence disagree')
            outer_driver_markers = [line for line in output.splitlines() if line.startswith('test_exit=')]
            p.require(outer_driver_markers == [marker.group(0)], 'Campaign stdout and original driver marker disagree')
            run = direct_path(launch['evidence'], directory=True)
            p.require(run.parent == build and run.name.startswith('run-'), 'Wrong fresh-build actual run location')
            row['evidence'] = str(run)
            originals = case / 'original-run'
            originals.mkdir(mode=0o700)
            copies = {}
            for name in ('execution.json', 'test-results.json', 'test-timings.json', 'run.log'):
                source = direct_path(str(run / name))
                raw = source.read_bytes()
                (originals / name).write_bytes(raw)
                copies[name] = hashlib.sha256(raw).hexdigest()
            row['originalRunCopies'] = copies
            execution = p.read_json(run / 'execution.json')
            row['executionSha256'] = p.sha(run / 'execution.json')
            row['executionExit'] = execution['exitCode']
            row['driverExit'] = launch['launcherExit']
            p.require(execution['command'] == [str(p.SDK), str(harness / 'KeepVaultMac.Tests.dll'),
                                              '--performance', '--only', row['testId'], '--parallel', '1']
                      and execution['sourceInputsSha256'] == expected_metadata['source-inputs-before.json'],
                      'Wrong actual worker command/source binding')
            p.require(execution['logSha256'] == copies['run.log']
                      and set(execution['files']) == {'test-results.json', 'test-timings.json'},
                      'Incomplete actual coordinator receipt')
            for name, digest in execution['files'].items():
                p.require(copies[name] == digest, 'Actual coordinator output hash mismatch: ' + name)
            actual = p.read_json(run / 'test-results.json')['tests']
            p.require(len(actual) == 1 and actual[0]['id'] == row['testId'], 'Wrong actual coordinator case')
            row['testResult'] = actual[0]
            profiles = [line.split('=', 1)[1] for line in (originals / 'run.log').read_text().splitlines()
                        if line.startswith('REV12_WORKFLOW_PROFILE_ARTIFACT=')]
            p.require(len(profiles) == 1, 'Missing or ambiguous actual workflow profile')
            profile = direct_path(profiles[0])
            p.require(profile.parent == REPO / 'work/v13-evidence'
                      and profile.name.startswith(row['testId'] + '-') and profile.suffix == '.json',
                      'Wrong actual workflow profile location')
            raw = profile.read_bytes()
            (case / 'workflow-profile.json').write_bytes(raw)
            row['artifact'] = {'path': str(profile), 'sha256': hashlib.sha256(raw).hexdigest()}
            data = p.parse_json(raw)
            artifact_contract(p, data, row, expected_binaries)
            manifest = data['receipt']['InputManifestSha256']
            prior = manifests.setdefault(row['sourceBytes'], manifest)
            p.require(prior == manifest, 'Public fixture differs within the same source-byte size')
            p.count(execution['exitCode'], 'actual execution exit')
            p.count(launch['launcherExit'], 'actual driver exit')
            p.require(int(marker.group(1)) == execution['exitCode'], 'Driver stdout and actual execution exit disagree')
            p.require(process.returncode == 0 and launch['launcherExit'] == 0 and execution['exitCode'] == 0
                      and launch['status'] == 'PASS' and actual[0]['status'] == 'PASS',
                      'Actual workflow or administration did not pass; preserve failure')
            row['status'] = 'PASS'
        except Exception as error:
            row['status'] = 'FAIL' if row['attempted'] else 'NOT RUN'
            p.problem(row, 'case', error)
        finally:
            if 'ownedProcessGroupId' in row:
                try:
                    row['remainingOwnedProcesses'] = p.remaining_group_processes(row['ownedProcessGroupId'])
                    row['newOwnedFixturesAfterCase'] = sorted(set(p.owned_fixture_names(build)) - set(fixtures or []))
                    p.require(not row['remainingOwnedProcesses'] and not row['newOwnedFixturesAfterCase'],
                              'Owned process/fixture cleanup remains unresolved')
                except Exception as error:
                    blocked = str(error)
                    p.problem(row, 'owned-cleanup', error)
            row['hostAfter'] = p.host(row, 'host-after')
            try:
                binding(case, 'after')
                row['inputBindingVerified'] = True
            except Exception as error:
                blocked = str(error)
                p.problem(row, 'case-final-binding', error)
            row['completedUtc'] = p.utc()
            if row['errors']:
                row['status'] = 'FAIL' if row['attempted'] else 'NOT RUN'
            if store_row(case, row):
                blocked = 'Actual receipt storage could not be confirmed'
    return 0 if all(row['status'] == 'PASS' for row in rows) else 1


if __name__ == '__main__':
    raise SystemExit(main())
