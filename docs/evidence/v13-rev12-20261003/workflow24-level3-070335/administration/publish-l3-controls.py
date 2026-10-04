#!/usr/bin/python3
"""PREPARED / NOT RUN: strict publication of the terminal 24 L3 controls.

This publishes existing evidence only. It never builds, reruns tests, replaces
FAILs or edits benchmark data. Run only after the original administrator ends.
"""
import datetime
import hashlib
import json
import math
import pathlib
import re
import subprocess
import types

BASE = pathlib.Path(__file__).resolve().parent
REPO = pathlib.Path('/Users/michael/Developer/GPT-Codex/Kalyna')
MATRIX = BASE / 'workflow24-level3-pinned-20261004T070752Z-c1f0551c'
HISTORY = BASE / 'workflow24-level3-pinned-20261004T070649Z-c936f61c'
BUILD = BASE / 'build-20261004T070335Z'
READY = BASE / 'binding.ready-20261004T0707.json'
READY_SHA = 'b39aacda763897675469f261ba792a44ec45f27344d6e7b5741a4389ad03ded2'
HISTORY_SHA = 'a55f9811760165a186adcb2ca4b2382234d43d2191dd65a463953db2e9fb5e46'
TARGET = REPO / 'docs/evidence/v13-rev12-20261003/workflow24-level3-070335'
SCRIPT_NAMES = {'run-development.py', 'run-campaign.py', 'workflow24-helpers.py',
                'run-workflow24-level3-pinned.py'}
RUN_NAMES = {'execution.json', 'test-results.json', 'test-timings.json', 'run.log'}
SUITES = {'standard': 'StandardCascade', 'paranoia': 'ParanoiaCascade',
          'camellia': 'Camellia256', 'serpent': 'Serpent256'}
PLAN = [dict(testId=f'performance.rev12-workflow-{size}-{suite}-{mode}', suite=kind,
             sourceBytes=4096 if size == '4kib' else 268435456, requestedWorkers=workers)
        for suite, kind in SUITES.items() for size in ('4kib', '256mib')
        for mode, workers in (('auto', None), ('manual1', 1), ('manual4', 4))]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def direct(path):
    require(path.is_absolute() and path.is_file() and not path.is_symlink()
            and path.resolve(strict=True) == path, 'Not a direct original file: ' + str(path))
    return path


def sha(path):
    digest = hashlib.sha256()
    with direct(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def read(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'Duplicate evidence field: ' + key)
            value[key] = item
        return value

    def invalid(token):
        raise ValueError('Non-finite evidence number: ' + token)

    def finite_float(token):
        value = float(token)
        require(math.isfinite(value), 'Non-finite evidence exponent: ' + token)
        return value

    return json.loads(direct(path).read_bytes(), object_pairs_hook=unique,
                      parse_constant=invalid, parse_float=finite_float)


def load_definitions(path, digest, name):
    # Execute only the exact already hash-verified source bytes after terminal
    # validation. A guarded module main is not called; no pycache is consulted.
    raw = direct(path).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == digest, 'Administration source drift')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def terminal(rows, expected, status):
    require(type(rows) is list and len(rows) == len(expected)
            and [row['testId'] for row in rows] == [row['testId'] for row in expected],
            'Wrong closed ordered 24-ID catalog')
    for row, plan in zip(rows, expected):
        require(all(row[key] == value for key, value in plan.items())
                and type(row['attempted']) is bool and type(row['errors']) is list
                and row['status'] == status and type(row.get('completedUtc')) is str,
                'Case is not the required actual terminal status: ' + plan['testId'])
        end = datetime.datetime.fromisoformat(row['completedUtc'])
        start = datetime.datetime.fromisoformat(row['startedUtc'])
        require(end.tzinfo is not None and start.tzinfo is not None and end >= start,
                'Invalid actual UTC bounds')


def tree_files(root):
    require(root.is_dir() and not root.is_symlink() and root.resolve(strict=True) == root,
            'Unsafe original evidence directory')
    found = []
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink() and path.resolve(strict=True) == path,
                'Evidence has a symlink or alias: ' + str(path))
        if path.is_file():
            require(path.suffix in ('.json', '.txt', '.log'), 'Unexpected raw evidence class: ' + str(path))
            found.append(path)
        else:
            require(path.is_dir(), 'Unexpected evidence object')
    return found


def main():
    require(not TARGET.exists(), 'Public target already exists; never overwrite original publication')
    require(sha(READY) == READY_SHA and sha(HISTORY / 'executions.json') == HISTORY_SHA,
            'READY or historical administration pin changed')
    ready = read(READY)
    require(ready['status'] == 'READY' and ready['compressionLevel'] == 3
            and ready['build'] == str(BUILD) and set(ready['scriptSha256']) == SCRIPT_NAMES,
            'Wrong fresh actual L3 binding')
    for name, digest in ready['scriptSha256'].items():
        require(sha(BASE / name) == digest, 'Bound administration changed: ' + name)

    # Reject incomplete checkpoints and any current FAIL/NOT RUN before module
    # loading or publication. Their original receipts remain unchanged.
    plan = read(MATRIX / 'plan.json')
    rows = read(MATRIX / 'executions.json')['executions']
    terminal(rows, PLAN, 'PASS')
    require(plan['cases'] == PLAN and plan['compressionLevel'] == 3
            and plan['build'] == str(BUILD) and plan['bindingPath'] == str(READY)
            and plan['bindingSha256'] == READY_SHA and plan['measuredWorkflowsPerCase'] == 1
            and plan['warmups'] == 0, 'Wrong terminal matrix plan')
    history_rows = read(HISTORY / 'executions.json')['executions']
    terminal(history_rows, PLAN, 'NOT RUN')
    require(all(row['attempted'] is False and 'ownedProcessGroupId' not in row for row in history_rows),
            'Historical administration is not zero actual product starts')
    correction = read(BASE / 'administrative-launch-correction-20261004.json')
    require(correction['originalExecutionsSha256'] == HISTORY_SHA
            and correction['originalAttemptedProductCases'] == 0
            and (REPO / correction['originalRejectedAdministration']) == HISTORY
            and (REPO / correction['actualFreshMatrix']) == MATRIX,
            'Historical administration correction does not bind both actual attempts')

    p = load_definitions(BASE / 'workflow24-helpers.py', ready['scriptSha256']['workflow24-helpers.py'], 'pub_l3_helpers')
    w = load_definitions(BASE / 'run-workflow24-level3-pinned.py',
                         ready['scriptSha256']['run-workflow24-level3-pinned.py'], 'pub_l3_validator')
    _, _, checked, _, maps = w.load_ready_binding(READY)
    require(checked == ready, 'Inconsistent READY parsing')
    binding = read(MATRIX / 'binding.json')
    require(binding['readyBinding'] == ready and binding['bindingPath'] == str(READY)
            and binding['bindingSha256'] == READY_SHA, 'Wrong original matrix binding')
    expected = {'sources': read(MATRIX / 'source-inputs.expected.json'),
                'binaries': read(MATRIX / 'binary-inputs.expected.json'),
                'metadata': read(MATRIX / 'build-metadata.expected.json')}
    require(sha(MATRIX / 'source-inputs.expected.json') == ready['sourceInputsSha256']
            and sha(MATRIX / 'binary-inputs.expected.json') == ready['binaryInputsExpected']['sha256']
            and sha(MATRIX / 'build-metadata.expected.json') == ready['buildMetadataExpected']['sha256'],
            'Copied expected inventory bytes do not match READY pins')
    require(expected['sources'] == read(BUILD / 'source-inputs-before.json') == read(BUILD / 'source-inputs-after.json')
            and expected['binaries'] == read(maps['binaryInputsExpected'])
            and expected['metadata'] == read(maps['buildMetadataExpected']), 'Wrong original expected maps')
    build_result = read(BUILD / 'build-result.json')
    require(build_result['status'] == 'PASS' and build_result['exitCode'] == 0
            and build_result['sourcesStable'] is True
            and expected['metadata'] == p.build_metadata(BUILD), 'Actual build metadata changed')
    harness = BUILD / 'artifacts/bin/KeepVaultMac.Tests/release_osx-arm64'
    require(subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip() == ready['gitHead']
            and p.sources() == expected['sources'] and p.binaries(harness) == expected['binaries'],
            'Current declared frozen source/resource/binary/HEAD binding changed')
    require(not p.owned_fixture_names(BUILD), 'Owned workflow fixtures remain; wait for actual cleanup')
    predecessor = pathlib.Path(ready['predecessorMatrix'])
    require(sha(predecessor / 'executions.json') == ready['predecessorExecutionsSha256']
            and sha(predecessor / 'plan.json') == ready['predecessorPlanSha256'], 'Original L5 predecessor changed')

    profiles = []
    manifests = {}
    for row in rows:
        case = MATRIX / row['testId']
        require(read(case / 'case-result.json') == row and row['attempted'] is True and not row['errors']
                and row['inputBindingVerified'] is True
                and row['remainingOwnedProcesses'] == row['newOwnedFixturesAfterCase'] == [],
                'PASS row does not retain complete actual case/cleanup evidence')
        p.count(row['ownedProcessGroupId'], 'actual own process group', positive=True)
        require(not p.remaining_group_processes(row['ownedProcessGroupId']), 'Actual owned child group is still live')
        for kind, expected_map in expected.items():
            require(read(case / (kind + '-before.json')) == expected_map
                    and read(case / (kind + '-after.json')) == expected_map, 'Actual before/after map drift')
        require(read(case / 'concurrent-processes-before.json')['relevantLiveProcesses'] == [],
                'Case retained competing live processes')
        require(sha(case / 'campaign-output.txt') == row['campaignOutputSha256'], 'Campaign stdout changed')
        campaign = pathlib.Path(row['campaignEvidence'])
        require(campaign.parent == BASE and sha(campaign) == row['campaignReceiptSha256']
                and (case / 'campaign-receipt.json').read_bytes() == direct(campaign).read_bytes(), 'Campaign receipt changed')
        launches = read(campaign)
        require(launches['performance'] is True and len(launches['executions']) == 1, 'Wrong actual campaign scope')
        launch = launches['executions'][0]
        require(launch['testId'] == row['testId'] and launch['evidence'] == row['evidence'], 'Wrong actual campaign case')
        run = pathlib.Path(row['evidence'])
        require(run.parent == BUILD and set(row['originalRunCopies']) == RUN_NAMES, 'Wrong actual build/run inventory')
        for name, digest in row['originalRunCopies'].items():
            require(sha(run / name) == digest == sha(case / 'original-run' / name)
                    and (case / 'original-run' / name).read_bytes() == direct(run / name).read_bytes(), 'Actual run copy changed')
        execution = read(run / 'execution.json')
        require(sha(run / 'execution.json') == row['executionSha256']
                and execution['command'] == [str(p.SDK), str(harness / 'KeepVaultMac.Tests.dll'),
                                              '--performance', '--only', row['testId'], '--parallel', '1']
                and execution['sourceInputsSha256'] == ready['sourceInputsSha256'], 'Wrong actual command/source receipt')
        require(set(execution['files']) == {'test-results.json', 'test-timings.json'}
                and execution['logSha256'] == sha(run / 'run.log')
                and all(sha(run / name) == digest for name, digest in execution['files'].items()), 'Actual output/log hashes changed')
        actual = read(run / 'test-results.json')['tests']
        require(len(actual) == 1 and actual[0] == row['testResult'] and actual[0]['id'] == row['testId']
                and actual[0]['status'] == launch['status'] == 'PASS', 'Wrong actual test verdict')
        p.finite(actual[0]['seconds'], 'actual coordinator duration', positive=True)
        p.count(actual[0]['peakRssMiB'], 'actual coordinator peak RSS', positive=True)
        require(row['campaignExit'] == row['driverExit'] == row['executionExit']
                == execution['exitCode'] == launch['launcherExit'] == 0, 'Actual exit chain failed')
        marker = [re.fullmatch(r'test_exit=(-?\d+) evidence=(.+)', line)
                  for line in launch['launcherOutput'].splitlines() if line.startswith('test_exit=')]
        stdout = (case / 'campaign-output.txt').read_text()
        require(len(marker) == 1 and marker[0] is not None and marker[0].group(1) == '0'
                and marker[0].group(2) == str(run)
                and [line for line in stdout.splitlines() if line.startswith('test_exit=')] == [marker[0].group(0)]
                and [line for line in stdout.splitlines() if line.startswith('campaign_evidence=')] == ['campaign_evidence=' + str(campaign)],
                'Actual campaign/driver stdout markers do not bind the receipts')
        profile = pathlib.Path(row['artifact']['path'])
        logs = (run / 'run.log').read_text()
        require([line for line in logs.splitlines() if line.startswith('REV12_WORKFLOW_PROFILE_ARTIFACT=')]
                == ['REV12_WORKFLOW_PROFILE_ARTIFACT=' + str(profile)]
                and profile.parent == REPO / 'work/v13-evidence'
                and profile.name.startswith(row['testId'] + '-') and profile.suffix == '.json'
                and sha(profile) == row['artifact']['sha256'] == sha(case / 'workflow-profile.json')
                and (case / 'workflow-profile.json').read_bytes() == direct(profile).read_bytes(), 'Actual profile marker/bytes changed')
        data = read(profile)
        w.artifact_contract(p, data, row, expected['binaries'])
        require(data['sourceHead'] == ready['gitHead'], 'Profile source HEAD does not match frozen binding')
        manifest = data['receipt']['InputManifestSha256']
        require(manifests.setdefault(row['sourceBytes'], manifest) == manifest, 'Same-size public fixture manifests differ')
        phases = data['phaseWallSeconds']
        mib = row['sourceBytes'] / (1 << 20)
        profiles.append({'testId': row['testId'], 'suite': row['suite'], 'requestedWorkers': row['requestedWorkers'],
                         'status': row['status'], 'receipt': data['receipt'], 'workflowWallSeconds': data['workflowWallSeconds'],
                         'sourceMiBPerSecondCompleteWorkflow': data['sourceMiBPerSecondCompleteWorkflow'],
                         'phaseWallSeconds': phases, 'sourceMiBPerSecondArchiveAndEncrypt': data['sourceMiBPerSecondArchiveAndEncrypt'],
                         'sourceMiBPerSecondDecryptAndExtract': mib / phases['decryptAndExtractForOriginalComparison'],
                         'outerIntervals': [dict(item, PercentOfWorkflow=100 * item['DurationSeconds'] / data['workflowWallSeconds'])
                                            for item in data['outerWorkflowTimeline']],
                         'overlappingInnerAggregates': data['phaseProfile']['Aggregates'],
                         'overlappingGlobalMacSums': data['globalMacPhasesWallSecondsSum'],
                         'managedCpuSecondsThroughOriginalComparison': data['managedProcessCpuSecondsThroughOriginalComparison'],
                         'sampledManagedAndZpaqCpuSecondsThroughOriginalComparison': data['processAndObservedZpaqChildCpuSecondsThroughOriginalComparison'],
                         'peakRssMiB': actual[0]['peakRssMiB'], 'nativeScheduling': data['nativeScheduling'],
                         'hostBefore': row['hostBefore'], 'hostAfter': row['hostAfter']})

    for row in history_rows:
        require(read(HISTORY / row['testId'] / 'case-result.json') == row, 'Historical terminal row differs from its receipt')
    originals = []
    for prefix, root in (('matrix', MATRIX), ('historical-administration-not-run', HISTORY)):
        originals.extend((prefix + '/' + path.relative_to(root).as_posix(), path) for path in tree_files(root))
    originals += [('administration/' + name, BASE / name) for name in sorted(SCRIPT_NAMES)]
    originals += [('administration/publish-l3-controls.py', pathlib.Path(__file__).resolve())]
    originals += [('binding/' + READY.name, READY), ('binding/administrative-launch-correction-20261004.json',
                   BASE / 'administrative-launch-correction-20261004.json')]
    originals += [('build/' + name, BUILD / name) for name in expected['metadata']]
    originals += [('predecessor/' + name, predecessor / name) for name in ('plan.json', 'executions.json')]
    before = {name: sha(source) for name, source in originals}
    require(len(before) == len(originals), 'Duplicate publication destination')
    TARGET.mkdir(mode=0o755)
    for name, source in originals:
        destination = TARGET / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(direct(source).read_bytes())
        require(sha(destination) == before[name] == sha(source)
                and destination.read_bytes() == direct(source).read_bytes(), 'Original changed during publication: ' + name)
    require(all(sha(source) == before[name] for name, source in originals), 'Original snapshot changed during publication')
    summary = {'schemaVersion': 1, 'status': '24 ACTUAL PASS', 'compressionLevel': 3,
               'matrix': str(MATRIX), 'build': str(BUILD), 'readySha256': READY_SHA,
               'measuredWorkflowsPerCase': 1, 'warmups': 0, 'median': 'NOT APPLICABLE',
               'historicalAdministration': {'matrix': str(HISTORY), 'statuses': '24 NOT RUN', 'actualProductStarts': 0},
               'scope': 'Managed service/native controls only; no AOT/installed GUI/signing/release approval; source bytes once; inner sums overlap and CPU is not walltime',
               'cases': profiles}
    (TARGET / 'summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False, allow_nan=False) + '\n')
    lines = ['# Tatsächliche 24 L3-Kontrollen', '',
             'Alle 24 bestehenden IDs besitzen eigene tatsächliche PASS-Belege im frischen Build070335. Kompressionsstufe 3, produktive KDF, Auto/Manual1/Manual4, KPAR2-Erstellung und gesunde Verifikation, echter Originalvergleich sowie unabhängiger Struktur-/Hashvergleich und Cleanup sind gebunden. Dies ist keine installierte AOT-/GUI-/Signierungs- oder Releasefreigabe.', '',
             'Je Fall genau ein Workflow, kein Warmup und kein Median. Neue unabhängig generierte Faktoren können die KDF-Arbeit verändern. Unterschiede zwischen CPU-Präferenzen sind deshalb kein kontrollierter kausaler CPU-Skalierungsbeweis.', '',
             '| Suite | Quelle, MiB | CPU | Gesamt, s | Quelle MiB/s | Archiv+Encrypt, s | Quelle MiB/s | Decrypt+Extract, s | Quelle MiB/s | KPAR2 Create, s | Healthy Verify, s | Peak RSS, MiB |',
             '|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for item in profiles:
        phase = item['phaseWallSeconds']; cpu = 'Auto' if item['requestedWorkers'] is None else str(item['requestedWorkers'])
        lines.append(f"| {item['suite']} | {item['receipt']['InputBytes'] / (1 << 20):g} | {cpu} | {item['workflowWallSeconds']:.6f} | {item['sourceMiBPerSecondCompleteWorkflow']:.6f} | {phase['archiveAndEncrypt']:.6f} | {item['sourceMiBPerSecondArchiveAndEncrypt']:.6f} | {phase['decryptAndExtractForOriginalComparison']:.6f} | {item['sourceMiBPerSecondDecryptAndExtract']:.6f} | {phase['recoveryCreate']:.6f} | {phase['supplementalRecoveryHealthyVerification']:.6f} | {item['peakRssMiB']} |")
    lines += ['', 'Die Tabelle zählt jedes Originalbyte einmal. Die 256-MiB-Fixture enthält weiterhin ungefähr 75 Prozent Wiederholungsmuster und 25 Prozent öffentliche deterministische Pseudorandomdaten; komprimierte Cipherbytes sind eine andere Bytebasis.', '',
              '| Test-ID | Quellbytes | Komprimierte Payloadbytes | Containerbytes | Recoverybytes |', '|---|---:|---:|---:|---:|']
    for item in profiles:
        receipt = item['receipt']
        lines.append(f"| {item['testId']} | {receipt['InputBytes']} | {receipt['CompressedPayloadBytesDuringCreation']} | {receipt['ContainerBytes']} | {receipt['RecoveryBytes']} |")
    lines += ['', 'Die vollständigen acht additiven Außenintervalle samt Workflowprozent stehen je Fall in summary.json und im bytegleichen Originalprofil unter matrix/<Test-ID>/workflow-profile.json. Ihre Summe ist die tatsächliche monotone Gesamtwandzeit einschließlich Owner-/Fixturecleanup. Die separaten Servicezeiten können zusätzlichen Prüfaufwand ausschließen.', '',
              'Innere KDF-/Cipher-/MAC-Aggregate und native Callback-/Joinzeiten sind überlappend und werden nicht zur Gesamtzeit addiert. summary.json erhält diese Aggregate, ihre tatsächlichen öffentlichen Bytebasen und die separate MAC-Aufteilung. Prozess-CPU ist keine Wandzeit; die kombinierte Beobachtung kann unsampled terminale ZPAQ-CPU auslassen und enthält Fixturecleanup-CPU nicht. Es gibt keinen behaupteten CPU-Anteil je Cipher.', '',
              'Originalsnapshot, Hash, Original-/Strukturvergleich, Memoryadmission und Cleanup sind als eigene originale Service- beziehungsweise Außenintervalle erhalten. Host-Vorher-/Nachherausgaben werden unverändert pro Fall kopiert und in summary.json gebunden. Sie belegen nur Fallrandabfragen, keine kontinuierliche Netz-, Thermal- oder Nebenlastbedingung. Die tatsächlichen Energieausgaben sind zu lesen; AC wird nicht vorausgesetzt oder nachträglich behauptet.', '',
              'historical-administration-not-run bewahrt den ursprünglichen abgewiesenen Verwaltungsstart: 24 NOT RUN, kein Produktchild und keine gemessenen Produktworkflows. Die neue Matrix ist eine neue erste tatsächliche Produktausführung dieser 24 IDs, kein wiederholter vorheriger Produkt-PASS. Die originale Korrekturreceipt ist unter binding erhalten.', '',
              'COPY_VERIFICATION.json nennt die bytegleichen Originalpfade und Hashes. SHA256SUMS bindet sämtliche Nutzdateien und enthält sich selbst nicht. Originale wurden nicht verändert; es gab keine Testwiederholung und keine BenchmarkJSON-Änderung durch diesen Publisher. Bei einem aktuellen FAIL/NOT RUN oder nicht passenden Belegen erzeugt er keine PASS-Publikation.', '']
    (TARGET / 'README.md').write_text('\n'.join(lines))
    verification = {'schemaVersion': 1, 'publishedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'publisherSha256': sha(pathlib.Path(__file__).resolve()), 'originalFileCount': len(originals),
                    'copies': {name: {'originalPath': str(source), 'sha256': before[name], 'byteEqual': True}
                               for name, source in originals},
                    'scope': 'Publication only after 24 actual terminal PASS; no build/test/retry/benchmark edit'}
    (TARGET / 'COPY_VERIFICATION.json').write_text(json.dumps(verification, indent=2, ensure_ascii=False) + '\n')
    payload = {path.relative_to(TARGET).as_posix(): sha(path) for path in sorted(TARGET.rglob('*')) if path.is_file()}
    (TARGET / 'SHA256SUMS').write_text(''.join(digest + '  ' + name + '\n' for name, digest in payload.items()))
    print('public_evidence=' + str(TARGET))
    print('status=24 ACTUAL PASS; historicalProductStarts=0; copiedOriginals=' + str(len(originals)))


if __name__ == '__main__':
    main()
