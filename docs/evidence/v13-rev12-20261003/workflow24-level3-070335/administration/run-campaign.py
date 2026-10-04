#!/usr/bin/python3
"""Retain every selected REV12 development execution, including failures."""
import datetime, hashlib, json, pathlib, subprocess, sys, uuid

base = pathlib.Path(__file__).resolve().parent
runner = base / 'run-development.py'
performance = '--performance' in sys.argv[1:]
ids = [value for value in sys.argv[1:] if value != '--performance']
if not ids:
    raise SystemExit('Provide exact test IDs; add --performance for manual measurements.')
receipt = base / ('campaign-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    + '-' + uuid.uuid4().hex[:8] + '.json')
rows = []
for test_id in ids:
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    args = ['/usr/bin/python3', str(runner), 'test',
        *(['--performance'] if performance else ['--full', '--no-smoke']),
        '--only', test_id, '--parallel', '1']
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    evidence = next((line.split('evidence=', 1)[1] for line in result.stdout.splitlines()
        if line.startswith('test_exit=') and 'evidence=' in line), None)
    rows.append({'testId': test_id, 'startedUtc': start,
        'completedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'launcherExit': result.returncode, 'evidence': evidence, 'launcherOutput': result.stdout,
        'status': 'PASS' if result.returncode == 0 and evidence else ('FAIL' if evidence and result.returncode != 64 else 'NOT RUN')})
    receipt.write_text(json.dumps({'scope': 'Managed development evidence; installed release approval is separate',
        'performance': performance, 'executions': rows}, indent=2) + '\n')
    print(test_id + ' ' + rows[-1]['status'] + '\n' + result.stdout.strip(), flush=True)
print('campaign_evidence=' + str(receipt), flush=True)
raise SystemExit(0 if all(row['status'] == 'PASS' for row in rows) else 1)
