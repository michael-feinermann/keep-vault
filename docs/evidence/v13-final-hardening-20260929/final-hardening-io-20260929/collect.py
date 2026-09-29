import json,pathlib,hashlib,datetime
base=pathlib.Path(__file__).resolve().parent
runs=[('', 'work/v13-evidence/rev9-hardening-rerun-binaries-20260929.json'),('build3-rerun','work/v13-evidence/rev9-hardening-build3-binaries-20260929.json'),('build3-supplementary','work/v13-evidence/rev9-hardening-build3-binaries-20260929.json')]
latest={};executions=[]
for sub,manifest in runs:
 folder=base/sub
 summary=json.loads((folder/'summary.json').read_text())
 assert summary['binary_files_unchanged']
 for item in summary['results']:
  result=folder/(item['id']+'.test-results.json')
  record={**item,'result_path':str(result.relative_to(base)),'result_sha256':hashlib.sha256(result.read_bytes()).hexdigest(),'binary_reference_manifest':manifest}
  executions.append(record);latest[item['id']]=record
assert len(executions)==34 and len(latest)==30
output={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Signed development binaries, bounded inputs; not final signed/notarized release package. Build2 and Build3 are explicitly distinguished.','execution_count':len(executions),'unique_group_count':len(latest),'latest_pass_count':sum(r['status']=='PASS' for r in latest.values()),'initial_helper_failures_preserved':sum(r['status']=='FAIL' for r in executions),'latest_group_results':list(latest.values()),'all_executions':executions}
with (base/'combined-summary.json').open('x') as f:json.dump(output,f,indent=2);f.write('\n')
files={str(p.relative_to(base)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(base.rglob('*')) if p.is_file() and p.name!='final-evidence-sha256.json'}
with (base/'final-evidence-sha256.json').open('x') as f:json.dump(files,f,indent=2);f.write('\n')
print(json.dumps({k:output[k] for k in ['execution_count','unique_group_count','latest_pass_count','initial_helper_failures_preserved']}))
