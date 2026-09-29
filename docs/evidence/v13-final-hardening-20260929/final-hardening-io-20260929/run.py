import datetime,hashlib,json,pathlib,re,subprocess,time
root=pathlib.Path(__file__).resolve().parents[3]
stage=root/'work/v13-dev-trust-20260928'
evidence=pathlib.Path(__file__).resolve().parent
reference=root/'work/v13-evidence/rev9-hardening-rerun-binaries-20260929.json'
ids=re.findall(r'new\("(io\.[^"]+)"', (root/'KeepVaultMac.Tests/VerifiedArchiveInputTests.cs').read_text())
assert len(ids)==11
ids+=['fuzz.verified-input-10000','fuzz.recovery-streaming-10000','fuzz.verified-read-at-server-10000','recovery.kpar2-v4-adversarial']
ids+=['recovery.record-table-'+suffix for suffix in ['layout','tamper','budget','cleanup']]
ids+=['recovery.streaming-metadata-canonical','containers.v13-production-worker-equivalence']
assert len(ids)==21 and len(set(ids))==21

def write_new(path,obj):
 with path.open('x') as f: json.dump(obj,f,indent=2);f.write('\n')
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
manifest=json.loads(reference.read_text())
fixed={name:value for name,value in manifest['files'].items() if name!='.test-timings.json'}
def hashes(): return {name:sha(stage/name) for name in fixed}
initial=hashes()
assert initial==fixed,'Stage differs from supplied binary manifest'
sources=['KalynaArchiver/Services/VerifiedArchiveInput.cs','KeepVaultMac/Services/BoundFileTransaction.cs','KalynaArchiver/Services/BoundFileTransaction.cs','KeepVaultMac.Tests/VerifiedArchiveInputTests.cs','KeepVaultMac.Tests/VerifiedArchiveInputAttack.cs','KeepVaultMac.Tests/VerifiedIoFuzzTests.cs','KalynaArchiver/Services/RecoveryService.cs','KeepVaultMac.Tests/MacComprehensiveTests.cs']
write_new(evidence/'binary-and-source-before.json',{'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'reference_manifest':str(reference.relative_to(root)),'reference_manifest_sha256':sha(reference),'git_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'binary_sha256':initial,'current_source_sha256':{name:sha(root/name) for name in sources},'scope':'Managed hardening build 2 plus unchanged signed development natives. Source hashes are current working files at test start; this is not a final release artifact.'})
write_new(evidence/'plan.json',{'ids':ids,'group_count':len(ids),'seed':'0x5EED0313','cwd':'KeepVaultMac','real_source_limit_bytes':256*1024*1024})
summary=[]
for test in ids:
 cmd=['/opt/homebrew/bin/dotnet',str(stage/'KeepVaultMac.Tests.dll'),'--full','--no-smoke','--only',test,'--parallel','1','--seed','0x5EED0313']
 log=evidence/(test+'.log');saved=evidence/(test+'.test-results.json');metadata=evidence/(test+'.run.json')
 if any(p.exists() for p in [log,saved,metadata]):raise RuntimeError('Refusing overwrite: '+test)
 old_time=(stage/'.test-results.json').stat().st_mtime_ns if (stage/'.test-results.json').exists() else None
 started=time.monotonic();utc=datetime.datetime.now(datetime.timezone.utc).isoformat()
 print('START '+test,flush=True)
 with log.open('x') as f: completed=subprocess.run(cmd,cwd=root/'KeepVaultMac',stdout=f,stderr=subprocess.STDOUT)
 result_file=stage/'.test-results.json'
 if old_time==result_file.stat().st_mtime_ns:raise RuntimeError('Stale test result: '+test)
 raw=result_file.read_bytes()
 with saved.open('xb') as f:f.write(raw)
 result=json.loads(raw);tests=result.get('tests',[])
 if len(tests)!=1 or tests[0]['id']!=test:raise RuntimeError('Unexpected test selection: '+test)
 write_new(metadata,{'command':cmd,'cwd':str(root/'KeepVaultMac'),'started_utc':utc,'exit_code':completed.returncode,'wall_seconds':time.monotonic()-started,'log_sha256':sha(log),'result_sha256':sha(saved)})
 summary.append({'id':test,'exit_code':completed.returncode,'status':tests[0]['status'],'seconds':tests[0]['seconds']})
 print(json.dumps(summary[-1]),flush=True)
 if completed.returncode!=0: print(log.read_text(),flush=True)
final=hashes()
write_new(evidence/'summary.json',{'results':summary,'binary_files_unchanged':initial==final,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
write_new(evidence/'evidence-sha256.json',{p.name:sha(p) for p in sorted(evidence.iterdir()) if p.is_file() and p.name!='evidence-sha256.json'})
if initial!=final:raise RuntimeError('Stage binary files changed during tests')
print('FINISHED '+str(len(summary))+' groups',flush=True)
