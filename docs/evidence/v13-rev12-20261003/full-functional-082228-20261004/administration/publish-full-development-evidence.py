"""Copy completed original evidence; no build/test/helper imports or invocations."""
from pathlib import Path
import datetime
import hashlib
import json
import math
import shutil

REPO = Path('/Users/michael/Developer/GPT-Codex/Kalyna')
WRAPPER = REPO/'work/v13-evidence/rev12-full-current-20261004'
BUILD = REPO/'work/v13-evidence/rev12-gui-final-20261004/build-20261004T082228Z'
RUN = BUILD/'run-20261004T101611Z-1150e4ab'
HARNESS = BUILD/'artifacts/bin/KeepVaultMac.Tests/release_osx-arm64'
TC = REPO/'work/v13-evidence/rev11-release-b41144e/resume-harness'
OUT = REPO/'docs/evidence/v13-rev12-20261003/full-functional-082228-20261004'

def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda:f.read(1048576),b''):h.update(block)
    return h.hexdigest()

def read(p):return json.loads(p.read_bytes())
def require(v,m):
    if not v:raise RuntimeError(m)
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save(name,value):
    with (OUT/name).open('x') as f:json.dump(value,f,indent=2);f.write('\n')

def main():
    require(not OUT.exists(),'New immutable output directory required')
    result=read(RUN/'test-results.json');timing=read(RUN/'test-timings.json');execution=read(RUN/'execution.json')
    tests=result['tests'];ids=[t['id'] for t in tests]
    require(len(ids)==301 and len(set(ids))==301 and all(t['status']=='PASS' and t['failure'] is None for t in tests),'Not301uniquePASS')
    require(set(timing)==set(ids) and all(math.isfinite(v) and v>=0 for v in timing.values()),'Invalid timing coverage')
    require(execution['exitCode']==0 and execution['logSha256']==sha(RUN/'run.log'),'Actual execution/log mismatch')
    for name in ['test-results.json','test-timings.json']:
        require(execution['files'][name]==sha(RUN/name),'Execution result/timing hash mismatch')
    require(execution['sourceInputsSha256']==sha(BUILD/'source-inputs-before.json'),'Execution source link mismatch')
    require('301 macOS groups: 301 passed, 0 failed, 0 blocked.' in (RUN/'run.log').read_text(),'Actual301marker missing')
    first=datetime.datetime.fromisoformat(execution['startedUtc']);last=datetime.datetime.fromisoformat(execution['completedUtc'])
    require(last>first,'Bad actual execution interval')
    start=read(WRAPPER/'start.json');exit_=read(WRAPPER/'exit.json')
    before=read(WRAPPER/'harness-inputs-before.json');after=read(WRAPPER/'harness-inputs-after.json')
    require(start['harnessInputCount']==len(before)==127 and len(after)==128,'Unexpected harness cardinality')
    added=sorted(after.keys()-before.keys());removed=sorted(before.keys()-after.keys())
    changed=sorted(name for name in before.keys()&after.keys() if before[name]!=after[name])
    require(added==['progress-overhead-public.json'] and not removed and not changed,'Unexpected actual harness change')
    require(exit_['actualHelperExit']==0 and exit_['status']=='FAIL' and exit_['harnessInputsStable'] is False,'Original wrapper result mismatch')
    for name,pin in before.items():require(sha(HARNESS/name)==pin,'Current original harness pin mismatch')
    output_name=added[0];output=read(HARNESS/output_name)
    require(sha(HARNESS/output_name)==after[output_name],'Generated output hash mismatch')
    require(set(output)=={'runUtc','updates','allocatedBytes','elapsedMilliseconds','scope'} and
            output['updates']==1000000 and 0<=output['allocatedBytes']<4096 and
            math.isfinite(output['elapsedMilliseconds']) and output['elapsedMilliseconds']>=0,'Wrong public output schema/counters')
    require(first<=datetime.datetime.fromisoformat(output['runUtc'])<=last,'Generated output outside actual test interval')
    perf=next(t for t in tests if t['id']=='v13-progress-perf')
    require(perf['status']=='PASS','Actual progress-output producer did not pass')
    sources=read(BUILD/'source-inputs-before.json')
    require(sources==read(BUILD/'source-inputs-after.json') and len(sources)==284,'Original build source mismatch')
    for name,pin in sources.items():require(sha(REPO/name)==pin,'Current source differs from retained compile input')
    contract_path='KeepVaultMac.Tests/ProgressIsolationTests.cs';contract=(REPO/contract_path).read_text()
    require(sha(REPO/contract_path)==sources[contract_path] and
            'Path.Combine(AppContext.BaseDirectory, "progress-overhead-public.json")' in contract and
            'new("v13-progress-perf"' in contract,'Public output source contract missing')
    require(read(BUILD/'build-result.json')=={'status':'PASS','exitCode':0,'sourcesStable':True,
        'scope':'Managed development build with installed build15 signed natives, not a new signed product/release.'},'Build result mismatch')
    toolchain=read(BUILD/'toolchain.json')
    require(toolchain['sdkInventorySha256']==sha(TC/'sdk-copy.json') and
            toolchain['packageInventorySha256']==sha(TC/'packages-copy.json'),'Retained toolchain baseline reference mismatch')
    helper=REPO/'work/v13-evidence/rev12-gui-final-20261004/run-development.py'
    require(sha(helper)=='86c3d5e66f6858c9a59e428e79779f4a441bcf55b87660670956d3583f4820a4','Current helper differs from actual wrapper precondition')
    OUT.mkdir(parents=True)
    copies=[]
    def copy(p,name):
        require(p.is_file() and not p.is_symlink(),'Expected direct original file')
        target=OUT/name;target.parent.mkdir(parents=True,exist_ok=True)
        original=p.read_bytes();target.write_bytes(original)
        require(target.read_bytes()==original==p.read_bytes(),'Original copy drift')
        copies.append({'original':p.relative_to(REPO).as_posix(),'public':name,'sha256':sha(target),
                       'bytes':len(original),'byteEqual':True})
    for name in ['build-result.json','source-inputs-before.json','source-inputs-after.json','toolchain.json',
                 'build-0.log','build-1.log','build-2.log']:copy(BUILD/name,'build/'+name)
    for name in ['run.log','test-results.json','test-timings.json','execution.json']:copy(RUN/name,'run/'+name)
    for name in ['launcher.log','start.json','exit.json','harness-inputs-before.json','harness-inputs-after.json',
                 'preparation-original-not-run.json','run-full.py']:copy(WRAPPER/name,'wrapper/'+name)
    copy(helper,'administration/run-development.py')
    copy(TC/'sdk-copy.json','toolchain/sdk-copy.json');copy(TC/'packages-copy.json','toolchain/packages-copy.json')
    copy(HARNESS/output_name,'generated-output/'+output_name)
    copy(Path(__file__),'administration/publish-full-development-evidence.py')
    fragment=contract[contract.index('        // No speed deadline is imposed:'):contract.index('        return Task.CompletedTask;',contract.index('        // No speed deadline is imposed:'))]
    (OUT/'generated-output/source-authorized-output-fragment.txt').write_text(fragment)
    observation={'capturedUtc':utc(),'observationTiming':'AFTER_ONLY, packaging observation; not a before/during-run runtime inventory',
        'currentOriginalHarnessInputs':{'count':len(before),'allMatchOriginalBeforePins':True},
        'currentCompiledSourceInputs':{'count':len(sources),'allMatchOriginalBuildPins':True},
        'generatedOutput':{'sha256':sha(HARNESS/output_name),'matchesOriginalAfterMap':True},
        'currentHelperSha256':sha(helper),'matchesActualWrapperAssertedHelperPin':True,
        'toolchainBaselineReference':{'sdkManifestSha256':sha(TC/'sdk-copy.json'),'packagesManifestSha256':sha(TC/'packages-copy.json'),
            'bothMatchOriginalBuildToolchainReferences':True,'originalWrapperPrecondition':'run-full.py verifies sdk/packages baseline before writing actual start.json',
            'freshSdkTreeAfterInventory':'NOT RUN by this publisher','freshBuildRootPackagesAfterInventory':'NOT RUN by this publisher'},
        'publicPinScope':'Exactly KeepVaultMac/Packaging/Keys/mldsa87-public.key already present in the original284-source map; no key glob or private key read'}
    save('AFTER_ONLY_OBSERVATIONS.json',observation)
    classification={'schemaVersion':1,'createdUtc':utc(),'status':'FUNCTIONAL_DEVELOPMENT_301_PASS_WITH_ORIGINAL_ENVELOPE_FAIL',
        'actualTestGroups':301,'actualPass':301,'actualFail':0,'actualBlocked':0,'actualExecutionExit':0,'actualHelperExit':0,
        'originalOuterWrapperStatus':'FAIL','originalOuterHarnessInputsStable':False,
        'derivedInputClassification':{'originalInputCount':127,'originalInputsChanged':changed,'originalInputsRemoved':removed,
            'originalInputPinsAllStableAcrossOriginalBoundaries':True,'addedPublicGeneratedOutputs':added,
            'sourceAuthorizedExactOutput':{'sourcePath':contract_path,'sourceSha256':sources[contract_path],
                'producerActualTestId':'v13-progress-perf','producerActualStatus':'PASS','exactFilename':output_name,
                'outputSha256':after[output_name],'outputRunUtc':output['runUtc'],'insideActualExecutionUtcInterval':True,
                'publicSchemaKeys':sorted(output),'scope':output['scope']}},
        'actualExecutionInterval':{'startedUtc':execution['startedUtc'],'completedUtc':execution['completedUtc'],
            'seconds':(last-first).total_seconds(),'scope':'Actual helper coordinator execution interval, includes child launch/coordination, not sum of group times'},
        'headAtExecution':result['head'],'sourceInputCount':len(sources),'sourceInventorySha256':execution['sourceInputsSha256'],
        'testInventoryHash':result['testInventoryHash'],'harnessOriginalBinaryPins':{
            name:before[name] for name in ['KeepVaultMac.Tests.dll','Keep Vault.dll']},
        'testResultSha256':sha(RUN/'test-results.json'),'testTimingSha256':sha(RUN/'test-timings.json'),
        'afterOnlyObservationsReference':'AFTER_ONLY_OBSERVATIONS.json',
        'scope':'Managed ARM64/Avalonia-Headless current sources with retained signed Build15 natives, not final Build16 Universal/AOT/installed GUI/release proof',
        'finalUniversalAot':'NOT RUN','installedNativeGui':'NOT RUN','last512AfterNativeGui':'NOT RUN','releaseApproval':'NOT_GRANTED'}
    save('DERIVED_CLASSIFICATION.json',classification)
    save('GROUP_INDEX.json',{'scope':'Derived301row index; exact group seconds from original timing catalog; original result rounded seconds retained separately',
        'groups':[{'id':t['id'],'status':t['status'],'seconds':timing[t['id']],'resultRoundedSeconds':t['seconds'],
                   'peakRssMiB':t['peakRssMiB'],'seed':t['seed']} for t in tests]})
    save('ORIGINAL_COPY_RECEIPT.json',{'schemaVersion':1,'createdUtc':utc(),'copiedOriginals':len(copies),
        'allOriginalCopiesByteEqual':True,'files':copies,
        'scope':'Exact original public run/build/wrapper/helper/baseline/output bytes; derived classifications are separate files'})
    print(json.dumps({'copiedOriginals':len(copies),'groups':301,'sourceInputs':len(sources),
                      'originalEnvelope':'FAIL retained','derivedClassificationSha256':sha(OUT/'DERIVED_CLASSIFICATION.json')}))

if __name__=='__main__':main()
