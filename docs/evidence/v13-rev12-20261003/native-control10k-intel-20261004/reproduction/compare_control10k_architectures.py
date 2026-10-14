#!/usr/bin/env python3
"""PREPARED / NOT RUN: read-only two-architecture original-receipt comparison.

This does not compile, import a harness, execute native code or install Rosetta.
ARM64 and Intel/Rosetta remain separate actual runs with separate input maps.
"""
import argparse, hashlib, json, math, pathlib, struct, sys

ROOT=pathlib.Path('/Users/michael/Developer/GPT-Codex/Kalyna')
ARM_REPORT_SHA256='d339c65be50e850776c8d3ff37be2391560dede9e8881792a1ef25f791f240ab'
CPP_SHA256='b7c7fdde2bc8fee7dfe4c5b3c9af41327145c0d22b9575f99ad6ca4005c31493'
HEADER_SHA256='49e451e0713658ad75d44c96d2805cadf22cee9a2f3022153cbe97ef14df147c'
ORIGINAL_RUNNER_SHA256='0eef36ecf3d6edfa379f69dd63a5f0ace497ecbc3d1b78fc09327ac4a2f12fda'
INTEL_RUNNER_SHA256='919ef129e00275fcadbf1a8b5ded775280edc9b4e4c8bbe79a25bb06334e4835'
CORPUS_SHA256='62fc5b7738245e7537ef320f73ee0d3ced2f30680111baa899247d0fa4f9b7d2'
VERDICT_SHA256='d4102a27c87876bcf493197e41dc2cbf458e1dd7c87b9115a5e2fed22645b247'

def require(condition,message):
    if not condition: raise ValueError(message)

def sha(path):
    require(path.is_file() and not path.is_symlink(),'Expected direct original file: '+str(path))
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1<<20),b''):digest.update(block)
    return digest.hexdigest()

def unique(pairs):
    result={}
    for key,value in pairs:
        require(key not in result,'Duplicate JSON field: '+key);result[key]=value
    return result

def parse(raw):
    def invalid(value):raise ValueError('Non-finite JSON number: '+value)
    return json.loads(raw,object_pairs_hook=unique,parse_constant=invalid)

def hex64(value):
    return isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)

def actual_image(binary,architecture):
    with binary.open('rb') as stream:header=stream.read(32)
    require(len(header)==32,'Incomplete actual Mach-O header')
    values=struct.unpack('<8I',header)
    require(values[0]==0xfeedfacf and values[1]=={'arm64':0x0100000c,'x86_64':0x01000007}[architecture]
            and values[3]==2,'Wrong actual thin Mach-O architecture/filetype')
    return {'architecture':architecture,'cpuType':values[1],'cpuSubtype':values[2],'fileType':values[3]}

def pinned_input(data,suffix,expected):
    selected=[(path,item) for path,item in data['inputs_before'].items() if path.endswith(suffix)]
    require(selected and all(item['sha256']==expected for path,item in selected),'Missing/different pinned input: '+suffix)
    return selected

def checked_report(path,architecture):
    require(path.is_absolute() and path.parent.resolve(strict=True)==path.parent,'Ambiguous actual report location')
    digest=sha(path);data=parse(path.read_bytes())
    if architecture=='arm64':require(digest==ARM_REPORT_SHA256,'Original historical ARM64 report changed')
    require(data['status']=='PASS' and data['mode']==architecture,'No actual PASS for this architecture')
    for name,expected in [('cases_expected',10000),('cases_completed',10000),('expected_accepted',2500),('expected_rejected',7500)]:
        require(type(data[name]) is int and data[name]==expected,'Wrong actual complete count: '+name)
    require(data['seed']=='0x4b56313343544c31' and data['stderr_bytes_seen']==0
            and data['stderr_capture_truncated'] is False,'Wrong actual seed/stderr completeness')
    require(not any('error' in name or name in ('failure','failure_type') for name in data),'Actual failure/observer diagnostics present')
    require(data['inputs_before'] and data['inputs_before']==data['inputs_after'],'Actual input maps changed')
    require(all(hex64(item['sha256']) for item in data['inputs_before'].values()),'Invalid bound input hash')
    pinned_input(data,'/control_framing_fuzz.cpp',CPP_SHA256)
    pinned_input(data,'/native/zpaq_control.hpp',HEADER_SHA256)
    pinned_input(data,'/run_control_framing_fuzz_macos.py',ORIGINAL_RUNNER_SHA256)
    if architecture=='x86_64':
        pinned_input(data,'/run_control_framing_fuzz_intel_macos.py',INTEL_RUNNER_SHA256)
        pinned_input(data,'/usr/bin/arch',sha(pathlib.Path('/usr/bin/arch')))
        require(data['pythonProcessArchitecture']=='arm64' and data['executionArchitecture']=='x86_64'
                and data['childExitCode']==0,'No actual native ARM64 parent/thin Intel child completion')
        require(type(data['parentPid']) is int and data['parentPid']>0
                and type(data['childPid']) is int and data['childPid']>0,'Missing actual parent/child identity')
        require(data['binary_snapshot_before']==data['binary_snapshot_after'],'Intel binary identity changed')
    command=data['compile_command'];index=command.index('-arch')
    require(command[index+1]==architecture and command.count('-arch')==1,'Wrong single compile architecture')
    require('-O2' in command and '-DNDEBUG' in command,'Wrong optimized framing mode')
    binary=pathlib.Path(command[command.index('-o')+1])
    require(binary.is_absolute() and binary.parent==path.parent,'Actual harness binary outside run directory')
    binary_sha=sha(binary)
    require(binary_sha==data['binary_sha256_before']==data['binary_sha256_after'],'Actual harness binary hash changed')
    image=actual_image(binary,architecture)
    if architecture=='x86_64':
        launch=data['launch_command']
        require(len(launch)==5 and launch[:3]==['/usr/bin/arch','-x86_64',str(binary)]
                and launch[4]==str(data['parentPid']),'Wrong actual explicit Intel launch/parent command')
        require(data['machOImage']['architecture']=='x86_64' and all(data['machOImage'][k]==image[k]
                for k in ('cpuType','cpuSubtype','fileType')),'Intel architecture receipt differs from actual image')
    for name in ('build.stdout.txt','build.stderr.txt','run.stderr.txt'):
        require(sha(path.parent/name)==hashlib.sha256(b'').hexdigest(),'Actual build/runtime diagnostic is not empty: '+name)
    corpus_path=path.parent/'corpus.ndjson';require(sha(corpus_path)==data['corpus_sha256']==CORPUS_SHA256,'Public corpus changed')
    corpus=[parse(line) for line in corpus_path.read_bytes().splitlines()]
    require(len(corpus)==10000 and [c['index'] for c in corpus]==list(range(10000)),'Actual corpus is not all 10000 cases')
    require(sum(c['reject']==0 for c in corpus)==2500 and sum(c['reject']==1 for c in corpus)==7500,'Wrong independent corpus verdict counts')
    expected=hashlib.sha256(b''.join(('CONTROL_FUZZ_CASE '+str(c['index'])+' '+str(c['reject'])+'\n').encode() for c in corpus)).hexdigest()
    require(expected==VERDICT_SHA256==data['expected_semantic_output_sha256']==data['actual_semantic_output_sha256'],
            'Actual complete semantic transcript differs from independently reconstructed verdict')
    require(hex64(data['input_wire_sha256']) and hex64(data['output_wire_sha256']),'Missing actual wire receipts')
    require(type(data['seconds']) in (int,float) and math.isfinite(data['seconds']) and data['seconds']>0,'Invalid harness duration')
    return {'status':'VALIDATED ACTUAL PASS','architecture':architecture,'reportPath':str(path),'reportSha256':digest,
            'sourceProducerMode':data['mode'],'cases':10000,'accepted':2500,'rejected':7500,'seconds':data['seconds'],
            'binaryPath':str(binary),'binarySha256':binary_sha,'thinMachO':image,'inputFiles':len(data['inputs_before']),
            'corpusSha256':CORPUS_SHA256,'actualVerdictSha256':VERDICT_SHA256,
            'inputWireSha256':data['input_wire_sha256'],'outputWireSha256':data['output_wire_sha256'],
            'parentPid':data.get('parentPid'),'childPid':data.get('childPid'),
            'childExitCode':data.get('childExitCode'),
            'exitEvidence':'recorded childExitCode=0' if architecture=='x86_64' else 'pinned original producer requires actual child exit0 before PASS; original report has no separate exit field',
            'environment':'native ARM64 framing child' if architecture=='arm64' else 'thin Intel child via explicit arch -x86_64 from native ARM64 parent',
            'timingScope':'isolated framing harness walltime; not archive/cipher throughput; compile/inventory excluded'}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arm64-report',type=pathlib.Path,required=True)
    parser.add_argument('--intel-report',type=pathlib.Path,required=True)
    parser.add_argument('--output-dir',type=pathlib.Path,required=True)
    args=parser.parse_args();out=args.output_dir.resolve()
    require(out.is_relative_to(ROOT/'work'),'New comparison must remain in ignored work')
    out.mkdir(parents=True,exist_ok=False)
    rows=[]
    for architecture,path in [('arm64',args.arm64_report),('x86_64',args.intel_report)]:
        try:
            if not path.exists():
                rows.append({'architecture':architecture,'status':'NOT RUN','reportPath':str(path)});continue
            rows.append(checked_report(path,architecture))
        except Exception as error:
            rows.append({'architecture':architecture,'status':'VALIDATION FAIL','reportPath':str(path),
                         'errorType':type(error).__name__,'error':str(error)})
    status='PASS' if all(r['status']=='VALIDATED ACTUAL PASS' for r in rows) else 'FAIL' if any(r['status']=='VALIDATION FAIL' for r in rows) else 'INCOMPLETE'
    result={'status':status,'scope':'Separate historical actual ARM64 and newly actual x86_64/Rosetta framing runs; no architecture substitution',
            'reporterSha256':sha(pathlib.Path(__file__).resolve()),'runs':rows,
            'limitations':['no invented ARM64 or Intel execution','same corpus and verdict; wire order/hashes may differ',
                           'actual marker transcript is producer-bound hash, not a separately saved stdout transcript',
                           'input maps bind dependency headers/compiler/SDK descriptor/Python/runner; not every linker/system/Rosetta runtime input',
                           'no native Intel hardware performance evidence; Rosetta semantics only',
                           'no full source_entry/CPU/memory lifecycle, sequence exhaustion, leak freedom, installed GUI or release approval']}
    (out/'comparison.json').write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')
    lines=['# Getrennte tatsächliche Control10k-Architekturbelege','',f'Status: {status}.',
           '', '| Architektur | Belegstatus | Tatsächliche Fälle | Harnesszeit, s |', '|---|---|---:|---:|']
    for row in rows:lines.append('| '+row['architecture']+' | '+row['status']+' | '+str(row.get('cases','nicht belegt'))+' | '+str(row.get('seconds','nicht belegt'))+' |')
    lines+=['','ARM64 wird ausschließlich aus seinem unveränderten ursprünglichen PASS gelesen. Intel/Rosetta benötigt seinen eigenen vollständigen tatsächlichen PASS. Ein fehlender oder gescheiterter Intel-Beleg wird nicht durch ARM64 ersetzt.',
            '', 'Gleicher öffentlicher 10.000-Fälle-Corpus und vollständiger Verdict sind obligatorisch. Tatsächliche Wirehashes dürfen wegen zweier Caller und Reject-Rennen abweichen; jeder Lauf muss seinen bytegenauen Wireoracle erfüllt haben.',
            '', 'Die native Parentauthentisierung stammt aus dem unveränderten produktiven control_channel-Konstruktor. Beim Intel-Lauf sind tatsächliche Parent-/Child-PIDs, arch-Aufruf und dünnes x86_64-Mach-O separat erhalten. Originale ARM64-Reports haben kein eigenes Childexit-/PID-/UTC-Feld; diese Werte werden nicht ergänzt.',
            '', 'Das ist eine enge Controlframing-Semantikprüfung. Rosetta ist kein Lauf auf nativer Intel-Hardware, keine Geschwindigkeitsmessung der Anwendung und keine Intel- oder Gesamtproduktfreigabe. Eingaben sind konkret gebunden, aber nicht sämtliche Linker-/System-/Rosetta-Runtimeinputs hermetisch inventarisiert.']
    (out/'README.de.md').write_text('\n'.join(lines)+'\n')
    files=sorted(p for p in out.iterdir() if p.is_file())
    (out/'SHA256SUMS.txt').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in files))
    print(json.dumps({'status':status,'runs':[{'architecture':r['architecture'],'status':r['status']} for r in rows]}))
    return 0 if status=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())
