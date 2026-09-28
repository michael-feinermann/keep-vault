#!/usr/bin/env python3
"""Compile the production read-at parser into a bounded, seeded test harness."""
import hashlib,json,os,platform,subprocess,time
from pathlib import Path
root=Path(__file__).resolve().parents[2]
out=root/'work/v13-native/read-at-fuzz'
out.mkdir(parents=True,exist_ok=True)
source=root/'native/tests/verified_read_at_fuzz.cpp'
header=root/'native/verified_archive_reader.hpp'
report={'target':'VerifiedArchiveReader','source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
        'production_header_sha256':hashlib.sha256(header.read_bytes()).hexdigest(),
        'host':platform.platform(),'clang':subprocess.check_output(['/usr/bin/clang++','--version'],text=True).splitlines()[0],
        'seed':'0x4b5631335241465a','cases_per_binary':10000,'leak_sanitizer':'unavailable on this macOS target; not claimed','runs':[]}
for name,flags in [('arm64',['-arch','arm64','-O2']),('x86_64',['-arch','x86_64','-O2']),
                   ('asan-ubsan',['-arch','arm64','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
 binary=out/('read-at-fuzz-'+name)
 command=['/usr/bin/clang++','-std=c++17','-pthread',*flags,str(source),'-o',str(binary)]
 build=subprocess.run(command,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 (out/(name+'-build.log')).write_text(build.stdout)
 if build.returncode:raise SystemExit(build.stdout)
 env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1')
 start=time.monotonic();run=subprocess.run([str(binary),report['seed']],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=env,timeout=180)
 elapsed=time.monotonic()-start
 (out/(name+'.log')).write_text(run.stdout)
 if run.returncode or 'read_at_fuzz=PASS' not in run.stdout or 'runtime error:' in run.stdout or 'ERROR: AddressSanitizer' in run.stdout:
  raise SystemExit(run.stdout)
 report['runs'].append({'binary':name,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
                       'compile_command':command,'elapsed_seconds':elapsed,'result':run.stdout.strip()})
 (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 print(name,run.stdout.strip(),flush=True)
