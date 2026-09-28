#!/usr/bin/env python3
"""Instrument reviewed adapters/CTR helper; Crypto++ archive stays uninstrumented.
Run only on public independent test corpus. No product features are changed.
"""
import argparse,pathlib,subprocess,os,json,hashlib
p=argparse.ArgumentParser();p.add_argument('corpus');p.add_argument('--native',default='KeepVaultMac/Native/osx-arm64');p.add_argument('--output',default='work/v13-native/sanitizers');p.add_argument('--report',required=True);a=p.parse_args()
cc=subprocess.check_output(['xcrun','--find','clang'],text=True).strip();sdk=subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip();results=[]
for mode in ['address,undefined','thread']:
 d=pathlib.Path(a.output)/('asan' if mode.startswith('address') else 'tsan');d.mkdir(parents=True,exist_ok=True)
 for cipher in ['camellia','serpent']:
  subprocess.run([cc,'--driver-mode=g++','-isysroot',sdk,'-arch','arm64','-mmacosx-version-min=14.0','-std=c++17','-O1','-g','-fno-omit-frame-pointer','-fsanitize='+mode,'-dynamiclib','-pthread','-Iexternal/cryptopp',f'native/{cipher}_v13_export.cpp',str(pathlib.Path(a.native)/'libcryptopp.a'),'-o',str(d/f'lib{cipher}_v13.dylib')],check=True)
 subprocess.run([cc,'-isysroot',sdk,'-std=c11','-O1','-g','-fno-omit-frame-pointer','-fsanitize='+mode,'-pthread','native/tests/ctr_corpus_runner.c','-o',str(d/'runner')],check=True)
 env=os.environ.copy();env.update(ASAN_OPTIONS='detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1',TSAN_OPTIONS='halt_on_error=1')
 result=subprocess.run([str(d/'runner'),str(d),a.corpus],env=env,text=True,capture_output=True);assert result.returncode==0,(result.returncode,result.stdout,result.stderr)
 results.append({'sanitizer':mode,**json.loads(result.stdout),'stderr':result.stderr,'binary_sha256':{x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in d.glob('*.dylib')}})
report={'status':'PASS','scope':'new adapters, fixed-access Camellia and shared CTR instrumented; vendor static Crypto++ archive uninstrumented','leak_sanitizer':'NOT AVAILABLE in Apple arm64 sanitizer runtime; detect_leaks=0','corpus_sha256':hashlib.sha256(pathlib.Path(a.corpus).read_bytes()).hexdigest(),'results':results};pathlib.Path(a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
