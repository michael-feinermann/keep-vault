#!/usr/bin/env python3
"""Complete public Standard/Paranoia fixtures with two independent XChaCha oracles.
Input is the exact final inner-stage ciphertext, not a separate random message.
Test dependencies only: PyNaCl1.6.2/libsodium and pinned Go x/crypto0.43.0.
"""
import argparse, base64, ctypes, hashlib, json, pathlib, subprocess, time
import nacl, nacl.bindings, nacl._sodium

p=argparse.ArgumentParser()
p.add_argument('fixture');p.add_argument('--go-oracle',required=True)
p.add_argument('--library',required=True);p.add_argument('--report',required=True)
a=p.parse_args();path=pathlib.Path(a.fixture);doc=json.loads(path.read_text())
assert doc['schema']==1 and doc['publicSyntheticOnly'] is True and doc['marsKats']==10 and doc['shacalKats']==1024
b64=lambda b:base64.b64encode(b).decode('ascii')
dec=lambda s:base64.b64decode(s,validate=True)
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
go=subprocess.Popen([a.go_oracle],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
lib=ctypes.CDLL(str(pathlib.Path(a.library).resolve()))
enc=lib.keepvault_xchacha20poly1305_v13_encrypt_with_budget
enc.argtypes=[ctypes.c_void_p,ctypes.c_size_t]*6+[ctypes.c_uint32];enc.restype=ctypes.c_int
checks=0;rows=[];started=time.monotonic()
try:
 for case in doc['cases']:
  suite=case['suiteId'];assert suite in [2,3]
  stages=case['stages']
  if stages[-1]['cipher']=='XChaCha20Poly1305': stages=stages[:-1]
  assert len(stages)==(3 if suite==2 else 7)
  keys=dec(case['key']);nonces=dec(case['stageNonce'])
  assert len(keys)==(256 if suite==2 else 440)
  assert len(nonces)==(232 if suite==2 else 312)
  key,nonce,aad,plain=keys[-32:],nonces[-24:],dec(case['aad']),dec(stages[-1]['output'])
  assert len(plain)==case['length'] and len(plain)<=16*1024*1024
  expected=nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plain,aad,nonce,key)
  request={'Key':b64(key),'Nonce':b64(nonce),'Aad':b64(aad),'Plaintext':b64(plain)}
  go.stdin.write(json.dumps(request)+'\n');go.stdin.flush();reply=json.loads(go.stdout.readline())
  assert not reply.get('Error'),reply
  go_value=dec(reply['Combined']);assert go_value==expected;checks+=1
  assert nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(expected,aad,nonce,key)==plain;checks+=1
  buffers=[ctypes.create_string_buffer(v,max(1,len(v))) for v in [key,nonce,aad,plain]]
  for grant in [1,2,10]:
   out=ctypes.create_string_buffer(max(1,len(plain)));tag=ctypes.create_string_buffer(16)
   rc=enc(buffers[0],len(key),buffers[1],len(nonce),buffers[2],len(aad),buffers[3],len(plain),out,len(plain),tag,16,grant)
   assert rc==0 and out.raw[:len(plain)]+tag.raw==expected,(suite,len(plain),grant,rc)
   checks+=1
  cipher,tag=expected[:-16],expected[-16:]
  for field,value in {'ciphertext':cipher,'tag':tag,'libsodiumCiphertext':cipher,'libsodiumTag':tag,'goCiphertext':go_value[:-16],'goTag':go_value[-16:]}.items():
   if case.get(field): assert dec(case[field])==value,field
   case[field]=b64(value)
  case['stages']=stages+[{'cipher':'XChaCha20Poly1305','key':b64(key),'nonce':b64(nonce),'output':b64(cipher),'tag':b64(tag)}]
  rows.append({'suite_id':suite,'length':len(plain),'stages':len(case['stages']),'inner_ciphertext_sha256':hashlib.sha256(plain).hexdigest(),'aad_sha256':hashlib.sha256(aad).hexdigest(),'outer_ciphertext_sha256':hashlib.sha256(cipher).hexdigest(),'tag_hex':tag.hex(),'native_grants':[1,2,10]})
finally:
 go.stdin.close();go.wait(timeout=30)
 if go.returncode!=0: raise RuntimeError('Go oracle failed')
path.write_text(json.dumps(doc,indent=2)+'\n')
report={'status':'PASS','scope':'exact Standard/Paranoia inner-stage outputs authenticated by independent libsodium AND Go and compared to actual native AEAD','checks':checks,'cases':rows,'elapsed_seconds':time.monotonic()-started,'pynacl':nacl.__version__,'libsodium':'1.0.20-stable (PyNaCl1.6.2 release metadata)','go_crypto':'v0.43.0','fixture_sha256':sha(path),'library_sha256':sha(a.library),'go_oracle_sha256':sha(a.go_oracle),'libsodium_binding_sha256':sha(nacl._sodium.__file__),'source_sha256':{n:sha(n) for n in ['native/tests/complete_cascade_outer_v13.py','native/tests/xchacha_go_reference/main.go','native/tests/xchacha_go_reference/go.mod','native/tests/xchacha_go_reference/go.sum','native/xchachapoly_ref_export.cpp','KeepVaultMac.Tests/Fixtures/V13Reference/CascadeCompositionReference.cs.txt','external/cryptopp/mars.cpp','external/cryptopp/marss.cpp','external/cryptopp/TestVectors/mars.txt','external/cryptopp/TestVectors/shacal2.txt']}}
pathlib.Path(a.report).write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':'PASS','cases':len(rows),'checks':checks,'fixture_sha256':report['fixture_sha256']}))
