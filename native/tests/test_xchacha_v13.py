#!/usr/bin/env python3
"""Bounded v13 ABI/KAT/interoperability checks; public synthetic data only.
Usage: python test_xchacha_v13.py library --go-oracle executable [--report report.json]
Requires pinned PyNaCl==1.6.2 (bundled libsodium), Go oracle x/crypto v0.43.0.
Product artifact trust checks are covered by application tests, not ctypes here.
"""
import argparse, base64, ctypes as C, hashlib, itertools, json, pathlib, platform, random, subprocess, time
import nacl, nacl.bindings, nacl._sodium

P=C.c_void_p; Z=C.c_size_t; U=C.c_uint32
parser=argparse.ArgumentParser();parser.add_argument('library');parser.add_argument('--go-oracle',required=True);parser.add_argument('--report');parser.add_argument('--fuzz-cases',type=int,default=10000);args=parser.parse_args()
lib=C.CDLL(str(pathlib.Path(args.library).resolve())); funcs={}; checks=0
for name in ['encrypt','decrypt','encrypt_serial','decrypt_serial','encrypt_with_workers','decrypt_with_workers','cryptopp_encrypt','cryptopp_decrypt']:
    prefix='keepvault_xchacha20poly1305_v13_' if name in ['encrypt','decrypt'] else 'keepvault_test_xchacha20poly1305_v13_'
    f=getattr(lib,prefix+name+('_with_budget' if name in ['encrypt','decrypt'] else ''));f.argtypes=[P,Z,P,Z,P,Z,P,Z,P,Z,P,Z]+([U] if name.endswith('workers') or name in ['encrypt','decrypt'] else []);f.restype=C.c_int;funcs[name]=f
h=lib.keepvault_test_hchacha20_v13;h.argtypes=[P,Z,P,Z,P,Z];h.restype=C.c_int
proc=subprocess.Popen([args.go_oracle],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
def check(ok, name):
    global checks
    assert ok, name
    checks+=1

def buf(b): return C.create_string_buffer(b,max(1,len(b)))
def deterministic(n,seed): return (bytes((i*29+seed)%256 for i in range(256))*((n+255)//256))[:n]
def encrypt(key,nonce,aad,data,name='encrypt',workers=0):
    k,n,a,p=map(buf,[key,nonce,aad,data]);out=buf(bytes([0xa5])*len(data));tag=buf(bytes([0xa7])*16)
    params=[k,len(key),n,len(nonce),a,len(aad),p,len(data),out,len(data),tag,16]
    if name.endswith('workers') or name in ['encrypt','decrypt']:params.append(workers or 1)
    check(funcs[name](*params)==0,name+' status')
    return out.raw[:len(data)]+tag.raw[:16]
def reject(key,nonce,aad,combined,name='decrypt',workers=0):
    k,n,a,inp,tag=map(buf,[key,nonce,aad,combined[:-16],combined[-16:]])
    length=len(combined)-16;out=buf(b'\xa5'*length)
    params=[k,len(key),n,len(nonce),a,len(aad),inp,length,out,length,tag,16]
    if name.endswith('workers') or name in ['encrypt','decrypt']:params.append(workers or 1)
    check(funcs[name](*params)!=0 and out.raw[:length]==b'\xa5'*length,'rejection before plaintext')
def go(key,nonce,aad,data):
    req={k:base64.b64encode(v).decode() for k,v in [('Key',key),('Nonce',nonce),('Aad',aad),('Plaintext',data)]}
    proc.stdin.write(json.dumps(req)+'\n');proc.stdin.flush();r=json.loads(proc.stdout.readline());check(not r['Error'],'Go status');return base64.b64decode(r['Combined'])
def roundtrip(key,nonce,aad,data,combined,name='decrypt',workers=0,in_place=False):
    k,n,a,tag=map(buf,[key,nonce,aad,combined[-16:]]);inp=buf(combined[:-16]);out=inp if in_place else buf(bytes(len(data)))
    params=[k,len(key),n,len(nonce),a,len(aad),inp,len(data),out,len(data),tag,16]
    if name.endswith('workers') or name in ['encrypt','decrypt']:params.append(workers or 1)
    check(funcs[name](*params)==0 and out.raw[:len(data)]==data,name+' roundtrip')
start=time.time()
# draft-irtf-cfrg-xchacha-03 section 2.2.1, exact subkey.
key=bytes(range(32));nonce=bytes.fromhex('000000090000004a0000000031415927');out=buf(bytes(32))
check(h(buf(key),32,buf(nonce),16,out,32)==0,'HChaCha status')
check(out.raw==bytes.fromhex('82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc'),'HChaCha KAT 2.2.1')
# draft-irtf-cfrg-xchacha-03 appendix A.3.1.
key=bytes(range(0x80,0xa0));nonce=bytes(range(0x40,0x58));aad=bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
data=b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
expected=bytes.fromhex('bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49')
check(encrypt(key,nonce,aad,data)==expected,'XChaCha KAT A.3.1')
check(nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(data,aad,nonce,key)==expected,'libsodium KAT')
check(go(key,nonce,aad,data)==expected,'Go KAT')
for i in range(24):
    bad=bytearray(nonce);bad[i]^=1;bad=bytes(bad)
    changed=encrypt(key,bad,aad,data);check(changed==nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(data,aad,bad,key)==go(key,bad,aad,data),'every nonce byte oracle')
    reject(key,bad,aad,expected)
for i in range(16):
    bad=bytearray(expected);bad[-16+i]^=1;reject(key,nonce,aad,bytes(bad));reject(key,nonce,aad,bytes(bad),'decrypt_with_workers',4)
reject(bytes([key[0]^1])+key[1:],nonce,aad,expected);reject(key,nonce,bytes([aad[0]^1])+aad[1:],expected)
lengths=[0,1,15,16,17,31,32,33,63,64,65]
cases=list(itertools.product(lengths,lengths))
cases += [(n,65) for n in [65535,65536,65537,262143,262144,262145,1048575,1048576,1048577,16777215,16777216]]
for length,alength in cases:
    key=deterministic(32,31);nonce=deterministic(24,(length+alength)%256);aad=deterministic(alength,23);data=deterministic(length,67)
    expected=nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(data,aad,nonce,key)
    check(encrypt(key,nonce,aad,data)==expected,'libsodium byte comparison')
    check(go(key,nonce,aad,data)==expected,'Go byte comparison')
    check(encrypt(key,nonce,aad,data,'cryptopp_encrypt')==expected,'independent Crypto++')
    check(encrypt(key,nonce,aad,data,'encrypt_serial')==expected,'scalar reference')
    roundtrip(key,nonce,aad,data,expected);roundtrip(key,nonce,aad,data,expected,in_place=True)
    if length in [0,65,262145,1048577,16777216]:
        for workers in [1,2,3,4,7,8,16,32,64]:
            check(encrypt(key,nonce,aad,data,'encrypt_with_workers',workers)==expected,'test worker byte comparison')
            check(encrypt(key,nonce,aad,data,'encrypt',workers)==expected,'product budget byte comparison')
            roundtrip(key,nonce,aad,data,expected,'decrypt',workers)
            roundtrip(key,nonce,aad,data,expected,'decrypt_with_workers',workers)
    # in-place encrypt
    k,n,a=map(buf,[key,nonce,aad]);ip=buf(data);tag=buf(bytes(16))
    check(funcs['encrypt'](k,32,n,24,a,len(aad),ip,len(data),ip,len(data),tag,16,1)==0 and ip.raw[:len(data)]+tag.raw==expected,'in-place encrypt')
# Deterministic randomized differential corpus; each record is at most 8 KiB.
# Public seed permits reproduction without storing keys/plaintexts or large files.
fuzz=random.Random(0x4b565f563133)
for i in range(args.fuzz_cases):
    key=fuzz.randbytes(32);nonce=fuzz.randbytes(24);aad=fuzz.randbytes(fuzz.randrange(129));data=fuzz.randbytes(fuzz.randrange(8193))
    expected=nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(data,aad,nonce,key)
    actual=encrypt(key,nonce,aad,data)
    check(actual==expected==go(key,nonce,aad,data),'randomized libsodium/Go comparison')
    if i % 32 == 0:
        check(encrypt(key,nonce,aad,data,'cryptopp_encrypt')==expected,'randomized independent Crypto++')
        roundtrip(key,nonce,aad,data,expected,in_place=True)
        bad=bytearray(expected);bad[-1]^=1;reject(key,nonce,aad,bytes(bad))
# Native invalid-length/alias preflight uses tiny sentinels, no oversized allocation.
k,n,a=map(buf,[bytes(32),bytes(24),bytes(17)]);inp=buf(bytes(128));out=buf(b'\xa5'*128);tag=buf(b'\xa7'*16)
base=[k,32,n,24,a,17,inp,64,out,128,tag,16,1]
for pos,values in [(1,[0,31,33]),(3,[0,12,23,25]),(7,[16777217,2**32]),(9,[0,63]),(11,[0,15,17]),(12,[0])]:
    for value in values:
        params=base.copy();params[pos]=value
        check(funcs['encrypt'](*params)==1 and out.raw==b'\xa5'*128 and tag.raw==b'\xa7'*16,'invalid native length')
for pos in [0,2,4,6,8,10]:
    params=base.copy();params[pos]=None
    check(funcs['encrypt'](*params)==1,'null pointer preflight')
for pos,address in [(8,C.addressof(inp)+1),(8,C.addressof(k)),(10,C.addressof(out)+1),(8,C.addressof(a))]:
    params=base.copy();params[pos]=address
    check(funcs['encrypt'](*params)==1 and out.raw==b'\xa5'*128,'partial or protected alias')
# Raw IETF counter boundary seam; no product legacy AEAD.
raw=lib.keepvault_test_chacha20_xcrypt;raw.argtypes=[P,P,U,P,P,Z];raw.restype=C.c_int
check(raw(k,n,2**32-1,inp,out,64)==0,'last raw block valid');out=buf(b'\xa5'*128)
check(raw(k,n,2**32-1,inp,out,65)==4 and out.raw==b'\xa5'*128,'raw counter refusal')
for forbidden in ['chacha20poly1305_encrypt','chacha20poly1305_decrypt']:
    try:getattr(lib,forbidden);raise AssertionError('legacy product AEAD export present')
    except AttributeError:checks+=1
proc.stdin.close();check(proc.wait()==0,'Go exit')
# Capture binary hash plus pinned reference package/source identities without secrets.
sodium_hash=hashlib.sha256(pathlib.Path(nacl._sodium.__file__).read_bytes()).hexdigest()
report={'status':'PASS','checks':checks,'cases':len(cases),'fuzz_cases':args.fuzz_cases,'seconds':round(time.time()-start,3),'platform':platform.platform(),'architecture':platform.machine(),'library_sha256':hashlib.sha256(pathlib.Path(args.library).read_bytes()).hexdigest(),'pynacl':nacl.__version__,'libsodium':'1.0.20-stable (2025-12-31 build, PyNaCl 1.6.2 metadata)', 'libsodium_binding_sha256':sodium_hash,'go_crypto':'v0.43.0','maximum_payload':16777216,'sources':['https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03','https://github.com/pyca/pynacl/tree/1.6.2','https://pkg.go.dev/golang.org/x/crypto@v0.43.0/chacha20poly1305']}
print(json.dumps(report,indent=2))
if args.report:pathlib.Path(args.report).write_text(json.dumps(report,indent=2)+'\n')
