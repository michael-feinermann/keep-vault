#!/usr/bin/env python3
"""Bounded actual v13 ABI versus independent BC 2.6.2 block-based CTR.
Only public reproducible fixtures; no key material from the release store.
"""
import argparse,base64,ctypes as C,hashlib,json,pathlib,platform,random,subprocess,time
parser=argparse.ArgumentParser();parser.add_argument('directory');parser.add_argument('--oracle',required=True);parser.add_argument('--dotnet',default='dotnet');parser.add_argument('--report');parser.add_argument('--max-size',type=int,default=16777216);parser.add_argument('--fuzz-cases',type=int,default=10000);args=parser.parse_args()
P=C.c_void_p;Z=C.c_size_t;U=C.c_uint32;root=pathlib.Path(args.directory);checks=0;start=time.time();artifacts={}
proc=subprocess.Popen([args.dotnet,args.oracle],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
def check(ok,message):
 global checks
 assert ok,message
 checks+=1
def buf(data):return C.create_string_buffer(data,max(1,len(data)))
def oracle(cipher,key,nonce,data):
 req={'Algorithm':cipher,**{k:base64.b64encode(v).decode() for k,v in [('Key',key),('Nonce',nonce),('Input',data)]}}
 proc.stdin.write(json.dumps(req)+'\n');proc.stdin.flush();result=json.loads(proc.stdout.readline());check(not result['Error'],'BC status');return base64.b64decode(result['Output'])
fixtures=json.loads(pathlib.Path(__file__).with_name('camellia-serpent-vectors.json').read_text())
for cipher in ['camellia','serpent']:
 path=root/f'lib{cipher}_v13.dylib';artifacts[path.name]=hashlib.sha256(path.read_bytes()).hexdigest();lib=C.CDLL(str(path.resolve()))
 block=getattr(lib,f'keepvault_test_v13_{cipher}_256_encrypt_block');block.argtypes=[P,Z,P,Z,P,Z];block.restype=C.c_int
 ctr=getattr(lib,f'keepvault_v13_{cipher}_256_ctr_xcrypt');ctr.argtypes=[P,Z,P,Z,P,Z,P,Z,U];ctr.restype=C.c_int
 def crypt(key,nonce,data,workers=1,inplace=False):
  k,n,i=map(buf,[key,nonce,data]);o=i if inplace else buf(b'\xa5'*len(data));check(ctr(k,32,n,16,i,len(data),o,len(data),workers)==0,'CTR status');return o.raw[:len(data)]
 for vector in fixtures[cipher]:
  key=bytes.fromhex(vector['key']);data=bytes.fromhex(vector['input']);expected=bytes.fromhex(vector['output']);value=data
  for _ in range(vector.get('iterations',1)):
   out=buf(bytes(16));check(block(buf(key),32,buf(value),16,out,16)==0,'block KAT status');value=out.raw
  check(value==expected,vector['source'])
  if vector.get('iterations',1)==1:check(oracle(cipher,key,data,bytes(16))==expected,'BC block KAT')
 lengths=[0,1,15,16,17,31,32,33,63,64,65,65535,65536,65537,131071,131072,131073,262143,262144,262145,524287,524288,524289,1048575,1048576,1048577,16777215,16777216]
 for length in [n for n in lengths if n<=args.max_size]:
  key=bytes(range(32));nonce=bytes(range(16));data=(bytes(range(256))*((length+255)//256))[:length];expected=oracle(cipher,key,nonce,data)
  for workers in ([1,2,3,5,10] if length>=1048576 else [1,10,4096]):
   actual=crypt(key,nonce,data,workers);check(actual==expected,'BC CTR equality');check(crypt(key,nonce,actual,workers,True)==data,'exact inplace decrypt')
  check(crypt(key,nonce,data,1,True)==expected,'exact inplace encrypt')
 # Counter carries across byte, UInt32, UInt64; two full blocks and a tail.
 for nonce in [bytes.fromhex(x) for x in ['00'*15+'ff','00'*12+'ffffffff','00'*8+'ffffffffffffffff']]:
  data=bytes(range(33));check(crypt(key,nonce,data)==oracle(cipher,key,nonce,data),'full-width counter carry')
 nonce=b'\xff'*16;check(crypt(key,nonce,bytes(16))==oracle(cipher,key,nonce,bytes(16)),'last counter block')
 out=buf(b'\xa5'*128);check(ctr(buf(key),32,buf(nonce),16,buf(bytes(128)),17,out,128,1)==4 and out.raw==b'\xa5'*128,'counter overflow before output')
 # Invalid lengths/pointers/aliases before output. Zero workers invalid; high grant
 # valid on short inputs without creating thousands of OS threads.
 k,n,i,o=map(buf,[key,bytes(16),bytes(128),b'\xa5'*128]);base=[k,32,n,16,i,64,o,128,1]
 for position,values in [(1,[0,31,33]),(3,[0,15,17]),(5,[16777217,2**32]),(7,[0,63]),(8,[0])]:
  for value in values:
   v=base.copy();v[position]=value;check(ctr(*v)==1 and o.raw==b'\xa5'*128,'native length preflight')
 for position in [0,2,4,6]:
  v=base.copy();v[position]=None;check(ctr(*v)==1,'null preflight')
 for address in [C.addressof(i)+1,C.addressof(k),C.addressof(n)]:
  v=base.copy();v[6]=address;check(ctr(*v)==1 and o.raw==b'\xa5'*128,'alias preflight')
 check(ctr(k,32,n,16,None,0,None,0,1)==0,'explicit empty range contract')
 # Fixed public seed, at most 256 bytes per randomized record.
 rng=random.Random(0x56313343414d if cipher=='camellia' else 0x563133534552)
 for index in range(args.fuzz_cases):
  key=rng.randbytes(32);nonce=rng.randbytes(16);data=rng.randbytes(rng.randrange(257));check(crypt(key,nonce,data)==oracle(cipher,key,nonce,data),'randomized independent BC CTR')
proc.stdin.close();check(proc.wait()==0,'oracle exit')
report={'status':'PASS','checks':checks,'fuzz_cases_per_cipher':args.fuzz_cases,'maximum_payload':args.max_size,'seconds':round(time.time()-start,3),'architecture':platform.machine(),'artifacts':artifacts,'reference':'BouncyCastle.Cryptography 2.6.2; independently encoded full-width big-endian CTR','vector_sources':fixtures['sources'],'limitations':'Primitive/ABI test, not installed artifact trust or universal side-channel attestation.'}
print(json.dumps(report,indent=2))
if args.report:pathlib.Path(args.report).write_text(json.dumps(report,indent=2)+'\n')
