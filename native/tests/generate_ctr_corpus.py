#!/usr/bin/env python3
"""Public independent BC 2.6.2 fixtures for native x64/sanitizer runners."""
import argparse,base64,json,pathlib,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('output');p.add_argument('--oracle',required=True);p.add_argument('--dotnet',default='dotnet');a=p.parse_args()
lengths=[0,1,15,16,17,31,32,33,63,64,65,65535,65536,65537,131071,131072,131073,262143,262144,262145,524287,524288,524289,1048575,1048576,1048577,16777216]
proc=subprocess.Popen([a.dotnet,a.oracle],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
with open(a.output,'wb') as f:
 f.write(b'KV13CTR1'+struct.pack('<I',len(lengths)*2))
 for algorithm,cipher in enumerate(['camellia','serpent']):
  for length in lengths:
   key=bytes(range(32));nonce=bytes(range(16));data=(bytes(range(256))*((length+255)//256))[:length]
   proc.stdin.write(json.dumps({'Algorithm':cipher,**{k:base64.b64encode(v).decode() for k,v in [('Key',key),('Nonce',nonce),('Input',data)]}})+'\n');proc.stdin.flush()
   result=json.loads(proc.stdout.readline());assert not result['Error'];expected=base64.b64decode(result['Output']);assert len(expected)==length
   f.write(struct.pack('<BI',algorithm,length)+key+nonce+data+expected)
proc.stdin.close();assert proc.wait()==0
print(json.dumps({'records':len(lengths)*2,'bytes':pathlib.Path(a.output).stat().st_size,'reference':'BouncyCastle.Cryptography 2.6.2 independent big-endian CTR'}))
