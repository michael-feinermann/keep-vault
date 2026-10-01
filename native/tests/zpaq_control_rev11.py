#!/usr/bin/env python3
"""Public <=2 MiB native protocol fixture. No installed anchor or release claim."""
import argparse, hashlib, json, os, pathlib, socket, struct, subprocess, tempfile, threading, time, traceback
H=struct.Struct('>8sIIQQQQ'); MAGIC=b'KV13CTL1'
def exact(stream,n):
    b=bytearray()
    while len(b)<n:
        q=stream.recv(n-len(b)) if hasattr(stream,'recv') else stream.read(n-len(b))
        if not q: raise EOFError()
        b.extend(q)
    return bytes(b)
class Control:
    def __init__(self,root,entries,fault=None):
        self.path=str(root/'control');self.listener=socket.socket(socket.AF_UNIX);self.listener.bind(self.path);self.listener.listen(1)
        self.fault=fault;self.fault_once=False;self.source_wait=threading.Event();self.source_resume=threading.Event();self.entries=entries;self.cv=threading.Condition();self.write=threading.Lock();self.cpu=set();self.mem={};self.windows={};self.pending=[];self.errors=[];self.counts={};self.peak_cpu=0;self.peak_memory=0;self.written=0;self.closed=False
    def parent_hash(self,b):
        with self.cv:
            self.cv.wait_for(lambda:not self.cpu);self.cpu.add('parent');self.peak_cpu=max(self.peak_cpu,len(self.cpu))
        try:return hashlib.sha256(b).digest()
        finally:
            with self.cv:self.cpu.remove('parent');self.cv.notify_all()
    def start(self):
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def run(self):
        try:
            self.connection,_=self.listener.accept();last=0
            while True:
                h=exact(self.connection,48);magic,kind,n,seq,a,b,c=H.unpack(h)
                assert magic==MAGIC and n==0 and seq>last and 1<=kind<=10
                last=seq;self.counts[kind]=self.counts.get(kind,0)+1
                if kind==9:
                    for t in self.pending:t.join(5);assert not t.is_alive()
                    assert not self.cpu and not self.mem and not self.windows
                    self.reply(kind,seq);self.closed=True
                    assert self.connection.recv(1)==b'';break
                t=threading.Thread(target=self.handle,args=(kind,seq,a,b,c),daemon=True);self.pending.append(t);t.start()
        except BaseException as e:self.errors.append(traceback.format_exc())
        finally:
            if hasattr(self,'connection'):self.connection.close()
            self.listener.close()
    def reply(self,k,s,a=0,payload=b''):
        with self.write:
            if not self.fault_once and k==1 and self.fault in ('wrong-sequence','oversize-reply'):
                self.fault_once=True
                self.connection.sendall(H.pack(MAGIC,k|0x80000000,1048577 if self.fault=='oversize-reply' else 0,s+1 if self.fault=='wrong-sequence' else s,a,0,0));return
            self.connection.sendall(H.pack(MAGIC,k|0x80000000,len(payload),s,a,0,0)+payload)
    def handle(self,k,s,a,b,c):
        try:
            payload=b'';answer=0
            if k==1:
                assert (a,b,c)==(0,0,0)
                with self.cv:
                    self.cv.wait_for(lambda:not self.cpu);self.cpu.add(s);self.peak_cpu=max(self.peak_cpu,len(self.cpu))
                answer=s
            elif k==2:
                with self.cv:self.cpu.remove(a);self.cv.notify_all()
            elif k==3:
                if a<len(self.entries):
                    name,data,directory=self.entries[a];name=name.encode();mode=0o40700 if directory else 0o100600
                    payload=struct.pack('>QQQQII',a,len(data),20261001000000,(mode<<8)|ord('u'),directory,len(name))+name
                else:assert a==len(self.entries)
            elif k==4:
                assert 0<c<=1048576;data=self.entries[a][1];assert b+c<=len(data)
                payload=data[b:b+c];self.parent_hash(payload)
                if self.fault=='short-source':payload=payload[:-1]
                if self.fault=='stall-source':self.source_wait.set();self.source_resume.wait(10)
            elif k==5:assert a in(1,2) and c==0
            elif k==6:
                if self.fault=='deny-output':raise IOError('injected output authorization failure')
                assert a==c==0 and 0<b<=65536
                with self.cv:self.windows[s]=b
                answer=s
            elif k==7:
                assert 0<a<=2<<30 and b==c==0
                with self.cv:self.mem[s]=a;self.peak_memory=max(self.peak_memory,sum(self.mem.values()))
                answer=s
            elif k==8:
                with self.cv:self.mem.pop(a)
            elif k==10:
                with self.cv:limit=self.windows.pop(a);assert b<=limit;self.written+=b
            else:raise AssertionError(k)
            self.reply(k,s,answer,payload)
        except BaseException:
            self.errors.append(traceback.format_exc())
            try:self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:pass
    def finish(self):
        self.thread.join(8);assert not self.thread.is_alive(), 'control join timeout'
        assert not self.errors,self.errors;assert self.closed and self.peak_cpu<=1
        return dict(frames=self.counts,peak_cpu=self.peak_cpu,peak_model_bytes=self.peak_memory,write_bytes=self.written)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('binary');ap.add_argument('--report',required=True);ap.add_argument('--level',type=int,choices=range(6),default=0);args=ap.parse_args();binary=str(pathlib.Path(args.binary).resolve());results=[]
    data=(bytes(range(256))*8192) # exactly 2 MiB, generated public bytes
    entries=[('tree/',b'',1),('tree/empty/',b'',1),('tree/.zero',b'',0),('tree/ß-data.bin',data,0)]
    with tempfile.TemporaryDirectory(prefix='kvctl-test-',dir='/private/tmp') as tmp:
        base=pathlib.Path(tmp);archives={}
        for form in ('plain','pipe'):
            root=base/form;root.mkdir();ctl=Control(root,entries);ctl.start();archive=root/'public.zpaq'
            methods=['s4','s4.1.5.0.3.22','s4.1.4.0.8.25','s4.2.12.0.8.25c0.0.511.255','s4.3ci1','s4.0ci1.1.1.1.2am']
            command=[binary]+(['--pipe','add','-','-method',methods[args.level]] if form=='pipe' else ['add',str(archive),'-m'+str(args.level)])
            command+=['-threads','1','-kv-queue-slots','1','-kv-memory-budget',str(2<<30),'-kv-base-memory',str(256<<20),'-kv-bound-sources','-kv-control',ctl.path,str(os.getpid())]
            p=subprocess.run(command,cwd=root,capture_output=True,timeout=45)
            assert p.returncode==0,(command,p.returncode,p.stderr.decode(errors='replace'))
            blob=p.stdout if form=='pipe' else archive.read_bytes();archives[form]=blob
            results.append(dict(test=form+'-add',exit=p.returncode,archive_bytes=len(blob),sha256=hashlib.sha256(blob).hexdigest(),**ctl.finish()))
            dest=root/'extract';dest.mkdir();controlroot=root/'extract-control';controlroot.mkdir();ctle=Control(controlroot,[]);ctle.start();st=dest.stat()
            command=[binary,'--pipe' if form=='pipe' else '--verified-read-at','extract','-','-threads','1','-kv-queue-slots','1','-kv-memory-budget',str(2<<30),'-kv-base-memory',str(384<<20),'-kv-max-total',str(4<<20),'-kv-max-file',str(4<<20),'-kv-root-dev',str(st.st_dev),'-kv-root-ino',str(st.st_ino),'-kv-control',ctle.path,str(os.getpid())]
            if form=='pipe':p=subprocess.run(command,cwd=dest,input=blob,capture_output=True,timeout=45)
            else:
                p=subprocess.Popen(command,cwd=dest,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                def serve():
                    try:
                        p.stdin.write(b'KV13RA\0\0'+struct.pack('>Q',len(blob)));p.stdin.flush()
                        while True:
                            off,n=struct.unpack('>QI',exact(p.stdout,12));assert n<=1048576 and off+n<=len(blob)
                            ctle.parent_hash(blob[off:off+n]);p.stdin.write(blob[off:off+n]);p.stdin.flush()
                    except EOFError:pass
                    finally:p.stdin.close()
                server=threading.Thread(target=serve,daemon=True);server.start();p.wait(timeout=45);server.join(5);p.stderr=p.stderr.read()
            assert p.returncode==0,(command,p.returncode,p.stderr)
            assert (dest/'tree/ß-data.bin').read_bytes()==data and (dest/'tree/empty').is_dir() and (dest/'tree/.zero').stat().st_size==0
            results.append(dict(test=form+'-extract',exit=p.returncode,**ctle.finish()))
    negatives=[]
    for fault in ('wrong-sequence','oversize-reply','short-source','deny-output','stall-source'):
        with tempfile.TemporaryDirectory(prefix='kvctl-negative-',dir='/private/tmp') as tmp:
            root=pathlib.Path(tmp);ctl=Control(root,entries,fault);ctl.start()
            command=[binary,'add',str(root/'partial.zpaq'),'-m0','-threads','1','-kv-queue-slots','1','-kv-memory-budget',str(2<<30),'-kv-base-memory',str(256<<20),'-kv-bound-sources','-kv-control',ctl.path,str(os.getpid())]
            p=subprocess.Popen(command,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if fault=='stall-source':
                assert ctl.source_wait.wait(10),'source request was not reached'
                time.sleep(.35);assert p.poll() is None,'product terminated silently stalled work'
                p.kill();ctl.source_resume.set()
            out,err=p.communicate(timeout=15)
            assert p.returncode!=0,(fault,'invalid protocol reported success')
            assert b'ERROR: AddressSanitizer' not in err and b'runtime error:' not in err,(fault,err.decode(errors='replace'))
            # The child is now confirmed gone. Only now can the harness revoke
            # owners from failed requests and wake its own test threads.
            with ctl.cv:ctl.cpu.clear();ctl.mem.clear();ctl.windows.clear();ctl.cv.notify_all()
            ctl.source_resume.set();ctl.thread.join(5)
            assert not ctl.thread.is_alive(),(fault,'control reader was not joined')
            for t in ctl.pending:t.join(5);assert not t.is_alive(),(fault,'control handler was not joined')
            negatives.append(dict(test=fault,exit=p.returncode,joined=True,normal_success=False))
    pathlib.Path(args.report).write_text(json.dumps(dict(scope='isolated native protocol fixture, not installed/release evidence',binary_sha256=hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest(),input_bytes=len(data),compression_level=args.level,results=results,negative=negatives),indent=2)+'\n')
    print(json.dumps(results))
if __name__=='__main__':main()
