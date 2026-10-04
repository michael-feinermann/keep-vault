#!/usr/bin/env python3
"""PROPOSAL ONLY: build and exercise unmodified native KV13CTL1 parser.

Nothing in this proposal has been compiled or executed during the pinned matrix.
Use one --mode at a time after it ends. Protocol oracle does not call production
get/put or the managed control codec. All frames and diagnostics are public.
"""
import argparse, hashlib, json, os, pathlib, platform, queue, random, shlex, socket, struct, sys
import subprocess, tempfile, threading, time

MAGIC=b'KV13CTL1'
HEADER=struct.Struct('>8sIIQQQQ')
FLAG=0x80000000
MAX=1<<20
CASES=10000
SEED=0x4b56313343544c31
MODES=('valid','fragmented','magic','flag','kind','sequence','oversize','short-header',
       'short-payload','duplicate','magic-tail','unknown-kind','close-field',
       'close-payload','reverse-two','big-boundary')

class OracleFailure(Exception): pass

def require(condition,label):
    if not condition: raise OracleFailure(label)

def sha(path):
    digest=hashlib.sha256()
    with open(path,'rb') as stream:
        for block in iter(lambda:stream.read(1<<20),b''): digest.update(block)
    return digest.hexdigest()

def snapshot(paths):
    result={}
    for raw in sorted(set(map(str,paths))):
        p=pathlib.Path(raw);s=p.stat()
        result[raw]={'sha256':sha(p),'resolved':str(p.resolve()),'bytes':s.st_size,
                     'dev':s.st_dev,'ino':s.st_ino,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns}
    return result

def fixtures():
    rng=random.Random(SEED)
    special=(0,1,(1<<32)-1,1<<32,(1<<63)-1,1<<63,(1<<64)-1)
    cases=[]
    for index in range(CASES):
        mode=MODES[index%len(MODES)];kind=1+index%10
        values=[special[(index+j)%len(special)] if index<224 else rng.getrandbits(64) for j in range(6)]
        a,b,c,ra,rb,rc=values;length=rng.randrange(257);pattern=rng.getrandbits(64)
        action=0
        if mode=='reverse-two': action=3;kind=4
        elif mode in ('close-field','close-payload') or kind==9:
            action=1;kind=9;a=b=c=ra=rb=rc=0;length=0
        if mode=='duplicate': action=2;kind=4
        if mode=='big-boundary': length=(0,1,MAX-1,MAX)[(index//16)%4]
        if mode=='close-payload': length=1
        reject=mode not in ('valid','fragmented','reverse-two','big-boundary')
        # Ordinary close probes require the canonical zero/empty acknowledgment.
        if action==1 and mode not in ('close-field','close-payload'): length=0
        cases.append(dict(index=index,mode=mode,action=action,kind=kind,a=a,b=b,c=c,
                          ra=ra,rb=rb,rc=rc,length=length,pattern=pattern,reject=int(reject)))
    return cases

def payload(case):
    block=bytes((case['pattern']+j*73)&255 for j in range(256))
    return (block*((case['length']+255)//256))[:case['length']]

def instruction(case):
    keys=('index','action','kind','a','b','c','ra','rb','rc','length','pattern','reject')
    return (' '.join(str(case[k]) for k in keys)+'\n').encode()

def receive_exact(connection,count,allow_empty=False):
    data=bytearray()
    while len(data)<count:
        block=connection.recv(count-len(data))
        if not block:
            if allow_empty and not data:return None
            raise OracleFailure('native request ended inside its actual frame')
        data.extend(block)
    return bytes(data)

def read_request(connection,digest):
    raw=receive_exact(connection,HEADER.size,True)
    if raw is None:return None
    digest.update(raw)
    magic,kind,size,sequence,a,b,c=HEADER.unpack(raw)
    require(magic==MAGIC and size==0 and 1<=kind<=10 and sequence>0,'native request violates independent wire norm')
    return dict(kind=kind,sequence=sequence,a=a,b=b,c=c,raw=raw)

def verify_request(request,case,sequence,variant=0,close=False):
    fields=(9,sequence,0,0,0) if close else (case['kind'],sequence,case['a']^variant,case['b'],case['c'])
    expected=HEADER.pack(MAGIC,fields[0],0,*fields[1:])
    require(request['raw']==expected,'actual native request differs byte-for-byte from independent fixture')

def reply(case,request,variant=0,close=False):
    data=b'' if close else payload(case)
    a,b,c=(0,0,0) if close else (case['ra']^variant,case['rb'],case['rc'])
    return HEADER.pack(MAGIC,request['kind']|FLAG,len(data),request['sequence'],a,b,c)+data

def send_response(connection,wire,digest,fragment=False):
    digest.update(wire)
    if fragment:
        for start in range(0,min(len(wire),67),3):connection.sendall(wire[start:min(start+3,67)])
        if len(wire)>67:connection.sendall(wire[67:])
    else: connection.sendall(wire)

def serve_case(connection,case,input_wire,output_wire):
    first=read_request(connection,input_wire);require(first is not None,'native child omitted first request')
    if case['action']==3:
        second=read_request(connection,input_wire);require(second is not None,'native child omitted concurrent request')
        variants=[first['a']^case['a'],second['a']^case['a']]
        require(set(variants)=={1,2},'concurrent requests lost independent caller identities')
        verify_request(first,case,1,variants[0]);verify_request(second,case,2,variants[1])
        send_response(connection,reply(case,second,variants[1]),output_wire,True)
        send_response(connection,reply(case,first,variants[0]),output_wire,True)
        next_sequence=3
    else:
        verify_request(first,case,1)
        wire=reply(case,first);mode=case['mode'];next_sequence=2
        if mode in ('magic','magic-tail'):
            position=(case['index']//len(MODES))%8 if mode=='magic' else 7
            wire=wire[:position]+bytes([wire[position]^1])+wire[position+1:]
        elif mode=='flag': wire=wire[:8]+struct.pack('>I',first['kind'])+wire[12:]
        elif mode in ('kind','unknown-kind'):
            wrong=(1+(first['kind']%10))|FLAG if mode=='kind' else 0xffffffff
            wire=wire[:8]+struct.pack('>I',wrong)+wire[12:]
        elif mode=='sequence': wire=wire[:16]+struct.pack('>Q',(0,2,(1<<64)-1)[case['index']%3])+wire[24:]
        elif mode=='oversize': wire=wire[:12]+struct.pack('>I',MAX+1)+wire[16:48]
        elif mode=='close-field': wire=wire[:24]+struct.pack('>Q',1)+wire[32:]
        if mode=='short-header':
            send_response(connection,wire[:(case['index']//len(MODES))%48],output_wire);connection.shutdown(socket.SHUT_WR)
        elif mode=='short-payload':
            data=payload(case) or b'x';wire=HEADER.pack(MAGIC,first['kind']|FLAG,len(data),1,case['ra'],case['rb'],case['rc'])+data[:-1]
            send_response(connection,wire,output_wire);connection.shutdown(socket.SHUT_WR)
        elif mode=='duplicate':
            # Both replies precede any reply to the subsequent request.
            send_response(connection,wire+wire,output_wire)
        else: send_response(connection,wire,output_wire,mode=='fragmented')
    # A successful first finish must itself remain the sole close request.
    # Failed close semantics may legitimately issue one subsequent cleanup close.
    close_seen=case['action']==1 and not case['reject']
    duplicate_probe_seen=False
    while True:
        request=read_request(connection,input_wire)
        if request is None:break
        if case['mode']=='duplicate' and request['kind']!=9:
            require(not duplicate_probe_seen,'duplicate probe emitted more than one subsequent request')
            duplicate_probe_seen=True
            verify_request(request,case,next_sequence);next_sequence+=1
            # The duplicate must already fail the receiver. No successful reply
            # is supplied to this next probe; native shutdown must reach EOF.
            continue
        require(not close_seen,'non-idempotent native close emitted another request')
        verify_request(request,case,next_sequence,close=True);next_sequence+=1;close_seen=True
        try:send_response(connection,reply(case,request,close=True),output_wire)
        except BrokenPipeError:
            require(case['reject'],'valid probe closed during acknowledgment')
    require(case['reject'] or close_seen,'valid native probe omitted its actual close acknowledgment')
    return close_seen

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=('arm64','x86_64','asan-ubsan','tsan'),required=True)
    parser.add_argument('--source-root',type=pathlib.Path,default=pathlib.Path.cwd())
    parser.add_argument('--output-dir',type=pathlib.Path,required=True)
    parser.add_argument('--report',type=pathlib.Path,required=True)
    args=parser.parse_args();root=args.source_root.resolve();out=args.output_dir.resolve()
    require(out.is_relative_to(root/'work'),'proposal outputs must stay in ignored work')
    require(args.report.resolve().is_relative_to(out),'report must stay under selected work output')
    out.mkdir(parents=True,exist_ok=False) # never overwrite an earlier receipt
    report={'status':'NOT RUN','scope':'isolated actual native KV13CTL1 control_channel framing; no product patch or installed release proof',
            'mode':args.mode,'seed':hex(SEED),'cases_expected':CASES,'cases_completed':0,
            'limitations':['not complete source_entry metadata semantics','not full CPU/memory grant lifecycle',
                            'not private UINT64 sequence exhaustion or thread-start fault injection',
                            'macOS only','LeakSanitizer disabled; no leak-free claim',
                            'SDK binding covers actual dependency headers and descriptor, not every linker/runtime component']}
    process=None;stderr_chunks=[];stderr_thread=None;stdout_thread=None
    stdout_messages=queue.Queue(maxsize=256);stdout_errors=[];stderr_errors=[];before={};after={}
    input_wire=None;output_wire=None;semantic=None;stderr_bytes_seen=0
    try:
        compiler=subprocess.check_output(['/usr/bin/xcrun','--find','clang++'],text=True,timeout=30).strip()
        sdk=subprocess.check_output(['/usr/bin/xcrun','--sdk','macosx','--show-sdk-path'],text=True,timeout=30).strip()
        report['compiler_version']=subprocess.check_output([compiler,'--version'],text=True,timeout=30)
        report['sdk_version']=subprocess.check_output(['/usr/bin/xcrun','--sdk','macosx','--show-sdk-version'],text=True,timeout=30).strip()
        report['host']=platform.platform();report['python_version']=sys.version
        source=pathlib.Path(__file__).with_name('control_framing_fuzz.cpp').resolve()
        arch='x86_64' if args.mode=='x86_64' else 'arm64'
        flags=['-std=c++17','-Wall','-Wextra','-Wpedantic','-Werror','-pthread','-arch',arch,'-isysroot',sdk,'-I'+str(root/'native')]
        flags+=['-O2','-DNDEBUG'] if args.mode in ('arm64','x86_64') else ['-O1','-g','-fno-omit-frame-pointer','-fsanitize='+('thread' if args.mode=='tsan' else 'address,undefined')]
        dependency_command=[compiler,*flags,'-M','-MT','control_framing',str(source)]
        dependency=subprocess.run(dependency_command,text=True,capture_output=True,check=True,timeout=60)
        raw=dependency.stdout.replace('\\\n',' ');require(':' in raw,'compiler omitted dependency receipt')
        dependencies=[pathlib.Path(x) for x in shlex.split(raw.split(':',1)[1])]
        captured=[*dependencies,pathlib.Path(compiler),pathlib.Path(sdk)/'SDKSettings.json',pathlib.Path(sys.executable),pathlib.Path(__file__).resolve()]
        before=snapshot(captured);report['inputs_before']=before
        binary=out/('control-framing-'+args.mode)
        command=[compiler,*flags,str(source),'-o',str(binary)]
        report['dependency_command']=dependency_command;report['compile_command']=command
        build=subprocess.run(command,text=True,capture_output=True,timeout=120)
        (out/'build.stdout.txt').write_text(build.stdout);(out/'build.stderr.txt').write_text(build.stderr)
        require(build.returncode==0,'proposal harness did not compile');report['binary_sha256_before']=sha(binary)
        corpus=fixtures();corpus_bytes=b''.join((json.dumps(c,sort_keys=True,separators=(',',':'))+'\n').encode() for c in corpus)
        (out/'corpus.ndjson').write_bytes(corpus_bytes);report['corpus_sha256']=hashlib.sha256(corpus_bytes).hexdigest()
        report['expected_accepted']=sum(not c['reject'] for c in corpus)
        report['expected_rejected']=sum(bool(c['reject']) for c in corpus)
        report['expected_semantic_output_sha256']=hashlib.sha256(b''.join(('CONTROL_FUZZ_CASE '+str(c['index'])+' '+str(c['reject'])+'\n').encode() for c in corpus)).hexdigest()
        input_wire=hashlib.sha256();output_wire=hashlib.sha256();semantic=hashlib.sha256()
        with tempfile.TemporaryDirectory(prefix='kvctl10k-',dir='/private/tmp') as temporary, socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
            address=str(pathlib.Path(temporary)/'socket')
            listener.bind(address);listener.listen(1);listener.settimeout(5)
            env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1',TSAN_OPTIONS='halt_on_error=1')
            start=time.monotonic();process=subprocess.Popen([str(binary),address,str(os.getpid())],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
            def drain_stderr():
                nonlocal stderr_bytes_seen
                try:
                    for block in iter(lambda:process.stderr.read(16384),b''):
                        remaining=max(0,(1<<20)-stderr_bytes_seen)
                        if remaining:stderr_chunks.append(block[:remaining])
                        stderr_bytes_seen+=len(block)
                except BaseException as failure:stderr_errors.append(type(failure).__name__+': '+str(failure))
            def drain_stdout():
                try:
                    while True:
                        marker=process.stdout.readline(256)
                        stdout_messages.put(marker or None,timeout=1)
                        if not marker:break
                except BaseException as failure:stdout_errors.append(type(failure).__name__+': '+str(failure))
            def marker_with_deadline():
                require(not stdout_errors,'stdout observer failed')
                try:return stdout_messages.get(timeout=5)
                except queue.Empty:raise OracleFailure('native completion exceeded five-second test deadline')
            stderr_thread=threading.Thread(target=drain_stderr);stderr_thread.start()
            stdout_thread=threading.Thread(target=drain_stdout);stdout_thread.start()
            for case in corpus:
                report['current_case']=case['index'];report['current_case_mode']=case['mode']
                process.stdin.write(instruction(case));process.stdin.flush()
                connection,_=listener.accept();connection.settimeout(5)
                with connection: serve_case(connection,case,input_wire,output_wire)
                marker=marker_with_deadline()
                expected=('CONTROL_FUZZ_CASE '+str(case['index'])+' '+str(case['reject'])+'\n').encode()
                require(marker==expected,'native case did not complete exact norm verdict and destructor join')
                semantic.update(marker);report['cases_completed']+=1
            process.stdin.close();require(marker_with_deadline()==b'CONTROL_FUZZ_COMPLETE 10000\n','native corpus completion marker missing')
            require(process.wait(timeout=5)==0,'native child failed after completed corpus')
            require(marker_with_deadline() is None,'native child emitted unexpected completion suffix')
            stdout_thread.join(5);require(not stdout_thread.is_alive() and not stdout_errors,'stdout observer did not join cleanly')
            stderr_thread.join(5);require(not stderr_thread.is_alive() and not stderr_errors,'stderr observer did not join cleanly')
            report['seconds']=time.monotonic()-start
        stderr=b''.join(stderr_chunks);(out/'run.stderr.txt').write_bytes(stderr)
        require(not stderr,'native or sanitizer diagnostics were not empty')
        report['input_wire_sha256']=input_wire.hexdigest();report['output_wire_sha256']=output_wire.hexdigest()
        report['actual_semantic_output_sha256']=semantic.hexdigest();report['binary_sha256_after']=sha(binary)
        require(report['actual_semantic_output_sha256']==report['expected_semantic_output_sha256'],'actual complete native verdict transcript differs from independent corpus')
        require(report['binary_sha256_before']==report['binary_sha256_after'],'harness binary changed during run')
        after=snapshot(captured);report['inputs_after']=after;require(before==after,'actual source/compiler/SDK inputs changed')
        report['status']='PASS'
    except BaseException as failure:
        report['status']='FAIL';report['failure_type']=type(failure).__name__;report['failure']=str(failure)
        if process is not None and process.poll() is None:
            process.kill();process.wait(timeout=5) # controlled failing test child, never product/archive work
        if stderr_thread is not None:stderr_thread.join(5)
        if stdout_thread is not None:stdout_thread.join(5)
        if stdout_errors:report['stdout_observer_errors']=stdout_errors
        if stderr_errors:report['stderr_observer_errors']=stderr_errors
        if stderr_chunks:(out/'run.stderr.txt').write_bytes(b''.join(stderr_chunks))
        if before:
            try:report['inputs_after']=snapshot(before)
            except BaseException as changed:report['input_after_error']=str(changed)
    finally:
        report['stderr_bytes_seen']=stderr_bytes_seen
        report['stderr_capture_truncated']=stderr_bytes_seen>(1<<20)
        if input_wire is not None:report['input_wire_sha256']=input_wire.hexdigest()
        if output_wire is not None:report['output_wire_sha256']=output_wire.hexdigest()
        if semantic is not None:report['actual_semantic_output_sha256']=semantic.hexdigest()
        args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('status','mode','seed','cases_completed')}))
    return 0 if report['status']=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())
