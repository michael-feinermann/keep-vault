using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using KalynaArchiver.Services;

internal static unsafe class Program
{
    private readonly record struct Stage(string Name,string Export,int Kind,int KeyBytes,int NonceBytes);
    private static readonly Stage[] Stages = [
        new("aes_ref","aes_256_ctr_xcrypt_v13_with_workers",0,32,16),
        new("mars_ref","mars_448_ctr_xcrypt_v13_with_workers",0,56,16),
        new("camellia_v13","keepvault_v13_camellia_256_ctr_xcrypt",2,32,16),
        new("serpent_v13","keepvault_v13_serpent_256_ctr_xcrypt",2,32,16),
        new("shacal2_ref","shacal2_512_ctr_xcrypt_v13_with_workers",0,64,32),
        new("kalyna_v13","keepvault_v13_kalyna_512_512_ctr_xcrypt_with_workers",0,64,64),
        new("threefish_ref","threefish_1024_ctr_xcrypt_v13_with_workers",1,128,128),
        new("xchachapoly_v13","keepvault_xchacha20poly1305_v13_encrypt_with_budget",3,32,24) ];
    static int Main(string[] args)
    {
        if(args.Length is <2 or >3)throw new ArgumentException("native directory; shared or standalone; optional positive grant");
        bool shared=args[1]=="shared"; if(!shared&&args[1]!="standalone")throw new ArgumentException("executor mode");
        uint[] grants=args.Length==3?[uint.Parse(args[2])]:[1,2,5,10];
        if(grants.Any(grant=>grant==0))throw new ArgumentException("grant must be positive");
        const int Chunk=16*1024*1024,Chunks=16,Repetitions=5;
        nint[] functions=new nint[8];var artifacts=new Dictionary<string,string>();
        for(int i=0;i<8;i++){string path=Path.GetFullPath(Path.Combine(args[0],"lib"+Stages[i].Name+".dylib"));nint lib=NativeLibrary.Load(path);if(shared)NativeCipherExecutor.Install(lib);functions[i]=NativeLibrary.GetExport(lib,Stages[i].Export);artifacts[Path.GetFileName(path)]=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));}
        byte[][] keys=Stages.Select((s,j)=>Enumerable.Range(0,s.KeyBytes).Select(i=>(byte)(i+j*31)).ToArray()).ToArray();
        byte[][] nonces=Stages.Select((s,j)=>Enumerable.Range(0,s.NonceBytes).Select(i=>(byte)(i+j*7)).ToArray()).ToArray();
        byte[] input=new byte[Chunk],buffer=new byte[Chunk],tag=new byte[16],tweak=new byte[16],aad=new byte[36];for(int i=0;i<input.Length;i++)input[i]=(byte)i;
        void Invoke(int stage,uint grant){var s=Stages[stage];fixed(byte* k=keys[stage],n=nonces[stage],b=buffer,t=tweak,a=aad,g=tag){nint f=functions[stage];int rc=s.Kind switch{
            0=>((delegate* unmanaged[Cdecl]<byte*,byte*,byte*,byte*,nuint,uint,int>)f)(k,n,b,b,Chunk,grant),
            1=>((delegate* unmanaged[Cdecl]<byte*,byte*,byte*,byte*,byte*,nuint,uint,int>)f)(k,t,n,b,b,Chunk,grant),
            2=>((delegate* unmanaged[Cdecl]<byte*,nuint,byte*,nuint,byte*,nuint,byte*,nuint,uint,int>)f)(k,32,n,16,b,Chunk,b,Chunk,grant),
            _=>((delegate* unmanaged[Cdecl]<byte*,nuint,byte*,nuint,byte*,nuint,byte*,nuint,byte*,nuint,byte*,nuint,uint,int>)f)(k,32,n,24,a,36,b,Chunk,b,Chunk,g,16,grant)};if(rc!=0)throw new Exception(s.Name+" status "+rc);}}
        var suites=new[]{("Camellia256",new[]{2}),("Serpent256",new[]{3}),("StandardCascade",new[]{0,5,6,7}),("ParanoiaCascade8",new[]{0,1,2,3,4,5,6,7})};var output=new List<object>();
        foreach(var suite in suites){string? golden=null;foreach(uint grant in grants){
            double[] seconds=new double[Repetitions],allocated=new double[Repetitions],cpuSeconds=new double[Repetitions];
            // One whole 256MiB warm-up per case. Fixed public inputs/IVs intentionally
            // exclude KDF, archive nonce derivation, global MAC and I/O from timing.
            for(int repetition=-1;repetition<Repetitions;++repetition){long before=GC.GetTotalAllocatedBytes(true);TimeSpan cpuBefore=Process.GetCurrentProcess().TotalProcessorTime;var sw=Stopwatch.StartNew();for(int chunk=0;chunk<Chunks;chunk++){Buffer.BlockCopy(input,0,buffer,0,Chunk);foreach(int stage in suite.Item2)Invoke(stage,grant);}sw.Stop();long allocationCount=GC.GetTotalAllocatedBytes(true)-before;double cpu=(Process.GetCurrentProcess().TotalProcessorTime-cpuBefore).TotalSeconds;
                using var digest=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);digest.AppendData(buffer);digest.AppendData(tag);string hash=Convert.ToHexString(digest.GetHashAndReset());golden??=hash;if(hash!=golden)throw new Exception("worker result differs");
                if(repetition>=0){seconds[repetition]=sw.Elapsed.TotalSeconds;allocated[repetition]=allocationCount;cpuSeconds[repetition]=cpu;}}
            double[] sorted=(double[])seconds.Clone();Array.Sort(sorted);output.Add(new{suite=suite.Item1,worker_grant=grant,bytes_per_run=(long)Chunk*Chunks,chunk_bytes=Chunk,warmups=1,repetitions=Repetitions,seconds,median_mib_per_second=256/sorted[2],managed_allocated_bytes=allocated,cpu_seconds=cpuSeconds,peak_working_set_bytes=Process.GetCurrentProcess().PeakWorkingSet64,output_sha256=golden,threadpool_threads=ThreadPool.ThreadCount});
        }}
        Console.WriteLine(JsonSerializer.Serialize(new{status="PASS",scope="primitive cascade, fixed public keys/nonces; no KDF, derived nonce, global MAC, container or I/O claim",executor=shared?"shared persistent product source":"standalone bounded native teams (comparison only)",runtime=RuntimeInformation.FrameworkDescription,architecture=RuntimeInformation.ProcessArchitecture.ToString(),artifacts,results=output},new JsonSerializerOptions{WriteIndented=true}));return 0;
    }
}
