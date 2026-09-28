using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using KalynaArchiver.Services;

internal static unsafe class Program
{
    private static int _checks;
    private static void Require(bool value, string label) { if (!value) throw new Exception(label); ++_checks; }
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void Probe(nint context, nuint index)
    {
        // Unique identities have unique counters; no secret data, busy waits,
        // or additional threads. End-of-job write proves each submitted job joined.
        int* values = (int*)context;
        Interlocked.Increment(ref values[index]);
    }
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Replacement(nuint _, delegate* unmanaged[Cdecl]<nint, nuint, void> __, nint ___) => 0;

    private static int Main(string[] args)
    {
        if (args.Length != 1) throw new ArgumentException("Native directory required.");
        string root = Path.GetFullPath(args[0]);
        nint x = NativeLibrary.Load(Path.Combine(root, "libxchachapoly_v13.dylib"));
        NativeCipherExecutor.Install(x); NativeCipherExecutor.Install(x);
        var register = (delegate* unmanaged[Cdecl]<delegate* unmanaged[Cdecl]<nuint, delegate* unmanaged[Cdecl]<nint, nuint, void>, nint, int>, int>)NativeLibrary.GetExport(x,"keepvault_v13_register_executor");
        Require(register(&Replacement) == 1, "An installed executor may not be replaced.");
        var dispatch = (delegate* unmanaged[Cdecl]<nuint, delegate* unmanaged[Cdecl]<nint, nuint, void>, nint, int>)NativeLibrary.GetExport(x,"keepvault_test_v13_dispatch_registered");
        foreach (int count in new[] { 1,32,63,64,65,96,128,256,512,1024,4096 })
        {
            int[] seen = new int[count];
            fixed (int* p = seen) Require(dispatch((nuint)count,&Probe,(nint)p)==0,"Dispatch status");
            Require(seen.All(v=>v==1),"Every logical work identity exactly once");
        }
        foreach (int failAfter in new[] {0,1,2,7})
        {
            int[] seen = new int[16]; NativeCipherExecutor.RejectSubmissionAfterForTests=failAfter;
            fixed (int* p=seen) Require(dispatch(16,&Probe,(nint)p)==3,"Scheduling failure propagated");
            NativeCipherExecutor.RejectSubmissionAfterForTests=null;
            Require(seen[0]==1 && seen.Skip(1).Take(failAfter).All(v=>v==1) && seen.Skip(failAfter+1).All(v=>v==0),"All started work joined after failure");
        }
        const int length=16*1024*1024;
        byte[] key=Enumerable.Range(0,128).Select(i=>(byte)(i*13)).ToArray();
        byte[] nonce=Enumerable.Range(0,128).Select(i=>(byte)(i*7)).ToArray();
        byte[] input=Enumerable.Range(0,length).Select(i=>(byte)i).ToArray(),expected=new byte[length],actual=new byte[length],tweak=new byte[16],aad=new byte[36],tag=new byte[16],referenceTag=new byte[16];
        foreach(var entry in new[] {
            ("aes_ref","aes_256_ctr_xcrypt_v13_with_workers",0), ("mars_ref","mars_448_ctr_xcrypt_v13_with_workers",0),
            ("shacal2_ref","shacal2_512_ctr_xcrypt_v13_with_workers",0), ("kalyna_v13","keepvault_v13_kalyna_512_512_ctr_xcrypt_with_workers",0),
            ("threefish_ref","threefish_1024_ctr_xcrypt_v13_with_workers",1), ("camellia_v13","keepvault_v13_camellia_256_ctr_xcrypt",2),
            ("serpent_v13","keepvault_v13_serpent_256_ctr_xcrypt",2), ("xchachapoly_v13","keepvault_xchacha20poly1305_v13_encrypt_with_budget",3) })
        {
            nint lib=entry.Item1=="xchachapoly_v13"?x:NativeLibrary.Load(Path.Combine(root,"lib"+entry.Item1+".dylib"));
            nint function=NativeLibrary.GetExport(lib,entry.Item2);NativeCipherExecutor.Install(lib);
            int Run(byte[] output,uint grant,byte[] destinationTag)
            {
                fixed(byte* k=key,n=nonce,i=input,o=output,t=tweak,a=aad,g=destinationTag)
                {
                    if(entry.Item3==0)return ((delegate* unmanaged[Cdecl]<byte*,byte*,byte*,byte*,nuint,uint,int>)function)(k,n,i,o,length,grant);
                    if(entry.Item3==1)return ((delegate* unmanaged[Cdecl]<byte*,byte*,byte*,byte*,byte*,nuint,uint,int>)function)(k,t,n,i,o,length,grant);
                    if(entry.Item3==2)return ((delegate* unmanaged[Cdecl]<byte*,nuint,byte*,nuint,byte*,nuint,byte*,nuint,uint,int>)function)(k,32,n,16,i,length,o,length,grant);
                    return ((delegate* unmanaged[Cdecl]<byte*,nuint,byte*,nuint,byte*,nuint,byte*,nuint,byte*,nuint,byte*,nuint,uint,int>)function)(k,32,n,24,a,36,i,length,o,length,g,16,grant);
                }
            }
            Require(Run(expected,1,referenceTag)==0,entry.Item1+" serial");
            foreach(uint grant in new uint[]{2,3,5,10,65,128,1024,4096}){
                NativeCipherExecutor.LastDispatchCountForTests=0;
                Require(Run(actual,grant,tag)==0,entry.Item1+" borrowed executor status");
                Require(NativeCipherExecutor.LastDispatchCountForTests==grant,entry.Item1+" actual cipher team has no fixed grain cap");
                Require(CryptographicOperations.FixedTimeEquals(expected,actual)&&CryptographicOperations.FixedTimeEquals(referenceTag,tag),entry.Item1+" exact byte equality");
            }
            NativeCipherExecutor.RejectSubmissionAfterForTests=1;
            Require(Run(actual,5,tag)!=0,entry.Item1+" partial scheduling failure");
            NativeCipherExecutor.RejectSubmissionAfterForTests=null;
            Require(Run(actual,5,tag)==0&&actual.AsSpan().SequenceEqual(expected),entry.Item1+" recovery after failure");
        }
        Console.WriteLine(JsonSerializer.Serialize(new{status="PASS",checks=_checks,logical_identities=4096,payload_bytes=length,executor="actual shared product source; failure hooks test-build only",threadpool_threads=ThreadPool.ThreadCount}));
        return 0;
    }
}
