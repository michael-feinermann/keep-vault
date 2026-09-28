using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using KalynaArchiver.Services;
internal static unsafe class Program {
 static void Main(string[] args) {
  if(args.Length!=1)throw new ArgumentException("candidate directory");const int length=16*1024*1024;byte[]key=new byte[64],nonce=new byte[32],input=new byte[length],output=new byte[length];for(int i=0;i<input.Length;i++)input[i]=(byte)i;for(int i=0;i<key.Length;i++)key[i]=(byte)(i*3+1);for(int i=0;i<nonce.Length;i++)nonce[i]=(byte)(i*7);
  string?[] goldens=new string?[5];var results=new List<object>();var artifacts=new Dictionary<string,string>();string[]names=["AES256","MARS448","Camellia256","Serpent256","SHACAL2"];
  foreach(int grain in new[]{64,128,256,512,1024}){
   string path=Path.GetFullPath(Path.Combine(args[0],"libgrain"+grain+".dylib"));artifacts[Path.GetFileName(path)]=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));nint library=NativeLibrary.Load(path);NativeCipherExecutor.Install(library);var run=(delegate* unmanaged[Cdecl]<int,byte*,byte*,byte*,byte*,nuint,uint,int>)NativeLibrary.GetExport(library,"grain_xcrypt");
   for(int algorithm=0;algorithm<5;algorithm++){double[]seconds=new double[5];for(int repetition=-1;repetition<5;repetition++){var sw=Stopwatch.StartNew();fixed(byte*k=key,n=nonce,i=input,o=output){if(run(algorithm,k,n,i,o,length,10)!=0)throw new Exception("cipher failure");}sw.Stop();if(repetition>=0)seconds[repetition]=sw.Elapsed.TotalSeconds;string hash=Convert.ToHexString(SHA256.HashData(output));goldens[algorithm]??=hash;if(hash!=goldens[algorithm])throw new Exception("grain output mismatch");}double[] sorted=(double[])seconds.Clone();Array.Sort(sorted);results.Add(new{cipher=names[algorithm],preferred_claim_kib=grain,worker_grant=10,bytes=length,warmups=1,repetitions=5,seconds,median_mib_per_second=16/sorted[2],sha256=goldens[algorithm]});}
  }
  Console.WriteLine(JsonSerializer.Serialize(new{status="PASS",scope="isolated candidate builds of identical shared product CTR driver; only preferred claim size differs; actual shared executor",artifacts,results},new JsonSerializerOptions{WriteIndented=true}));
 }
}
