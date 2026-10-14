using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using KalynaArchiver.Services;

internal static class V13HeaderNonceFuzzTests
{
    private const ulong Seed = 0x4B56563133524539UL;
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("v13-header-seeded-fuzz", "10,000 unique seeded canonical/malformed headers through both metadata consumers", HeaderAsync, TestResource.Light, "V13"),
        new("v13-nonce-seeded-fuzz", "10,000 seeded ActivePrefix transcripts and malformed API boundaries", NonceAsync, TestResource.Light, "V13"),
    ];

    private static async Task HeaderAsync()
    {
        string fixtures=Path.Combine(RepositoryLayout.FindRepositoryRoot(),"KeepVaultMac.Tests","Fixtures","V13Reference");
        JsonObject[] baselines=[..new[]{"standard","paranoia","aes"}.Select(n=>JsonNode.Parse(File.ReadAllBytes(Path.Combine(fixtures,n+"-header-rev9.json")))!.AsObject())];
        var rng=new Stream(Seed);var distinct=new HashSet<string>();int accepted=0,rejected=0;
        for(int i=0;i<10_000;i++)
        {
            try
            {
                int chosen=rng.Bound(3),mode=i%20;JsonObject h=(JsonObject)baselines[chosen].DeepClone();
                h["Hint"]=$"public-rev9-fuzz-{i:X8}-{rng.Next():X16}";
                byte[] basis=rng.Bytes(320);h["Nonce"]=Convert.ToBase64String(basis);
                h["SaltSha3Round1"]=Convert.ToBase64String(rng.Bytes(64));h["SaltSkeinRound1"]=Convert.ToBase64String(rng.Bytes(64));
                if(chosen!=2)h["Tweak"]=Convert.ToBase64String(V13StandardTests.ReferenceTweak(h["Algorithm"]!.GetValue<string>(),chosen==0?2:6,basis));
                if(chosen==1){h["SecondNonce"]=Convert.ToBase64String(rng.Bytes(320));h["SaltSha3Round2"]=Convert.ToBase64String(rng.Bytes(64));h["SaltSkeinRound2"]=Convert.ToBase64String(rng.Bytes(64));}
                bool valid=mode<3;string? raw=null;int? declared=null;
                switch(mode)
                {
                    case 3:raw=h.ToJsonString()[..^1]+",\"Version\":13}";break;
                    case 4:h["Unknown"+rng.Next().ToString("X16")]=rng.Next().ToString("X16");break;
                    case 5:h.Remove(new[]{"Version","Algorithm","Nonce","NonceDerivationMode","SaltSha3Round1","KdfInputMode","KdfMode"}[rng.Bound(7)]);break;
                    case 6:h["Argon2Iterations"]=5+rng.Bound(100);break;
                    case 7:h["Argon2Parallelism"]=5+rng.Bound(100);break;
                    case 8:h["MasterKeyBits"]=1025+rng.Bound(8192);break;
                    case 9:h["Nonce"]=Convert.ToBase64String(rng.Bytes(rng.Bound(320)));break;
                    case 10:
                        string encoded=h["Nonce"]!.GetValue<string>();int at=rng.Bound(encoded.Length+1);
                        h["Nonce"]=encoded[..at]+new[]{" ","\t","\r\n"}[rng.Bound(3)]+encoded[at..];break;
                    case 11:
                        const string alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                        string salt=h["SaltSha3Round1"]!.GetValue<string>();int pos=salt.IndexOf('=')-1;
                        h["SaltSha3Round1"]=salt[..pos]+alphabet[alphabet.IndexOf(salt[pos])+1+rng.Bound(15)]+salt[(pos+1)..];break;
                    case 12:h["Version"]=14+rng.Bound(1_000_000);break;
                    case 13:h["Algorithm"]="unknown-"+rng.Next().ToString("X16");break;
                    case 14:h["NonceDerivationMode"]="unknown-"+rng.Next().ToString("X16");break;
                    case 15:
                        string text=h.ToJsonString(),identity=h["Hint"]!.GetValue<string>();
                        int minimum=text.IndexOf(identity,StringComparison.Ordinal)+identity.Length+1;
                        // Keep the unique case identity before the truncation so
                        // very short common prefixes cannot duplicate cases.
                        raw=text[..(minimum+rng.Bound(text.Length-minimum))];break;
                    case 16:raw=new string(' ',1+rng.Bound(8))+h.ToJsonString();break;
                    case 17:declared=16*1024+1+rng.Bound(1_000_000);break;
                    case 18:h["SecondNonce"]=chosen==1?null:Convert.ToBase64String(rng.Bytes(320));h["SecondNonceBits"]=chosen==1?0:2560;break;
                    case 19:h["Argon2MemoryKiB"]=1+rng.Bound(4_000_000);break;
                }
                byte[] header=Encoding.UTF8.GetBytes(raw??h.ToJsonString());
                byte[] frame=new byte[11+header.Length+193];"KZPAQ2\0"u8.CopyTo(frame);BinaryPrimitives.WriteInt32LittleEndian(frame.AsSpan(7),declared??header.Length);header.CopyTo(frame,11);
                Require(distinct.Add(Convert.ToHexString(SHA256.HashData(frame))),"Duplicate fuzz input.");
                foreach(bool recovery in new[]{false,true})
                {
                    using var input=new MemoryStream(frame,false);bool passed=true;
                    try{var service=new KalynaContainerService();if(recovery)_=await service.ReadRecoveryKdfInfoAsync(input,default);else _=await service.ReadContainerInfoAsync(input,default);}
                    catch(InvalidDataException){passed=false;}
                    Require(passed==valid,$"Expected {(valid?"accept":"reject")}, consumer={(recovery?"recovery":"info")}, mutation={mode}.");
                }
                if(valid)accepted++;else rejected++;
            }
            catch(Exception e){throw new InvalidOperationException($"Header fuzz seed={Seed:X16}, case={i}.",e);}
        }
        Require(accepted==1500&&rejected==8500&&distinct.Count==10_000,"Header fuzz inventory changed.");
    }

    private static Task NonceAsync()
    {
        var rng=new Stream(Seed^0x4E4F4E4345UL);var identities=new HashSet<string>();int positive=0;
        for(int i=0;i<10_000;i++)
        {
            try
            {
                EncryptionSuite suite=(EncryptionSuite)rng.Bound(12);EncryptionSuiteParameters p=EncryptionSuiteCatalog.Get(suite);
                ChunkNoncePlan plan=ChunkNoncePlan.Create(p);byte[] basis=rng.Bytes(plan.BasisBytes);long index=(long)(rng.Next()&long.MaxValue);
                Require(identities.Add(Convert.ToHexString(SHA256.HashData(basis))),"Duplicate basis in seeded test corpus.");
                byte[] expected=V13StandardTests.ReferenceNonce(p,basis,index),guard=Enumerable.Repeat((byte)0xA5,p.StageNonceBytes+2).ToArray();
                plan.DeriveStageNonce(basis,index,guard.AsSpan(1,p.StageNonceBytes));
                Require(expected.SequenceEqual(guard.AsSpan(1,p.StageNonceBytes).ToArray())&&guard[0]==0xA5&&guard[^1]==0xA5,"Independent ActivePrefix output/sentinel mismatch.");positive++;
                switch(i%5)
                {
                    case 0:Throws<ArgumentException>(()=>plan.DeriveStageNonce(basis.AsSpan(0,basis.Length-1-rng.Bound(16)),index,guard.AsSpan(1,p.StageNonceBytes)));break;
                    case 1:Throws<ArgumentException>(()=>plan.DeriveStageNonce(basis,index,guard.AsSpan(1,p.StageNonceBytes-1)));break;
                    case 2:Throws<ArgumentOutOfRangeException>(()=>plan.DeriveStageNonce(basis,-1-(long)(rng.Next()&0x7fffffff),guard.AsSpan(1,p.StageNonceBytes)));break;
                    case 3:Throws<ArgumentException>(()=>plan.DeriveStageNonce(basis,index,basis.AsSpan(0,p.StageNonceBytes)));break;
                    case 4:
                        using(var cancel=new CancellationTokenSource()){cancel.Cancel();Throws<OperationCanceledException>(()=>plan.DeriveStageNonce(basis,index,guard.AsSpan(1,p.StageNonceBytes),cancel.Token));}break;
                }
                Require(guard[0]==0xA5&&guard[^1]==0xA5,"Rejected nonce argument overwrote an outside sentinel.");
            }
            catch(Exception e){throw new InvalidOperationException($"Nonce fuzz seed={(Seed^0x4E4F4E4345UL):X16}, case={i}.",e);}
        }
        Require(positive==10_000&&identities.Count==10_000,"Nonce fuzz inventory changed.");return Task.CompletedTask;
    }
    // Fixed SplitMix64 byte source for public test cases; never product RNG.
    private sealed class Stream(ulong state)
    {
        internal ulong Next(){unchecked{ulong z=(state+=0x9E3779B97F4A7C15UL);z=(z^(z>>30))*0xBF58476D1CE4E5B9UL;z=(z^(z>>27))*0x94D049BB133111EBUL;return z^(z>>31);}}
        internal int Bound(int n)=>(int)(Next()%(uint)n);
        internal byte[] Bytes(int n){byte[] value=new byte[n];for(int i=0;i<n;i+=8){ulong x=Next();for(int j=0;j<8&&i+j<n;j++)value[i+j]=(byte)(x>>(j*8));}return value;}
    }
    private static void Throws<T>(Action f)where T:Exception{try{f();}catch(T){return;}throw new InvalidOperationException("Expected "+typeof(T).Name);}
    private static void Require(bool value,string message){if(!value)throw new InvalidOperationException(message);}
}
