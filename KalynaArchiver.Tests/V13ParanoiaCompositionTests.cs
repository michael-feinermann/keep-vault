using System.Security.Cryptography;
using System.Buffers.Binary;
using System.Text.Json.Nodes;
using System.Text.Json;
using KalynaArchiver.Services;

internal static class V13ParanoiaCompositionTests
{
    private const string FixtureSha256 = "287319CDCF4DE2132370E4CAA5FEFA62315F0B22F2C4F26DEC5256477B6EA6A9";
    private const string ParanoiaAlgorithm = "XChaCha20-Poly1305(Threefish-1024-CTR(Kalyna-512/512-CTR(SHACAL-2-512-CTR(Serpent-256-CTR(Camellia-256-CTR(MARS-448-CTR(AES-256-CTR)))))))+HMAC-SHA3-512+Skein-MAC-1024";
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("v13-cascade-independent-composition", "Standard/Paranoia independent intermediate stages and identical libsodium/Go outer AEAD", CompositionAsync, TestResource.CpuHeavy, "V13"),
        new("v13-par8-header-auth", "Paranoia writer header, two global MAC gates and recomputed-global-MAC local tag rejection", HeaderAuthAsync, TestResource.EntropyGlobal, "V13"),
        new("v13-par8-rolekeys", "Paranoia eight independent stage contexts, dual PRF values, MAC/recovery roles and tweak index", RoleKeysAsync, TestResource.Light, "V13"),
    ];

    private static string FixturePath() => Path.Combine(RepositoryLayout.FindRepositoryRoot(),
        "KeepVaultMac.Tests", "Fixtures", "V13Reference", "cascade_composition_rev9.json");

    private static async Task CompositionAsync()
    {
        byte[] fixture = File.ReadAllBytes(FixturePath());
        Require(Convert.ToHexString(SHA256.HashData(fixture)) == FixtureSha256, "Frozen cascade fixture was changed.");
        using JsonDocument doc = JsonDocument.Parse(fixture);
        Require(doc.RootElement.GetProperty("schema").GetInt32() == 1 && doc.RootElement.GetProperty("publicSyntheticOnly").GetBoolean(), "Unexpected fixture schema.");
        int cases = 0;
        using CpuWorkBudget.Lease cpu = await CpuWorkBudget.AcquireAsync(ArchiveOperationPolicy.Current.MaxCpuWorkers, 1, default);
        using IDisposable cpuScope = cpu.EnterScope();
        using IDisposable nativeScope = NativeCipherWorkerBudget.EnterScope(1);
        foreach (JsonElement item in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            int suiteId=item.GetProperty("suiteId").GetInt32();
            Require(suiteId is 2 or 3, "Unregistered fixture suite.");
            EncryptionSuite suite=(EncryptionSuite)suiteId;
            byte[] key=Read(item,"key"), nonce=Read(item,"stageNonce"), tweak=Read(item,"tweak"), aad=Read(item,"aad"), plain=Read(item,"plaintext");
            int length=item.GetProperty("length").GetInt32();
            Require(length==plain.Length && aad.Length==36 && tweak.Length==16, "Fixture width mismatch.");
            byte[] current=[..plain]; int keyOffset=0,nonceOffset=0,index=0;
            string[] names=suiteId==3?["AES-256","MARS-448","Camellia-256","Serpent-256","SHACAL-2-512","Kalyna-512/512","Threefish-1024","XChaCha20Poly1305"]:["AES-256","Kalyna-512/512","Threefish-1024","XChaCha20Poly1305"];
            foreach(JsonElement stage in item.GetProperty("stages").EnumerateArray())
            {
                string cipher=stage.GetProperty("cipher").GetString()!;
                Require(index<names.Length && cipher==names[index], "Independent fixture stage order changed.");
                byte[] stageKey=Read(stage,"key"), stageNonce=Read(stage,"nonce"), output=new byte[length];
                Require(stageKey.SequenceEqual(key.AsSpan(keyOffset,stageKey.Length).ToArray()) && stageNonce.SequenceEqual(nonce.AsSpan(nonceOffset,stageNonce.Length).ToArray()), "Fixture stage slices differ from exact concatenated inputs.");
                switch(cipher)
                {
                    case "AES-256": NativeAes.XCryptCtr256(stageKey,stageNonce,current,output,length);break;
                    case "MARS-448": NativeMars.XCryptCtr448(stageKey,stageNonce,current,output,length);break;
                    case "Camellia-256": NativeCamellia.XCrypt(stageKey,stageNonce,current,output,length);break;
                    case "Serpent-256": NativeSerpent.XCrypt(stageKey,stageNonce,current,output,length);break;
                    case "SHACAL-2-512": NativeShacal2.XCryptCtr512(stageKey,stageNonce,current,output,length);break;
                    case "Kalyna-512/512": NativeKalyna.XCryptCtr512(stageKey,stageNonce,current,output,length);break;
                    case "Threefish-1024": NativeThreefish.XCryptCtr1024(stageKey,tweak,stageNonce,current,output,length);break;
                    case "XChaCha20Poly1305":
                        byte[] tag=new byte[16];NativeXChaChaPoly.Encrypt(stageKey,stageNonce,aad,current,output,length,tag);
                        Require(tag.SequenceEqual(Read(stage,"tag")), "Outer stage tag differs from external oracles.");break;
                    default:throw new InvalidDataException("Unknown fixture cipher.");
                }
                Require(output.SequenceEqual(Read(stage,"output")), $"Suite {suiteId}, stage {index}, length {length}: independent output differs.");
                current=output;keyOffset+=stageKey.Length;nonceOffset+=stageNonce.Length;index++;
            }
            Require(index==names.Length && keyOffset==key.Length && nonceOffset==nonce.Length, "Incomplete fixture composition.");
            byte[] expected=Read(item,"ciphertext"), expectedTag=Read(item,"tag");
            Require(expected.SequenceEqual(Read(item,"libsodiumCiphertext")) && expected.SequenceEqual(Read(item,"goCiphertext"))
                && expectedTag.SequenceEqual(Read(item,"libsodiumTag")) && expectedTag.SequenceEqual(Read(item,"goTag")), "Independent AEAD oracles disagree.");
            byte[] actual=new byte[length], actualTag=new byte[16];
            KalynaContainerService.EncryptSuiteChunkForTests(EncryptionSuiteCatalog.Get(suite),key,tweak,nonce,plain,actual,length,aad,actualTag);
            Require(actual.SequenceEqual(expected) && actualTag.SequenceEqual(expectedTag), "Product cascade differs from complete independent fixture.");
            cases++;
        }
        Require(cases==28,"Expected fourteen lengths for both exact cascades.");
    }

    private static Task RoleKeysAsync()
    {
        byte[] master=Enumerable.Range(0,128).Select(i=>unchecked((byte)(17*i+5))).ToArray();
        string[] names=["AES-256","MARS-448","Camellia-256","Serpent-256","SHACAL-2-512","Kalyna-512/512","Threefish-1024","XChaCha20-Poly1305"];
        int[] bits=[256,448,256,256,512,512,1024,256];
        using RoleKeyMaterial material=SuiteKeySchedule.DeriveSuiteKeys(master,EncryptionSuiteCatalog.Get(EncryptionSuite.ParanoiaCascade));
        Require(EncryptionSuiteCatalog.Get(EncryptionSuite.ParanoiaCascade).Algorithm==ParanoiaAlgorithm && material.EncryptionKey.Bytes.Length==440,"Paranoia identifier/key width changed.");
        int offset=0;var seen=new HashSet<string>();
        for(int i=0;i<8;i++)
        {
            byte[] context=V13StandardTests.ReferenceContext(ParanoiaAlgorithm,i,names[i],"Encryption",bits[i]);
            byte[] expected=V13StandardTests.ReferenceRole(master,context)[..(bits[i]/8)];
            Require(context.SequenceEqual(SuiteKeySchedule.BuildRoleContext(ParanoiaAlgorithm,i,names[i],KeyRolePurpose.Encryption,bits[i])),"Paranoia stage context differs.");
            Require(expected.SequenceEqual(material.EncryptionKey.Bytes.AsSpan(offset,expected.Length).ToArray()) && seen.Add(Convert.ToHexString(expected)),"Paranoia independently derived stage role differs.");
            offset+=expected.Length;
        }
        foreach((string cipher,KeyRolePurpose purpose,int length,byte[] actual) in new[]{
            ("HMAC-SHA3-512",KeyRolePurpose.Sha3Mac,64,material.Sha3MacKey.Bytes),
            ("Skein-MAC-1024-1024",KeyRolePurpose.SkeinMac,128,material.SkeinMacKey.Bytes)})
        {
            byte[] context=V13StandardTests.ReferenceContext(ParanoiaAlgorithm,-1,cipher,purpose.ToString(),length*8);
            Require(V13StandardTests.ReferenceRole(master,context)[..length].SequenceEqual(actual),"Paranoia global MAC role differs.");
        }
        foreach((string cipher,KeyRolePurpose purpose,int length) in new[]{
            ("HMAC-SHA3-512",KeyRolePurpose.RecoverySha3Certification,64),
            ("Skein-MAC-1024-1024",KeyRolePurpose.RecoverySkeinCertification,128)})
        {
            byte[] context=V13StandardTests.ReferenceContext(ParanoiaAlgorithm,-1,cipher,purpose.ToString(),length*8);
            byte[] actual=SuiteKeySchedule.DeriveGlobalKey(master,ParanoiaAlgorithm,cipher,purpose,length);
            Require(V13StandardTests.ReferenceRole(master,context)[..length].SequenceEqual(actual),"Paranoia recovery role differs.");
        }
        byte[] basis=Enumerable.Range(0,320).Select(i=>unchecked((byte)(i*7+3))).ToArray();
        Require(KalynaContainerService.CreateSuiteTweak(EncryptionSuite.ParanoiaCascade,basis).SequenceEqual(V13StandardTests.ReferenceTweak(ParanoiaAlgorithm,6,basis)),"Paranoia tweak index/basis encoding differs.");
        return Task.CompletedTask;
    }
    private static async Task HeaderAuthAsync()
    {
        const string password="N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce",pin="428317";
        string factorA=new('A',256),factorB=new('B',256);
        string directory=Path.Combine(Path.GetTempPath(),"keepvault-par8-auth-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
#if KEEPVAULT_MACOS
        directory=MacSafeFileSystem.ResolveExistingRealPath(directory);
#endif
        var owned=new List<byte[]>();
        try
        {
            // Explicit test-only KAT profile. Production parameters are never changed.
            using IDisposable kat=V13MasterKdf.UseMemoryCostForTests(8192);
            var salt1=LockedSensitiveBuffer.Create(128);var salt2=LockedSensitiveBuffer.Create(128);
            var nonce1=LockedSensitiveBuffer.Create(320);var nonce2=LockedSensitiveBuffer.Create(320);
            for(int i=0;i<128;i++){salt1.Bytes[i]=unchecked((byte)(i*29+23));salt2.Bytes[i]=unchecked((byte)(i*61+161));}
            for(int i=0;i<320;i++){nonce1.Bytes[i]=unchecked((byte)(i*43+43));nonce2.Bytes[i]=unchecked((byte)(i*73+211));}
            using var entropy=new GeneratedArchiveEntropy(factorA,factorB,salt1,nonce1,salt2,nonce2);
            byte[] payload=Enumerable.Range(0,127).Select(i=>(byte)i).ToArray();
            string path=Path.Combine(directory,"par8.kzpaq");using var input=new MemoryStream(payload,false);
            var service=new KalynaContainerService();
            await service.EncryptZpaqStreamWithPreparedEntropyAsync(input,path,password,pin,factorA,factorB,EncryptionSuite.ParanoiaCascade,entropy,"par8-public-test",null,default);
            byte[] original=await File.ReadAllBytesAsync(path);int headerLength=BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(7)),macOffset=11+headerLength;
            JsonObject h=JsonNode.Parse(original.AsSpan(11,headerLength))!.AsObject();
            Require(h["Version"]!.GetValue<int>()==13 && h["Algorithm"]!.GetValue<string>()==ParanoiaAlgorithm && h["EncryptionKeyBits"]!.GetValue<int>()==3520,"Paranoia canonical writer identity differs.");
            Require(h["NonceBits"]!.GetValue<int>()==2560 && h["SecondNonceBits"]!.GetValue<int>()==2560
                && Convert.FromBase64String(h["Nonce"]!.GetValue<string>()).Length==320 && Convert.FromBase64String(h["SecondNonce"]!.GetValue<string>()).Length==320
                && h["NonceDerivationMode"]!.GetValue<string>()=="Seed320-Blockwise64-SHA3-512-ActivePrefix-v3","Paranoia full-basis header differs.");
            using(var plain=new MemoryStream()){await service.DecryptToStreamAsync(path,password,pin,factorA,factorB,plain,null,default);Require(plain.ToArray().SequenceEqual(payload),"Unmodified Paranoia fixture failed.");}
            foreach(Action<JsonObject> mutation in new Action<JsonObject>[]
            {
                x=>x["Version"]=12,
                x=>x["Algorithm"]="ChaCha20-Poly1305(Threefish-1024-CTR(Kalyna-512/512-CTR(SHACAL-2-512-CTR(MARS-448-CTR(AES-256-CTR)))))+HMAC-SHA3-512+Skein-MAC-1024",
                x=>x["Algorithm"]="XChaCha20-Poly1305(Threefish-1024-CTR(Kalyna-512/512-CTR(SHACAL-2-512-CTR(MARS-448-CTR(AES-256-CTR)))))+HMAC-SHA3-512+Skein-MAC-1024",
                x=>x["EncryptionKeyBits"]=3008,
                x=>{x["Nonce"]=Convert.ToBase64String(new byte[312]);x["NonceBits"]=2496;},
                x=>{x["SecondNonce"]=Convert.ToBase64String(new byte[312]);x["SecondNonceBits"]=2496;},
                x=>{x["Nonce"]=Convert.ToBase64String(new byte[280]);x["NonceBits"]=2240;},
                x=>x["NonceDerivationMode"]="Seed320-SHA3-512-ChunkBlocks-v1",
                x=>x["NonceDerivationMode"]="Seed320-Blockwise64-SHA3-512+AllBlocks-StageProjection-v2",
                x=>x["KdfInputMode"]=V13MasterKdf.KdfInputMode.Replace("v13","v12",StringComparison.Ordinal),
                x=>x["SaltSha3Round2"]=null,
                x=>x["SecondNonce"]=null,
            })
            {
                var legacy=(JsonObject)h.DeepClone();mutation(legacy);byte[] encoded=JsonSerializer.SerializeToUtf8Bytes(legacy);
                byte[] frame=[..original.AsSpan(0,7),..new byte[4],..encoded,..original.AsSpan(macOffset)];BinaryPrimitives.WriteInt32LittleEndian(frame.AsSpan(7),encoded.Length);
                foreach(bool recovery in new[]{false,true})
                {
                    using var legacyInput=new MemoryStream(frame,false);bool rejected=false;
                    try{if(recovery)_=await service.ReadRecoveryKdfInfoAsync(legacyInput,default);else _=await service.ReadContainerInfoAsync(legacyInput,default);}
                    catch(InvalidDataException){rejected=true;}
                    Require(rejected,"Paranoia reader accepted an old or incomplete generation header.");
                }
            }
            foreach(int at in new[]{macOffset,macOffset+64,macOffset+192,original.Length-1})
            {
                byte[] damaged=(byte[])original.Clone();damaged[at]^=1;await File.WriteAllBytesAsync(path,damaged);
                using var output=new MemoryStream();bool failed=false;
                try{await service.DecryptToStreamAsync(path,password,pin,factorA,factorB,output,null,default);}
                catch(CryptographicException){failed=true;}
                Require(failed&&output.Length==0,"Paranoia global authentication released plaintext or accepted damage.");
            }
            byte[] a=Convert.FromHexString(factorA),b=Convert.FromHexString(factorB);owned.Add(a);owned.Add(b);
            byte[] qs=V13MasterKdf.DeriveSha3CredentialHash(ParanoiaAlgorithm,password,pin,a,b),qk=V13MasterKdf.DeriveSkeinCredentialHash(ParanoiaAlgorithm,password,pin,a,b);owned.Add(qs);owned.Add(qk);
            byte[] s11=Convert.FromBase64String(h["SaltSha3Round1"]!.GetValue<string>()),s12=Convert.FromBase64String(h["SaltSkeinRound1"]!.GetValue<string>()),
                s21=Convert.FromBase64String(h["SaltSha3Round2"]!.GetValue<string>()),s22=Convert.FromBase64String(h["SaltSkeinRound2"]!.GetValue<string>());
            (_,uint m1)=V13MasterKdf.DerivePmi(ParanoiaAlgorithm,1,qs,qk,[],s11,s12);
            byte[] master1=V13MasterKdf.DeriveRoundMaster(ParanoiaAlgorithm,1,qs,qk,s11,s12,null,m1);owned.Add(master1);
            (_,uint m2)=V13MasterKdf.DerivePmi(ParanoiaAlgorithm,2,qs,qk,master1,s21,s22);
            byte[] master2=V13MasterKdf.DeriveRoundMaster(ParanoiaAlgorithm,2,qs,qk,s21,s22,master1,m2);owned.Add(master2);
            using RoleKeyMaterial keys=SuiteKeySchedule.DeriveSuiteKeys(master2,EncryptionSuiteCatalog.Get(EncryptionSuite.ParanoiaCascade));
            byte[] corrupt=(byte[])original.Clone();corrupt[^1]^=1;
            using(var stream=new MemoryStream(corrupt))
            {
                (byte[] sha,byte[] skein)=await ParallelContainerAuthenticator.ComputeAsync(stream,macOffset+192,
                    ["KZPAQ2\0"u8.ToArray(),original.AsSpan(7,4).ToArray(),original.AsSpan(11,headerLength).ToArray()],keys.Sha3MacKey.Bytes,keys.SkeinMacKey.Bytes,default);
                owned.Add(sha);owned.Add(skein);sha.CopyTo(corrupt,macOffset);skein.CopyTo(corrupt,macOffset+64);
            }
            await File.WriteAllBytesAsync(path,corrupt);
            // Establish separately that both regenerated global tags pass.
            using(var stream=new MemoryStream(corrupt)){await service.VerifyAuthenticationAsync(stream,password,pin,factorA,factorB,default);}
            using var localOutput=new MemoryStream();bool localFailure=false;
            try{await service.DecryptToStreamAsync(path,password,pin,factorA,factorB,localOutput,null,default);}
            catch(CryptographicException failure){localFailure=failure.Message.Contains("XChaCha20-Poly1305 authentication tag",StringComparison.Ordinal);}
            Require(localFailure&&localOutput.Length==0,"Paranoia did not reach the independent local AEAD gate before plaintext output.");
        }
        finally{foreach(byte[] bytes in owned)CryptographicOperations.ZeroMemory(bytes);Directory.Delete(directory,true);}
    }

    private static byte[] Read(JsonElement item,string name)=>Convert.FromBase64String(item.GetProperty(name).GetString()!);
    private static void Require(bool value,string message){if(!value)throw new InvalidOperationException(message);}
}
