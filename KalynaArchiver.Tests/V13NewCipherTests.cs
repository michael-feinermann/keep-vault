using System.Security.Cryptography;
using KalynaArchiver.Services;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

internal static class V13NewCipherTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("crypto.v13-camellia-reference", "Camellia-256 KAT, independent CTR and full-width carry", () => Run(false), TestResource.CpuHeavy, "Crypto"),
        new("crypto.v13-serpent-reference", "Final Serpent-256 KAT, independent CTR and full-width carry", () => Run(true), TestResource.CpuHeavy, "Crypto"),
    ];
    private static void Require(bool good, string label) { if (!good) throw new InvalidOperationException(label); }
    private static Task Run(bool serpent)
    {
        using IDisposable scope = NativeCipherWorkerBudget.EnterScope(Math.Max(1, Math.Min(Environment.ProcessorCount,4)));
        Require(serpent ? NativeSerpent.IsAvailable() : NativeCamellia.IsAvailable(), "Trusted v13 cipher library required.");
        byte[] key = Convert.FromHexString(serpent ? new string('0',64) : "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
        byte[] block = Convert.FromHexString(serpent ? "00000000000000000000000000000001" : "0123456789abcdeffedcba9876543210");
        byte[] expectedBlock = Convert.FromHexString(serpent ? "ad86de83231c3203a86ae33b721eaa9f" : "9acc237dff16d76c20ef7c919e3a7509");
        byte[] actualBlock = new byte[16];
        if (serpent) NativeSerpent.EncryptBlock(key,block,actualBlock); else NativeCamellia.EncryptBlock(key,block,actualBlock);
        Require(actualBlock.AsSpan().SequenceEqual(expectedBlock), "Published primitive KAT.");
        Action<byte[],byte[],byte[],byte[],int> crypt = serpent ? NativeSerpent.XCrypt : NativeCamellia.XCrypt;
        byte[] nonce=Enumerable.Range(0,16).Select(i=>(byte)i).ToArray();
        foreach (int length in new[] {0,1,15,16,17,31,32,33,63,64,65,65535,65536,65537,262143,262144,262145,1048575,1048576,1048577,16777215,16777216})
        {
            byte[] input=new byte[length];for(int i=0;i<length;++i)input[i]=(byte)(i*29);
            byte[] expected=Reference(serpent,key,nonce,input),output=new byte[length];
            crypt(key,nonce,input,output,length);Require(output.AsSpan().SequenceEqual(expected),"Independent BC CTR byte equality.");
            crypt(key,nonce,output,output,length);Require(output.AsSpan().SequenceEqual(input),"Exact inplace decrypt.");
            crypt(key,nonce,input,input,length);Require(input.AsSpan().SequenceEqual(expected),"Exact inplace encrypt.");
        }
        foreach(string value in new[]{"000000000000000000000000000000ff","000000000000000000000000ffffffff","0000000000000000ffffffffffffffff"})
        {
            byte[] n=Convert.FromHexString(value), input=new byte[33], actual=new byte[33];crypt(key,n,input,actual,33);
            Require(actual.AsSpan().SequenceEqual(Reference(serpent,key,n,input)),"Big-endian counter carry across every width.");
        }
        byte[] last=Enumerable.Repeat((byte)255,16).ToArray(),sentinel=Enumerable.Repeat((byte)0xa5,17).ToArray();
        bool refused=false;try{crypt(key,last,new byte[17],sentinel,17);}catch(CryptographicException){refused=true;}
        Require(refused&&sentinel.All(v=>v==0xa5),"Full counter wrap refused before output.");
        return Task.CompletedTask;
    }
    // Independent block-only reference: no native CTR driver and no BC CTR mode.
    private static byte[] Reference(bool serpent, byte[] key, byte[] nonce, byte[] input)
    {
        IBlockCipher engine=serpent?new SerpentEngine():new CamelliaEngine();engine.Init(true,new KeyParameter(key));
        byte[] counter=nonce.ToArray(),stream=new byte[16],output=new byte[input.Length];
        for(int offset=0;offset<input.Length;offset+=16)
        {
            engine.ProcessBlock(counter,0,stream,0);
            for(int i=0;i<Math.Min(16,input.Length-offset);++i)output[offset+i]=(byte)(input[offset+i]^stream[i]);
            if(offset+16<input.Length){int index=15;while(index>=0&&++counter[index]==0)--index;if(index<0)throw new OverflowException();}
        }
        return output;
    }
}
