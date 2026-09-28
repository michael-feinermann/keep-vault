using System.Text.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

// Test-only independent CTR framing. Both engines are BLOCK ENCRYPTION,
// including for decryption. No product native helper or S-box is referenced.
for (string? line; (line = Console.ReadLine()) != null;)
{
    try
    {
        Request request = JsonSerializer.Deserialize<Request>(line)!;
        byte[] key = Convert.FromBase64String(request.Key), counter = Convert.FromBase64String(request.Nonce);
        byte[] input = Convert.FromBase64String(request.Input), output = new byte[input.Length];
        if (key.Length != 32 || counter.Length != 16 || input.Length > 16 * 1024 * 1024) throw new ArgumentException("Invalid public test input.");
        IBlockCipher engine = request.Algorithm switch { "camellia" => new CamelliaEngine(), "serpent" => new SerpentEngine(), _ => throw new ArgumentException("Unknown cipher.") };
        engine.Init(true, new KeyParameter(key));
        byte[] stream = new byte[16];
        for (int offset = 0; offset < input.Length; offset += 16)
        {
            engine.ProcessBlock(counter, 0, stream, 0);
            for (int b = 0; b < Math.Min(16, input.Length - offset); ++b) output[offset + b] = (byte)(input[offset + b] ^ stream[b]);
            if (offset + 16 < input.Length)
            {
                int digit = 15;
                while (digit >= 0 && ++counter[digit] == 0) --digit;
                if (digit < 0) throw new OverflowException("Full 128-bit counter overflow.");
            }
        }
        Console.WriteLine(JsonSerializer.Serialize(new { Output = Convert.ToBase64String(output), Error = "" }));
    }
    catch (Exception ex) { Console.WriteLine(JsonSerializer.Serialize(new { Output = "", Error = ex.GetType().Name })); }
}
internal sealed record Request(string Algorithm, string Key, string Nonce, string Input);
