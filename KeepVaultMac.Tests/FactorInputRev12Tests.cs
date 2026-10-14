using System.Security.Cryptography;
using KalynaArchiver.Services;

// Public synthetic fixtures only. Shared Windows/macOS core regression tests.
internal static class FactorInputRev12Tests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("factor.rev12-whitespace", "V13-FACTOR-WHITESPACE: pinned full UTF-16 whitespace set and identical locked factor bytes", WhitespaceAsync, TestResource.Light, "Factors"),
        new("factor.rev12-boundaries", "V13-FACTOR-BOUNDARIES: complete payload and raw-text limits without partial decode", BoundariesAsync, TestResource.ProcessGlobal, "Factors"),
        new("factor.rev12-invalid", "V13-FACTOR-INVALID: no labels, Unicode/OCR substitutes, NUL or malformed surrogates", InvalidAsync, TestResource.Light, "Factors"),
        new("factor.rev12-password-pin", "V13-FACTOR-PASSWORD-PIN: formatting leaves password/PIN credential transcripts unchanged", CredentialsAsync, TestResource.Light, "Factors"),
        new("factor.rev12-allpaths", "V13-FACTOR-ALLPATHS: formatted factors decrypt, repair and retry the same v13 containers", AllPathsAsync, TestResource.ProcessGlobal, "Factors"),
    ];

    private static readonly char[] WhiteSpace =
    [
        '\u0009', '\u000A', '\u000B', '\u000C', '\u000D', '\u0020', '\u0085', '\u00A0', '\u1680',
        '\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005', '\u2006', '\u2007', '\u2008', '\u2009', '\u200A',
        '\u2028', '\u2029', '\u202F', '\u205F', '\u3000',
    ];
    internal static readonly string FactorA = Convert.ToHexString(Enumerable.Range(0, 128).Select(x => (byte)x).ToArray());
    internal static readonly string FactorB = Convert.ToHexString(Enumerable.Range(0, 128).Select(x => (byte)(255 - x)).ToArray());
    private const string Password = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
    private const string Pin = "428317";

    internal static string Format(string factor, string separator = " \t\r\n\u00A0\u202F") =>
        separator + string.Join(separator, factor.Select((c, i) => i % 2 == 0 ? char.ToLowerInvariant(c).ToString() : c.ToString())) + separator;

    private static Task WhitespaceAsync()
    {
        var expected = new HashSet<char>(WhiteSpace);
        Require(expected.Count == 25, "The whitespace test set must contain exactly 25 characters.");
        for (int value = char.MinValue; value <= char.MaxValue; value++)
        {
            char c = (char)value;
            Require(FactorInput.IsFormattingWhiteSpace(c) == expected.Contains(c), "The factor formatting set differs from its explicit fixture.");
            Require(char.IsWhiteSpace(c) == expected.Contains(c), "The pinned runtime whitespace set changed.");
        }
        foreach (char c in WhiteSpace)
        foreach (string factor in new[] { FactorA, FactorB })
        {
            string formatted = Format(factor, c.ToString());
            Require(PasswordKeyService.NormalizeGeneratedPassword(formatted) == factor, "A supported whitespace character changed canonical factor text.");
            using LockedSensitiveBuffer actual = ContainerKeyDerivation.ParseFactor(formatted, "public test factor");
            Require(actual.Bytes.AsSpan().SequenceEqual(Convert.FromHexString(factor)), "Formatting changed factor bytes.");
        }
        return Task.CompletedTask;
    }

    private static Task BoundariesAsync()
    {
        Require(FactorInput.Validate(new string('A', 255), true, out _) == FactorInput.Error.Incomplete, "255 payload characters were accepted as complete.");
        Require(FactorInput.Validate(new string('A', 256), true, out int count) == FactorInput.Error.None && count == 256, "256 payload characters were rejected.");
        Require(FactorInput.Validate(new string('A', 257), true, out _) == FactorInput.Error.TooManyHexCharacters, "257 payload characters were silently shortened.");
        foreach (int rawLength in new[] { 65_535, 65_536 })
        {
            string formatted = new string(' ', rawLength - FactorA.Length) + FactorA;
            Require(PasswordKeyService.NormalizeGeneratedPassword(formatted) == FactorA, "A permitted raw-text boundary was rejected.");
            using LockedSensitiveBuffer parsed = ContainerKeyDerivation.ParseFactor(formatted, "public test factor");
            Require(parsed.Bytes.AsSpan().SequenceEqual(Convert.FromHexString(FactorA)), "A permitted raw-text boundary changed factor bytes.");
        }
        Span<byte> output = stackalloc byte[128];
        foreach (string invalid in new[] { new string('A', 255), new string('A', 257), FactorA + new string(' ', 65_537 - 256), FactorA + "Z" })
        {
            output.Fill(0xB7);
            bool rejected = false;
            try { FactorInput.Decode(invalid.AsSpan(), output); }
            catch (ArgumentException) { rejected = true; }
            Require(rejected && output.IndexOfAnyExcept((byte)0xB7) == -1, "An invalid factor partially wrote the destination before full validation.");
            long allocations = SecureMemory.LockedAllocationsForTests;
            Throws(() => ContainerKeyDerivation.ParseFactor(invalid, "public test factor"));
            Require(SecureMemory.LockedAllocationsForTests == allocations, "Rejected raw input allocated or retained a locked factor buffer.");
            Throws(() => PasswordKeyService.NormalizeGeneratedPassword(invalid));
        }
        return Task.CompletedTask;
    }

    private static Task InvalidAsync()
    {
        string[] forbidden = ["O", "I", "G", "\uFF21", "\uFF10", "\u0661", "\u200B", "\uFEFF", "\0", "\uD800", "\uDC00", "Factor A:"];
        foreach (string text in forbidden)
        foreach (string raw in new[] { text + FactorA, FactorA + text, FactorA[..128] + text + FactorA[128..] })
        {
            Throws(() => PasswordKeyService.NormalizeGeneratedPassword(raw));
            Throws(() => ContainerKeyDerivation.ParseFactor(raw, "public test factor"));
            Require(FactorInput.Validate(raw, false, out _) != FactorInput.Error.None, "An invalid factor was accepted by the import adapter.");
        }
        const string sentinel = "PRIVATE_SENTINEL_FACTOR_NOT_FOR_LOGS";
        try { FactorInput.RequireComplete(sentinel); }
        catch (ArgumentException failure) { Require(!failure.Message.Contains(sentinel, StringComparison.Ordinal), "Factor validation disclosed input in the error."); }
        return Task.CompletedTask;
    }

    private static Task CredentialsAsync()
    {
        string algorithm = EncryptionSuiteCatalog.Get(EncryptionSuite.StandardCascade).Algorithm;
        string password = "  unchanged \u00A0 password e\u0301\t ";
        string pin = "00428317";
        ContainerKeyDerivation.ValidatePasswordEncoding(password);
        ContainerKeyDerivation.ValidatePinEncoding(pin);
        byte[] a = Convert.FromHexString(FactorA), b = Convert.FromHexString(FactorB);
        using LockedSensitiveBuffer parsedA = ContainerKeyDerivation.ParseFactor(Format(FactorA), "public A");
        using LockedSensitiveBuffer parsedB = ContainerKeyDerivation.ParseFactor(Format(FactorB), "public B");
        byte[] sha = V13MasterKdf.DeriveSha3CredentialHash(algorithm, password, pin, a, b);
        byte[] skein = V13MasterKdf.DeriveSkeinCredentialHash(algorithm, password, pin, a, b);
        byte[] formattedSha = V13MasterKdf.DeriveSha3CredentialHash(algorithm, password, pin, parsedA.Bytes, parsedB.Bytes);
        byte[] formattedSkein = V13MasterKdf.DeriveSkeinCredentialHash(algorithm, password, pin, parsedA.Bytes, parsedB.Bytes);
        byte[] trimmedPassword = V13MasterKdf.DeriveSha3CredentialHash(algorithm, password.Trim(), pin, parsedA.Bytes, parsedB.Bytes);
        byte[] shortenedPin = V13MasterKdf.DeriveSkeinCredentialHash(algorithm, password, pin.TrimStart('0'), parsedA.Bytes, parsedB.Bytes);
        try
        {
            Require(sha.AsSpan().SequenceEqual(formattedSha) && skein.AsSpan().SequenceEqual(formattedSkein), "Equivalent formatted factors changed credential hashes.");
            Require(!sha.AsSpan().SequenceEqual(trimmedPassword) && !skein.AsSpan().SequenceEqual(shortenedPin), "Password whitespace or leading-zero PIN bytes were normalized.");
        }
        finally { foreach (byte[] bytes in new[] { a, b, sha, skein, formattedSha, formattedSkein, trimmedPassword, shortenedPin }) CryptographicOperations.ZeroMemory(bytes); }
        return Task.CompletedTask;
    }

    internal static async Task<IReadOnlyDictionary<string, string>> AllPathsAsync()
    {
        var receipts = new Dictionary<string, string>(StringComparer.Ordinal);
        string directory = Directory.CreateTempSubdirectory("keep-vault-factor-rev12-").FullName;
#if KEEPVAULT_MACOS
        directory = MacSafeFileSystem.ResolveExistingRealPath(directory);
#endif
        byte[] payload = Enumerable.Range(0, 4_096).Select(i => (byte)(i * 43 + 17)).ToArray();
        try
        {
            using IDisposable memory = V13MasterKdf.UseMemoryCostForTests(8_192);
            foreach (EncryptionSuite suite in new[] { EncryptionSuite.StandardCascade, EncryptionSuite.ParanoiaCascade })
            {
                using GeneratedArchiveEntropy entropy = CreateEntropy();
                string path = Path.Combine(directory, suite + ".kzpaq");
                var service = new KalynaContainerService();
                using (var input = new MemoryStream(payload, false))
                    await service.EncryptZpaqStreamWithPreparedEntropyAsync(input, path, Password, Pin, FactorA, FactorB, suite, entropy, "public factor fixture", null, CancellationToken.None);
                byte[] original = await File.ReadAllBytesAsync(path);
                receipts.Add(suite.ToString(), Convert.ToHexString(SHA256.HashData(original)));
                var recovery = new RecoveryService();
                await recovery.CreateAuthenticatedAsync(path, Password, Pin, FactorA, FactorB, null, CancellationToken.None);
                string formattedA = Format(FactorA), formattedB = Format(FactorB);
                using (var output = new MemoryStream())
                {
                    await service.DecryptToStreamAsync(path, Password, Pin, formattedA, formattedB, output, null, CancellationToken.None);
                    Require(output.ToArray().AsSpan().SequenceEqual(payload), "Formatted factors could not decrypt the unchanged v13 container.");
                }
                byte[] damaged = (byte[])original.Clone(); damaged[^1] ^= 0x80;
                await File.WriteAllBytesAsync(path, damaged);
                RecoveryRepairResult result = await recovery.VerifyAndRepairAuthenticatedAsync(path, Password, Pin, formattedA, formattedB, null, CancellationToken.None);
                Require(result.RepairedShards == 1 && !string.IsNullOrEmpty(result.OutputPath)
                    && (await File.ReadAllBytesAsync(result.OutputPath)).AsSpan().SequenceEqual(original), "Formatted factors did not authenticate and repair exactly the original container.");
                Require((await File.ReadAllBytesAsync(path)).AsSpan().SequenceEqual(damaged), "Recovery unexpectedly rewrote the original damaged input.");
                // Retry A-only, B-only and both formatted through the same public stream path.
                foreach ((string a, string b) in new[] { (formattedA, FactorB), (FactorA, formattedB), (formattedA, formattedB) })
                {
                    using var output = new MemoryStream();
                    await service.DecryptToStreamAsync(result.OutputPath!, Password, Pin, a, b, output, null, CancellationToken.None);
                    Require(output.ToArray().AsSpan().SequenceEqual(payload), "A formatted-factor retry changed payload bytes.");
                }
            }
            return receipts;
        }
        finally { CryptographicOperations.ZeroMemory(payload); Directory.Delete(directory, recursive: true); }
    }

    private static GeneratedArchiveEntropy CreateEntropy()
    {
        var salt1 = LockedSensitiveBuffer.Create(128); var salt2 = LockedSensitiveBuffer.Create(128);
        var nonce1 = LockedSensitiveBuffer.Create(320); var nonce2 = LockedSensitiveBuffer.Create(320);
        for (int i = 0; i < 128; i++) { salt1.Bytes[i] = (byte)(i * 29 + 23); salt2.Bytes[i] = (byte)(i * 61 + 161); }
        for (int i = 0; i < 320; i++) { nonce1.Bytes[i] = (byte)(i * 43 + 43); nonce2.Bytes[i] = (byte)(i * 73 + 211); }
        return new GeneratedArchiveEntropy(FactorA, FactorB, salt1, nonce1, salt2, nonce2);
    }

    private static void Throws(Action action)
    {
        bool rejected = false;
        try { action(); }
        catch (ArgumentException) { rejected = true; }
        Require(rejected, "Malformed factor input was accepted.");
    }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
