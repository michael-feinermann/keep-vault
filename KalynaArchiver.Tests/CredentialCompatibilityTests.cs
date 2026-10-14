using System.IO;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using KalynaArchiver.Services;

/// <summary>
/// Frozen synthetic v12 files produced by the pre-policy 5.0.1 source snapshot.
/// The original bytes remain untouched. v13 production readers must reject
/// these older archives before any plaintext or repair result is released.
/// </summary>
internal static class CredentialCompatibilityTests
{
    private const string ManifestSha256 = "5FBFFFB598B233953B5482EADC38B7E615EE7D31C1898CBE5FAACA7C6DEA6DB5";
    private const string StrictRestoreEvidenceSha256 = "1911DCE00784372CAB447799A4D28B70F5313E40AEBF9B78ADAE4E4901D4B1EF";
    private static readonly string[] FixtureIds =
        ["empty", "short", "oversized-raw", "pin-substring", "date-2026-09-06", "model-and-old-pattern"];

    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("credentials.static-fixture-provenance", "frozen v12 credential raw-byte and independent SHA3/Skein oracle vectors",
            VerifyProvenanceAsync, TestResource.Light, "Credentials"),
        new("credentials.creation-still-rejects", "all frozen policy-incompatible credentials remain rejected for new archives",
            VerifyCreationRejectionAsync, TestResource.Light, "Credentials"),
        .. FixtureIds.Select(id => new TestCase("credentials.read-" + id,
            "V13-STD-NOLEGACY: genuine frozen v12 is refused by read and recovery: " + id,
            () => VerifyReadAndRepairAsync(id), TestResource.Light, "Credentials")),
    ];

    private static Task VerifyProvenanceAsync()
    {
        Manifest manifest = LoadManifest();
        int guardedAttempts = 0;
        bool guardRejected = false;
        bool loaderGuardRejected = false;
        int resourceReads = 0;
        using (PasswordGuessabilityService.ForbidEvaluationForTesting(() => guardedAttempts++))
        {
            try { _ = PasswordGuessabilityService.Evaluate("synthetic hook positive control", 200); }
            catch (InvalidOperationException) { guardRejected = true; }
            try { _ = PasswordModelData.Load(_ => { resourceReads++; return null; }); }
            catch (InvalidOperationException) { loaderGuardRejected = true; }
        }
        Assert(guardRejected && loaderGuardRejected && guardedAttempts == 2 && resourceReads == 0,
            "The evaluation/model-loader forbidding test hook is inactive or reads model resources before guarding.");
        byte[] a = Convert.FromHexString(manifest.FactorAHex), b = Convert.FromHexString(manifest.FactorBHex);
        try
        {
            foreach (Fixture fixture in manifest.Fixtures)
            {
                Assert(Encoding.UTF8.GetBytes(fixture.Password).SequenceEqual(Convert.FromHexString(fixture.PasswordUtf8Hex)), "Frozen password UTF-8 bytes changed.");
                Assert(Encoding.ASCII.GetBytes(fixture.Pin).SequenceEqual(Convert.FromHexString(fixture.PinAsciiHex)), "Frozen PIN ASCII bytes changed.");
                ContainerKeyDerivation.ValidatePasswordEncoding(fixture.Password);
                ContainerKeyDerivation.ValidatePinEncoding(fixture.Pin);
                AssertCredentialHashes(fixture, a, b);
                VerifyFiles(fixture);
                byte[] locator = new byte[512];
                using var input = File.OpenRead(ArchivePath(fixture) + ".kpar2");
                input.ReadExactly(locator);
                Assert(BinaryPrimitives.ReadInt32LittleEndian(locator.AsSpan(8)) == 4 &&
                    BinaryPrimitives.ReadInt32LittleEndian(locator.AsSpan(72)) == 12, "Frozen KPAR2 v4/v12 binding changed.");
            }
            Fixture raw = manifest.Fixtures.Single(f => f.Id == "oversized-raw");
            Assert(raw.Password.Length > 256 && raw.Pin.Length > 16, "Oversized fixture lost its original selection-policy violations.");
            string normalized = raw.Password.Trim().Normalize(NormalizationForm.FormC);
            Assert(normalized != raw.Password && raw.Pin[0] == '0', "Raw-byte sentinel does not exercise whitespace, normalization and leading zero.");
            byte[] normalizedHash = ReferenceOldSha3(raw.Algorithm, normalized, raw.Pin, a, b);
            byte[] shortenedPinHash = ReferenceOldSkein(raw.Algorithm, raw.Password, raw.Pin.TrimStart('0'), a, b);
            try
            {
                Assert(!normalizedHash.SequenceEqual(Convert.FromHexString(raw.Sha3CredentialHex)), "Password normalization did not change the KDF input.");
                Assert(!shortenedPinHash.SequenceEqual(Convert.FromHexString(raw.SkeinCredentialHex)), "Leading-zero removal did not change the KDF input.");
            }
            finally { CryptographicOperations.ZeroMemory(normalizedHash); CryptographicOperations.ZeroMemory(shortenedPinHash); }
        }
        finally { CryptographicOperations.ZeroMemory(a); CryptographicOperations.ZeroMemory(b); }
        return Task.CompletedTask;
    }

    private static async Task VerifyCreationRejectionAsync()
    {
        Manifest manifest = LoadManifest();
        string temp = Directory.CreateTempSubdirectory("keep-vault-credential-creation-").FullName;
        try
        {
            DateOnly frozenDate = new(2026, 9, 6);
            foreach (Fixture fixture in manifest.Fixtures)
            {
                var pin = ContainerKeyDerivation.AnalyzePinForCreation(fixture.Pin, fixture.Password, frozenDate);
                var password = PasswordKeyService.AnalyzeUserPassword(fixture.Password, manifest.FactorAHex, manifest.FactorBHex);
                Assert(!pin.IsAccepted || !password.IsAccepted, "A frozen incompatible credential pair now passes creation policy.");
                if (fixture.Id == "pin-substring") Assert(pin.Violations.Contains(PinPolicyViolation.ContainedInPassword), "PIN substring fixture misses its exact new policy gate.");
                if (fixture.Id == "date-2026-09-06") Assert(pin.Violations.Contains(PinPolicyViolation.CurrentDate), "Frozen date fixture misses its exact date gate.");
                if (fixture.Id == "model-and-old-pattern")
                {
                    Assert(!password.IsAccepted && password.Guessability is
                        { Status: PasswordModelStatus.Available, PreviousConservativeBits: >= 128, CorrectedBits: < 128 },
                        "Known phrase rejection did not come from an available corrective model lowering the old passing score.");
                    Assert(pin.Violations.Contains(PinPolicyViolation.SequentialAscending), "Old ascending PIN gate was loosened.");
                }
                using var source = new MemoryStream("synthetic rejected creation input"u8.ToArray(), false);
                string rejectedOutput = Path.Combine(temp, fixture.Id + ".kzpaq");
                bool rejected = false;
                try
                {
                    await new KalynaContainerService().EncryptZpaqStreamAsync(source, rejectedOutput,
                        fixture.Password, fixture.Pin, manifest.FactorAHex, manifest.FactorBHex,
                        EncryptionSuiteCatalog.Default, null, null, CancellationToken.None).ConfigureAwait(false);
                }
                catch (ArgumentException) { rejected = true; }
                Assert(rejected && !File.Exists(rejectedOutput), "New archive creation did not reject the frozen incompatible pair before publishing output.");
            }
        }
        finally { Directory.Delete(temp, true); }
    }

    private static async Task VerifyReadAndRepairAsync(string id)
    {
        Manifest manifest = LoadManifest();
        Fixture fixture = manifest.Fixtures.Single(f => f.Id == id);
        VerifyFiles(fixture);
        string original = ArchivePath(fixture);
        var container = new KalynaContainerService();
        int modelCalls = 0;
        using IDisposable noModel = PasswordGuessabilityService.ForbidEvaluationForTesting(() => modelCalls++);
        await RejectedAsync(() => container.ReadContainerInfoAsync(original, CancellationToken.None));
        using (var source = File.OpenRead(original))
        {
            await RejectedAsync(() => container.ReadRecoveryKdfInfoAsync(source, CancellationToken.None));
            source.Position = 0;
            await RejectedAsync(() => container.VerifyAuthenticationAsync(source, fixture.Password, fixture.Pin,
                manifest.FactorAHex, manifest.FactorBHex, CancellationToken.None));
        }
        using var plaintext = new MemoryStream();
        await RejectedAsync(() => container.DecryptToStreamAsync(original, fixture.Password, fixture.Pin,
            manifest.FactorAHex, manifest.FactorBHex, plaintext, null, CancellationToken.None));
        Assert(plaintext.Length == 0, "A v12 fixture released plaintext.");
        await RejectedAsync(() => new RecoveryService().VerifyAndRepairAuthenticatedAsync(original,
            fixture.Password, fixture.Pin, manifest.FactorAHex, manifest.FactorBHex, null, CancellationToken.None));
        Assert(modelCalls == 0, "Format rejection must not evaluate credential selection policy.");
        VerifyFiles(fixture);
    }

    private static async Task RejectedAsync(Func<Task> operation)
    {
        try { await operation().ConfigureAwait(false); }
        catch (InvalidDataException) { return; }
        throw new InvalidOperationException("A production v13 reader accepted an original v12 fixture.");
    }

    private static void AssertCredentialHashes(Fixture fixture, byte[] a, byte[] b)
    {
        byte[] qs = ReferenceOldSha3(fixture.Algorithm, fixture.Password, fixture.Pin, a, b);
        byte[] qk = ReferenceOldSkein(fixture.Algorithm, fixture.Password, fixture.Pin, a, b);
        try
        {
            Assert(Convert.ToHexString(qs) == fixture.Sha3CredentialHex, "v12 SHA3 raw credential KAT changed.");
            Assert(Convert.ToHexString(qk) == fixture.SkeinCredentialHex, "v12 keyed Skein raw credential KAT changed.");
        }
        finally { CryptographicOperations.ZeroMemory(qs); CryptographicOperations.ZeroMemory(qk); }
    }
    // Test-only historical encoding oracle. It performs no Argon2, parsing or
    // decryption and cannot be called by the production application.
    private static byte[] OldLp(params byte[][] fields)
    {
        using var output = new MemoryStream(); using var writer = new BinaryWriter(output);
        foreach (byte[] field in fields) { writer.Write(field.Length); writer.Write(field); }
        return output.ToArray();
    }
    private static byte[] ReferenceOldSha3(string algorithm, string password, string pin, byte[] a, byte[] b)
    {
        var result = new byte[128];
        for (int half = 0; half < 2; half++)
        {
            byte[] input = OldLp(Encoding.UTF8.GetBytes($"Kalyna-ZPAQ/v12/{algorithm}/SHA3-512/User+PIN+Factors-A{half + 1}+B{half + 1}"),
                Encoding.UTF8.GetBytes(password), Encoding.ASCII.GetBytes(pin), a.AsSpan(half * 64, 64).ToArray(), b.AsSpan(half * 64, 64).ToArray());
            var digest = new Org.BouncyCastle.Crypto.Digests.Sha3Digest(512); digest.BlockUpdate(input); digest.DoFinal(result, half * 64);
        }
        return result;
    }
    private static byte[] ReferenceOldSkein(string algorithm, string password, string pin, byte[] a, byte[] b)
    {
        var mac = new Org.BouncyCastle.Crypto.Macs.SkeinMac(1024, 1024);
        mac.Init(new Org.BouncyCastle.Crypto.Parameters.SkeinParameters.Builder().SetKey([.. a, .. b])
            .SetPersonalisation(Encoding.UTF8.GetBytes($"Kalyna-ZPAQ/v12/{algorithm}/Skein-MAC-1024-1024/User+PIN/Factors-A+B-Key")).Build());
        mac.BlockUpdate(OldLp(Encoding.UTF8.GetBytes(password), Encoding.ASCII.GetBytes(pin)));
        byte[] output = new byte[128]; mac.DoFinal(output); return output;
    }
    private static string FixtureDirectory => Path.Combine(RepositoryLayout.FindRepositoryRoot(), "KeepVaultMac.Tests", "Fixtures", "CredentialCompatibility");
    private static string ArchivePath(Fixture fixture) => Path.Combine(FixtureDirectory, fixture.Id + ".kzpaq");
    private static void VerifyFiles(Fixture fixture) => Assert(HashFile(ArchivePath(fixture)) == fixture.ArchiveSha256 &&
        HashFile(ArchivePath(fixture) + ".kpar2") == fixture.SidecarSha256, "Frozen compatibility fixture bytes changed.");
    private static string HashFile(string path) { using var file = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(file)); }
    private static Manifest LoadManifest()
    {
        string path = Path.Combine(FixtureDirectory, "manifest.json");
        Assert(HashFile(path) == ManifestSha256, "Frozen compatibility manifest changed; review provenance before updating its pinned hash.");
        string strictPath = Path.Combine(FixtureDirectory, "strict-restore-addendum.json");
        Assert(HashFile(strictPath) == StrictRestoreEvidenceSha256, "Strict fixture-dependency restore evidence changed.");
        using (JsonDocument strict = JsonDocument.Parse(File.ReadAllBytes(strictPath)))
        {
            JsonElement proof = strict.RootElement;
            Assert(proof.GetProperty("ArchivedManifestSha256").GetString() == ManifestSha256
                && proof.GetProperty("EffectiveRestoreLockedMode").GetBoolean()
                && !proof.GetProperty("EffectiveRestoreForceEvaluate").GetBoolean()
                && proof.GetProperty("StrictRestoreExitCode").GetInt32() == 0,
                "Fixture dependency verification did not use effective strict locked mode.");
            foreach (JsonProperty file in proof.GetProperty("EvidenceFiles").EnumerateObject())
                Assert(Path.GetFileName(file.Name) == file.Name && HashFile(Path.Combine(FixtureDirectory, file.Name)) == file.Value.GetString(),
                    "Strict fixture-dependency restore transcript changed.");
        }
        Manifest result = JsonSerializer.Deserialize<Manifest>(File.ReadAllBytes(path)) ?? throw new InvalidDataException("Missing fixture manifest.");
        Assert(result.BaseCommit == "e52159e7a569a8b77fe7732006388c4401c4009f" && result.SyntheticOnly && result.ProductionArgonParameters &&
            !result.MemoryOverrideUsed && result.ContainerVersion == 12 && result.KparVersion == 4 &&
            result.Fixtures.Select(f => f.Id).SequenceEqual(FixtureIds), "Compatibility fixture provenance or inventory changed.");
        foreach ((string name, string expectedHash) in result.ProvenanceFiles)
        {
            Assert(Path.GetFileName(name) == name && HashFile(Path.Combine(FixtureDirectory, name)) == expectedHash, "Frozen fixture producer provenance changed.");
        }
        return result;
    }
    private static void Assert(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private sealed record Manifest(string BaseCommit, bool SyntheticOnly, bool ProductionArgonParameters, bool MemoryOverrideUsed,
        int ContainerVersion, int KparVersion, string FactorAHex, string FactorBHex, string PlainFileName, string PlainUtf8Hex,
        string PackedPayloadSha256, Fixture[] Fixtures, Dictionary<string, string> ProvenanceFiles);
    private sealed record Fixture(string Id, string Password, string Pin, string Suite, string Algorithm,
        string PasswordUtf8Hex, string PinAsciiHex, string Sha3CredentialHex, string SkeinCredentialHex, string ArchiveSha256, string SidecarSha256);
}
