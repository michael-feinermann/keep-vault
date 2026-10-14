using System.Security.Cryptography;
using System.Text.Json;
using KalynaArchiver.Services;

/// <summary>
/// Deliberately corrupts each application-derived secret handoff reached by
/// every suite. The small internal Argon2 KAT profile is only a fault-matrix
/// accelerator; the existing production-cost independent KATs remain separate.
/// No credential, master, role key, pointer address or buffer bytes are logged.
/// </summary>
internal static class KdfHandoffFaultTests
{
    private const string Password = "KdfFaultTest!73#PrivateSyntheticOnly";
    private const string Pin = "428317";
    private const uint FaultMemoryKiB = 8 * 1024;
    private static readonly byte[] FactorA = Sequence(128, 17);
    private static readonly byte[] FactorB = Sequence(128, 93);
    private static readonly string FactorAHex = Convert.ToHexString(FactorA);
    private static readonly string FactorBHex = Convert.ToHexString(FactorB);

    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("security.kdf-handoff-fault-matrix",
            "every suite rejects missing and 00/01/FF derived outputs before downstream key handoffs",
            TestEveryHandoffAsync, TestResource.ProcessGlobal, "Security"),
        new("security.kdf-null-width-round-contracts",
            "null/default, shortened and misplaced round secrets fail before v13 derivation",
            TestNullWidthAndRoundContractsAsync, TestResource.ProcessGlobal, "Security"),
        new("security.kdf-key-owner-contracts",
            "master and role owners reject null, disposed, zeroed and invalid-width material",
            TestKeyOwnerContractsAsync, TestResource.ProcessGlobal, "Security"),
        new("security.kdf-handoff-destination-cleanup",
            "rejected credential, master and role handoffs erase the complete caller-owned output",
            TestCallerOutputCleanupAsync, TestResource.ProcessGlobal, "Security"),
    ];

    private static Task TestEveryHandoffAsync()
    {
        long initialBytes = SecureMemory.LockedBytesForTests;
        long initialAllocations = SecureMemory.LockedAllocationsForTests;
        long initialWorking = SecureMemory.ReservedWorkingSetBytesForTests;
        int initialRetained = SecureMemory.RetainedFailedLockRollbacksForTests;
        using IDisposable memory = V13MasterKdf.UseMemoryCostForTests(FaultMemoryKiB);
        int totalBoundaries = 0;
        int totalCases = 0;
        var rows = new List<object>();

        foreach (EncryptionSuite suite in Enum.GetValues<EncryptionSuite>())
        {
            EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(suite);
            KdfSalts salts = Salts(parameters.UsesTwoKdfRounds);
            using ContainerKeyDerivation.MasterResult master = ContainerKeyDerivation.DeriveMaster(
                parameters, Password, Pin, FactorAHex, FactorBHex, salts, null, CancellationToken.None);
            var baseline = new List<string>();
            using (DerivedSecretHandoff.UseMutationForTests((boundary, _) => baseline.Add(boundary)))
            {
                using (RoleKeyMaterial normal = Derive(parameters, salts))
                {
                    Require(normal.EncryptionKey.Bytes.Length == parameters.EncryptionKeyBytes,
                        "A normal discovery traversal returned an invalid encryption width.");
                    Require(normal.Sha3MacKey.Bytes.Length == parameters.Sha3MacKeyBytes
                        && normal.SkeinMacKey.Bytes.Length == parameters.SkeinMacKeyBytes,
                        "A normal discovery traversal returned invalid MAC widths.");
                }
                DeriveRecoveryRoles(master.Master.Bytes, parameters);
            }

            Require(baseline.Count != 0, "The matrix discovered no actual production handoffs.");
            Require(baseline.Count == baseline.Distinct(StringComparer.Ordinal).Count(),
                "Production handoff IDs are not unique within a suite traversal.");
            string[] expected = ExpectedBoundaries(parameters).ToArray();
            Require(expected.All(id => baseline.Contains(id, StringComparer.Ordinal)),
                "The actual traversal omitted an independently enumerated KDF or role handoff.");
            Require(baseline.Any(id => id.EndsWith("/credential/sha3-half-0", StringComparison.Ordinal))
                && baseline.Any(id => id.EndsWith("/credential/sha3-half-1", StringComparison.Ordinal))
                && baseline.Any(id => id.EndsWith("/credential/skein-complete", StringComparison.Ordinal))
                && baseline.Any(id => id.EndsWith("/master/final-owner", StringComparison.Ordinal))
                && baseline.Any(id => id.EndsWith("/roles/ownership/skein", StringComparison.Ordinal)),
                "The discovery traversal omitted a required KDF or ownership region.");
            IReadOnlyList<CascadeStage> stages = SuiteKeySchedule.StagesOf(parameters);
            Require(baseline.Count(id => id.Contains("/stage-", StringComparison.Ordinal)
                && id.EndsWith("/truncated", StringComparison.Ordinal)) == stages.Count,
                "The actual matrix did not cover every declared cipher stage.");
            Require(baseline.Count(id => id.EndsWith("/argon2-output", StringComparison.Ordinal))
                == (parameters.UsesTwoKdfRounds ? 4 : 2),
                "The actual matrix did not cover every required Argon2 branch output.");

            foreach (string target in baseline)
            {
                bool roleOnly = target.Contains("/stage-", StringComparison.Ordinal)
                    || target.Contains("/global-", StringComparison.Ordinal)
                    || target.Contains("/roles/ownership/", StringComparison.Ordinal);
                bool recoveryRoleOnly = target.Contains("/global-Recovery", StringComparison.Ordinal);
                foreach (string fault in new[] { "00", "01", "FF", "missing-output" })
                {
                    long bytes = SecureMemory.LockedBytesForTests;
                    long allocations = SecureMemory.LockedAllocationsForTests;
                    long working = SecureMemory.ReservedWorkingSetBytesForTests;
                    int retained = SecureMemory.RetainedFailedLockRollbacksForTests;
                    var events = new List<string>();
                    int hit = 0;
                    bool returned = false;
                    Exception? failure = null;
                    using (DerivedSecretHandoff.UseMutationForTests((boundary, material) =>
                    {
                        events.Add(boundary);
                        if (!string.Equals(boundary, target, StringComparison.Ordinal)) return;
                        hit++;
                        if (fault == "missing-output")
                            throw new ArgumentNullException("injectedDerivedOutput", "Synthetic missing output at the selected handoff.");
                        material.Fill(fault switch { "00" => (byte)0x00, "01" => (byte)0x01, _ => (byte)0xFF });
                    }))
                    {
                        try
                        {
                            if (recoveryRoleOnly)
                                DeriveRecoveryRoles(master.Master.Bytes, parameters);
                            else
                            {
                                using RoleKeyMaterial invalid = roleOnly
                                    ? SuiteKeySchedule.DeriveSuiteKeys(master.Master.Bytes, parameters)
                                    : Derive(parameters, salts);
                            }
                            returned = true;
                        }
                        catch (Exception rejected)
                        {
                            failure = rejected;
                        }
                    }

                    Require(hit == 1, $"The selected fault boundary was not hit exactly once: {suite}, {target}, {fault}.");
                    Require(!returned, $"A corrupted handoff returned success: {suite}, {target}, {fault}.");
                    Require(fault == "missing-output" ? failure is ArgumentNullException : failure is CryptographicException,
                        $"A corrupted handoff returned an unexpected failure category: {suite}, {target}, {fault}.");
                    Require(events.Count != 0 && events[^1] == target,
                        $"A downstream handoff executed after a rejected secret: {suite}, {target}, {fault}.");
                    Require(SecureMemory.LockedBytesForTests == bytes
                        && SecureMemory.LockedAllocationsForTests == allocations
                        && SecureMemory.ReservedWorkingSetBytesForTests == working
                        && SecureMemory.RetainedFailedLockRollbacksForTests == retained,
                        $"A rejected handoff leaked a secure-memory reservation: {suite}, {target}, {fault}.");
                    totalCases++;
                }
            }

            totalBoundaries += baseline.Count;
            rows.Add(new { suite = suite.ToString(), boundaryCount = baseline.Count,
                caseCount = baseline.Count * 4, boundaries = baseline,
                faults = new[] { "00", "01", "FF", "missing-output" }, status = "PASS" });
        }

        Require(SecureMemory.LockedBytesForTests == initialBytes
            && SecureMemory.LockedAllocationsForTests == initialAllocations
            && SecureMemory.ReservedWorkingSetBytesForTests == initialWorking
            && SecureMemory.RetainedFailedLockRollbacksForTests == initialRetained,
            "The complete handoff matrix left a secure-memory reservation outstanding.");
        Console.WriteLine("KDF_HANDOFF_MATRIX " + JsonSerializer.Serialize(new
        {
            status = "PASS", profile = "internal-8-MiB-fault-injection-only", suiteCount = rows.Count,
            boundaryCount = totalBoundaries, caseCount = totalCases, rows,
        }));
        return Task.CompletedTask;
    }

    private static Task TestNullWidthAndRoundContractsAsync()
    {
        const string algorithm = EncryptionSuiteCatalog.ParanoiaAlgorithm;
        byte[] qs = Sequence(128, 11), qk = Sequence(128, 61), m1 = Sequence(128, 127);
        byte[] salt = Sequence(64, 5), otherSalt = Sequence(64, 43), destination = new byte[128];
        byte[] context = SuiteKeySchedule.RoleContext(algorithm, 0, "AES-256", KeyRolePurpose.Encryption, 256);
        byte[] roleDestination = new byte[128];
        long beforeBytes = SecureMemory.LockedBytesForTests;
        long beforeAllocations = SecureMemory.LockedAllocationsForTests;
        using IDisposable memory = V13MasterKdf.UseMemoryCostForTests(FaultMemoryKiB);
        try
        {
            EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(EncryptionSuite.ParanoiaCascade);
            KdfSalts salts = Salts(twoRounds: true);
            Expect<ArgumentNullException>(() => ContainerKeyDerivation.DeriveMaster(null!, Password, Pin, FactorAHex, FactorBHex, salts, null, default));
            Expect<ArgumentNullException>(() => ContainerKeyDerivation.DeriveMaster(parameters, Password, Pin, FactorAHex, FactorBHex, null!, null, default));
            Expect<ArgumentNullException>(() => ContainerKeyDerivation.DeriveMaster(parameters, null!, Pin, FactorAHex, FactorBHex, salts, null, default));
            Expect<ArgumentNullException>(() => ContainerKeyDerivation.DeriveMaster(parameters, Password, null!, FactorAHex, FactorBHex, salts, null, default));
            Expect<ArgumentNullException>(() => ContainerKeyDerivation.DeriveMaster(parameters, Password, Pin, null!, FactorBHex, salts, null, default));
            Expect<ArgumentNullException>(() => ContainerKeyDerivation.DeriveMaster(parameters, Password, Pin, FactorAHex, null!, salts, null, default));
            Expect<ArgumentNullException>(() => ContainerKeyDerivation.DeriveMaster(parameters, Password, Pin, FactorAHex, FactorBHex,
                new KdfSalts(null!, salt, otherSalt, salt), null, default));
            Expect<ArgumentNullException>(() => ContainerKeyDerivation.DeriveMaster(parameters, Password, Pin, FactorAHex, FactorBHex,
                new KdfSalts(salt, null!, otherSalt, salt), null, default));
            Expect<ArgumentNullException>(() => ContainerKeyDerivation.ParseFactor((string)null!, "factor"));
            Expect<ArgumentException>(() => ContainerKeyDerivation.ParseFactor(default(ReadOnlySpan<char>), "factor"));
            Expect<ArgumentNullException>(() => V13MasterKdf.DeriveSha3CredentialHash(algorithm, null!, Pin, FactorA, FactorB, destination));
            Expect<ArgumentNullException>(() => V13MasterKdf.DeriveSkeinCredentialHash(algorithm, Password, null!, FactorA, FactorB, destination));
            Expect<ArgumentException>(() => V13MasterKdf.DeriveSha3CredentialHash(algorithm, Password, Pin, default, FactorB, destination));
            Expect<ArgumentException>(() => V13MasterKdf.DeriveSkeinCredentialHash(algorithm, Password, Pin, FactorA, new byte[127], destination));
            Expect<ArgumentException>(() => V13MasterKdf.DeriveSha3CredentialHash(algorithm, Password, Pin, FactorA, FactorB, default));
            Expect<ArgumentException>(() => V13MasterKdf.DeriveSkeinCredentialHash(algorithm, Password, Pin, FactorA, FactorB, new byte[127]));

            foreach (int round in new[] { 0, -1, 3 })
            {
                Expect<ArgumentOutOfRangeException>(() => V13MasterKdf.DerivePmi(algorithm, round, qs, qk, default, salt, otherSalt));
                Expect<ArgumentOutOfRangeException>(() => V13MasterKdf.DeriveRoundMaster(algorithm, round, qs, qk, salt, otherSalt, default, FaultMemoryKiB, destination));
            }
            Expect<ArgumentException>(() => V13MasterKdf.DerivePmi(algorithm, 1, default, qk, default, salt, otherSalt));
            Expect<ArgumentException>(() => V13MasterKdf.DerivePmi(algorithm, 1, qs, new byte[127], default, salt, otherSalt));
            Expect<ArgumentException>(() => V13MasterKdf.DerivePmi(algorithm, 1, qs, qk, default, default, otherSalt));
            Expect<ArgumentException>(() => V13MasterKdf.DerivePmi(algorithm, 1, qs, qk, m1, salt, otherSalt));
            Expect<ArgumentException>(() => V13MasterKdf.DerivePmi(algorithm, 2, qs, qk, default, salt, otherSalt));
            Expect<ArgumentException>(() => V13MasterKdf.DerivePmi(algorithm, 2, qs, qk, new byte[64], salt, otherSalt));
            Expect<ArgumentException>(() => V13MasterKdf.DeriveRoundMaster(algorithm, 1, default, qk, salt, otherSalt, default, FaultMemoryKiB, destination));
            Expect<ArgumentException>(() => V13MasterKdf.DeriveRoundMaster(algorithm, 1, qs, default, salt, otherSalt, default, FaultMemoryKiB, destination));
            Expect<ArgumentException>(() => V13MasterKdf.DeriveRoundMaster(algorithm, 1, qs, qk, default, otherSalt, default, FaultMemoryKiB, destination));
            Expect<ArgumentException>(() => V13MasterKdf.DeriveRoundMaster(algorithm, 1, qs, qk, salt, otherSalt, m1, FaultMemoryKiB, destination));
            Expect<ArgumentException>(() => V13MasterKdf.DeriveRoundMaster(algorithm, 2, qs, qk, salt, otherSalt, default, FaultMemoryKiB, destination));
            Expect<ArgumentException>(() => V13MasterKdf.DeriveRoundMaster(algorithm, 2, qs, qk, salt, otherSalt, new byte[127], FaultMemoryKiB, destination));
            Expect<ArgumentException>(() => V13MasterKdf.DeriveRoundMaster(algorithm, 1, qs, qk, salt, new byte[63], default, FaultMemoryKiB, destination));
            Expect<ArgumentException>(() => V13MasterKdf.DeriveRoundMaster(algorithm, 1, qs, qk, salt, otherSalt, default, FaultMemoryKiB, default));
            Expect<ArgumentException>(() => SuiteKeySchedule.DeriveRoleValue(default, context, roleDestination));
            Expect<ArgumentException>(() => SuiteKeySchedule.DeriveRoleValue(m1, default, roleDestination));
            Expect<ArgumentException>(() => SuiteKeySchedule.DeriveRoleValue(m1, context, default));
            Expect<ArgumentException>(() => SuiteKeySchedule.DeriveRoleKey(new byte[127], algorithm, 0, "AES-256", KeyRolePurpose.Encryption, new byte[32]));
            Expect<ArgumentException>(() => SuiteKeySchedule.DeriveGlobalKey(default, algorithm, "HMAC-SHA3-512", KeyRolePurpose.Sha3Mac, new byte[64]));
            Expect<ArgumentOutOfRangeException>(() => SuiteKeySchedule.DeriveGlobalKey(m1, algorithm, "HMAC-SHA3-512", KeyRolePurpose.Sha3Mac, default(Span<byte>)));
            Expect<ArgumentException>(() => SuiteKeySchedule.DeriveSuiteKeys(default, parameters));
            Expect<ArgumentNullException>(() => SuiteKeySchedule.DeriveSuiteKeys(m1, null!));
            foreach (byte pattern in new byte[] { 0x00, 0x01, 0xFF })
            {
                byte[] faulty = Enumerable.Repeat(pattern, 128).ToArray();
                Expect<CryptographicException>(() => V13MasterKdf.DerivePmi(algorithm, 1, faulty, qk, default, salt, otherSalt));
                Expect<CryptographicException>(() => V13MasterKdf.DeriveRoundMaster(algorithm, 2, qs, qk, salt, otherSalt, faulty, FaultMemoryKiB, destination));
                Expect<CryptographicException>(() => SuiteKeySchedule.DeriveRoleValue(faulty, context, roleDestination));
                CryptographicOperations.ZeroMemory(faulty);
            }

            // Unlike a missing round-two M1, the empty round-one secret is a
            // valid protocol input. The native primitive KAT independently
            // keeps its valid zero-key inputs; no primitive policy is changed.
            V13MasterKdf.DeriveRoundMaster(algorithm, 1, qs, qk, salt, otherSalt, default, FaultMemoryKiB, destination);
            DerivedSecretHandoff.Require(destination, V13MasterKdf.MasterBytes);
        }
        finally
        {
            foreach (byte[] buffer in new[] { qs, qk, m1, salt, otherSalt, destination, context, roleDestination })
                CryptographicOperations.ZeroMemory(buffer);
        }
        Require(SecureMemory.LockedBytesForTests == beforeBytes
            && SecureMemory.LockedAllocationsForTests == beforeAllocations,
            "Invalid KDF contracts or the valid round-one control leaked locked buffers.");
        return Task.CompletedTask;
    }

    private static Task TestKeyOwnerContractsAsync()
    {
        long beforeBytes = SecureMemory.LockedBytesForTests;
        long beforeAllocations = SecureMemory.LockedAllocationsForTests;
        Expect<ArgumentNullException>(() => new ContainerKeyDerivation.MasterResult(null!, V13MasterKdf.MemoryMinKiB, null));
        using (LockedSensitiveBuffer shortMaster = Buffer(64, 7))
            Expect<ArgumentException>(() => new ContainerKeyDerivation.MasterResult(shortMaster, V13MasterKdf.MemoryMinKiB, null));
        using (LockedSensitiveBuffer disposedMaster = Buffer(128, 7))
        {
            disposedMaster.Dispose();
            Expect<ObjectDisposedException>(() => new ContainerKeyDerivation.MasterResult(disposedMaster, V13MasterKdf.MemoryMinKiB, null));
        }
        using (LockedSensitiveBuffer zeroedMaster = Buffer(128, 7))
        {
            zeroedMaster.ZeroForDisposal();
            Expect<ObjectDisposedException>(() => new ContainerKeyDerivation.MasterResult(zeroedMaster, V13MasterKdf.MemoryMinKiB, null));
        }
        foreach (byte pattern in new byte[] { 0x00, 0x01, 0xFF })
        {
            using LockedSensitiveBuffer faulty = Buffer(128, 7);
            faulty.Bytes.AsSpan().Fill(pattern);
            Expect<CryptographicException>(() => new ContainerKeyDerivation.MasterResult(faulty, V13MasterKdf.MemoryMinKiB, null));
            Require(faulty.Bytes.All(value => value == 0), "A rejected master-owner output was not wiped.");
        }
        using (LockedSensitiveBuffer encryption = Buffer(32, 13))
        using (LockedSensitiveBuffer sha3 = Buffer(64, 37))
        using (LockedSensitiveBuffer skein = Buffer(128, 83))
        {
            Expect<ArgumentNullException>(() => new RoleKeyMaterial(null!, sha3, skein));
            Expect<ArgumentNullException>(() => new RoleKeyMaterial(encryption, null!, skein));
            Expect<ArgumentNullException>(() => new RoleKeyMaterial(encryption, sha3, null!));
        }
        for (int owner = 0; owner < 3; owner++)
        {
            using LockedSensitiveBuffer encryption = Buffer(32, 13);
            using LockedSensitiveBuffer sha3 = Buffer(64, 37);
            using LockedSensitiveBuffer skein = Buffer(128, 83);
            LockedSensitiveBuffer selected = owner switch { 0 => encryption, 1 => sha3, _ => skein };
            selected.Dispose();
            Expect<ObjectDisposedException>(() => new RoleKeyMaterial(encryption, sha3, skein));
        }
        for (int owner = 0; owner < 3; owner++)
        {
            using LockedSensitiveBuffer encryption = Buffer(32, 13);
            using LockedSensitiveBuffer sha3 = Buffer(64, 37);
            using LockedSensitiveBuffer skein = Buffer(128, 83);
            LockedSensitiveBuffer selected = owner switch { 0 => encryption, 1 => sha3, _ => skein };
            selected.ZeroForDisposal();
            Expect<ObjectDisposedException>(() => new RoleKeyMaterial(encryption, sha3, skein));
        }
        foreach (byte pattern in new byte[] { 0x00, 0x01, 0xFF })
        for (int owner = 0; owner < 3; owner++)
        {
            using LockedSensitiveBuffer encryption = Buffer(32, 13);
            using LockedSensitiveBuffer sha3 = Buffer(64, 37);
            using LockedSensitiveBuffer skein = Buffer(128, 83);
            LockedSensitiveBuffer selected = owner switch { 0 => encryption, 1 => sha3, _ => skein };
            selected.Bytes.AsSpan().Fill(pattern);
            Expect<CryptographicException>(() => new RoleKeyMaterial(encryption, sha3, skein));
            Require(selected.Bytes.All(value => value == 0), "A rejected role-owner output was not wiped.");
        }
        using (LockedSensitiveBuffer encryption = Buffer(32, 13))
        using (LockedSensitiveBuffer shortSha3 = Buffer(63, 37))
        using (LockedSensitiveBuffer skein = Buffer(128, 83))
            Expect<ArgumentException>(() => new RoleKeyMaterial(encryption, shortSha3, skein));
        using (LockedSensitiveBuffer encryption = Buffer(32, 13))
        using (LockedSensitiveBuffer sha3 = Buffer(64, 37))
        using (LockedSensitiveBuffer shortSkein = Buffer(127, 83))
            Expect<ArgumentException>(() => new RoleKeyMaterial(encryption, sha3, shortSkein));
        Require(SecureMemory.LockedBytesForTests == beforeBytes
            && SecureMemory.LockedAllocationsForTests == beforeAllocations,
            "Rejected key owners leaked locked buffers.");
        return Task.CompletedTask;
    }

    private static Task TestCallerOutputCleanupAsync()
    {
        const string algorithm = EncryptionSuiteCatalog.StandardAlgorithm;
        byte[] qs = Sequence(128, 11), qk = Sequence(128, 61), master = Sequence(128, 127);
        byte[] salt = Sequence(64, 5), otherSalt = Sequence(64, 43);
        byte[] context = SuiteKeySchedule.RoleContext(algorithm, 0, "AES-256", KeyRolePurpose.Encryption, 256);
        string stage = $"v13/{algorithm}/stage-0/AES-256/{KeyRolePurpose.Encryption}";
        string global = $"v13/{algorithm}/global-{KeyRolePurpose.Sha3Mac}/HMAC-SHA3-512";
        var cases = new List<(string Boundary, int Width, Action<byte[]> Derive)>();
        foreach (string half in new[] { "sha3-half-0", "sha3-half-1", "sha3-complete" })
            cases.Add(($"v13/{algorithm}/credential/{half}", 128, output =>
                V13MasterKdf.DeriveSha3CredentialHash(algorithm, Password, Pin, FactorA, FactorB, output)));
        cases.Add(($"v13/{algorithm}/credential/skein-complete", 128, output =>
            V13MasterKdf.DeriveSkeinCredentialHash(algorithm, Password, Pin, FactorA, FactorB, output)));
        cases.Add(($"v13/{algorithm}/round-1/master-interleaved", 128, output =>
            V13MasterKdf.DeriveRoundMaster(algorithm, 1, qs, qk, salt, otherSalt, default, FaultMemoryKiB, output)));
        foreach (string suffix in new[] { "hkdf-half-0", "hkdf-half-1", "hkdf-complete", "skein-branch", "combined" })
            cases.Add(($"v13/role/direct/{suffix}", 128, output =>
                SuiteKeySchedule.DeriveRoleValue(master, context, output)));
        cases.Add(($"{stage}/truncated", 32, output =>
            SuiteKeySchedule.DeriveRoleKey(master, algorithm, 0, "AES-256", KeyRolePurpose.Encryption, output)));
        cases.Add(($"{global}/truncated", 64, output =>
            SuiteKeySchedule.DeriveGlobalKey(master, algorithm, "HMAC-SHA3-512", KeyRolePurpose.Sha3Mac, output)));
        long beforeBytes = SecureMemory.LockedBytesForTests;
        long beforeAllocations = SecureMemory.LockedAllocationsForTests;
        using IDisposable memory = V13MasterKdf.UseMemoryCostForTests(FaultMemoryKiB);
        try
        {
            foreach ((string boundary, int width, Action<byte[]> derive) in cases)
            foreach (string fault in new[] { "00", "01", "FF", "missing-output" })
            {
                byte[] output = Enumerable.Repeat((byte)0xA6, width).ToArray();
                int hit = 0;
                using (DerivedSecretHandoff.UseMutationForTests((actual, material) =>
                {
                    if (actual != boundary) return;
                    hit++;
                    if (fault == "missing-output") throw new ArgumentNullException("injectedDerivedOutput");
                    material.Fill(fault switch { "00" => (byte)0x00, "01" => (byte)0x01, _ => (byte)0xFF });
                }))
                {
                    if (fault == "missing-output") Expect<ArgumentNullException>(() => derive(output));
                    else Expect<CryptographicException>(() => derive(output));
                }
                Require(hit == 1, $"The caller-output fault did not reach the selected boundary: {boundary}.");
                Require(output.All(value => value == 0), $"A rejected output retained caller-visible secret bytes: {boundary}.");
            }
        }
        finally
        {
            foreach (byte[] buffer in new[] { qs, qk, master, salt, otherSalt, context })
                CryptographicOperations.ZeroMemory(buffer);
        }
        Require(SecureMemory.LockedBytesForTests == beforeBytes
            && SecureMemory.LockedAllocationsForTests == beforeAllocations,
            "Rejected caller-output handoffs leaked locked buffers.");
        return Task.CompletedTask;
    }

    private static RoleKeyMaterial Derive(EncryptionSuiteParameters parameters, KdfSalts salts) =>
        ContainerKeyDerivation.DeriveSuiteKeys(parameters, Password, Pin, FactorAHex, FactorBHex,
            salts, null, CancellationToken.None);

    private static void DeriveRecoveryRoles(ReadOnlySpan<byte> master, EncryptionSuiteParameters parameters)
    {
        byte[]? sha3 = null, skein = null;
        try
        {
            sha3 = SuiteKeySchedule.DeriveGlobalKey(master, parameters.Algorithm,
                "KPAR2/HMAC-SHA3-512", KeyRolePurpose.RecoverySha3Certification, parameters.Sha3MacKeyBytes);
            skein = SuiteKeySchedule.DeriveGlobalKey(master, parameters.Algorithm,
                "KPAR2/Skein-MAC-1024-1024", KeyRolePurpose.RecoverySkeinCertification, parameters.SkeinMacKeyBytes);
        }
        finally
        {
            if (sha3 is not null) CryptographicOperations.ZeroMemory(sha3);
            if (skein is not null) CryptographicOperations.ZeroMemory(skein);
        }
    }

    private static IEnumerable<string> ExpectedBoundaries(EncryptionSuiteParameters parameters)
    {
        string prefix = $"v13/{parameters.Algorithm}";
        foreach (string credential in new[] { "sha3-half-0", "sha3-half-1", "sha3-complete", "skein-complete" })
            yield return $"{prefix}/credential/{credential}";
        for (int round = 1; round <= (parameters.UsesTwoKdfRounds ? 2 : 1); round++)
        {
            foreach (string branch in new[] { "sha3", "skein" })
            {
                yield return $"{prefix}/round-{round}/{branch}/password-copy";
                if (round == 2) yield return $"{prefix}/round-{round}/{branch}/secret-copy";
                yield return $"{prefix}/round-{round}/{branch}/argon2-output";
            }
            yield return $"{prefix}/round-{round}/master-interleaved";
            yield return $"{prefix}/master/round-{round}-ready";
        }
        yield return $"{prefix}/master/final-owner";
        yield return $"{prefix}/master/role-schedule-input";
        IReadOnlyList<CascadeStage> stages = SuiteKeySchedule.StagesOf(parameters);
        for (int stage = 0; stage < stages.Count; stage++)
        {
            string role = $"{prefix}/stage-{stage}/{SuiteKeySchedule.CanonicalCipherString(stages[stage].Cipher)}/{KeyRolePurpose.Encryption}";
            foreach (string suffix in RoleSuffixes()) yield return $"{role}/{suffix}";
        }
        foreach ((KeyRolePurpose purpose, string cipher) in new[]
        {
            (KeyRolePurpose.Sha3Mac, "HMAC-SHA3-512"),
            (KeyRolePurpose.SkeinMac, "Skein-MAC-1024-1024"),
            (KeyRolePurpose.RecoverySha3Certification, "KPAR2/HMAC-SHA3-512"),
            (KeyRolePurpose.RecoverySkeinCertification, "KPAR2/Skein-MAC-1024-1024"),
        })
            foreach (string suffix in RoleSuffixes()) yield return $"{prefix}/global-{purpose}/{cipher}/{suffix}";
        foreach (string owner in new[] { "encryption", "sha3", "skein" })
            yield return $"{prefix}/roles/ownership/{owner}";

        static string[] RoleSuffixes() =>
            ["hkdf-half-0", "hkdf-half-1", "hkdf-complete", "skein-branch", "combined", "truncated"];
    }

    private static KdfSalts Salts(bool twoRounds) => new(
        Sequence(64, 3), Sequence(64, 67), twoRounds ? Sequence(64, 131) : null,
        twoRounds ? Sequence(64, 199) : null);

    private static LockedSensitiveBuffer Buffer(int length, int seed)
    {
        LockedSensitiveBuffer owner = LockedSensitiveBuffer.Create(length);
        for (int index = 0; index < length; index++) owner.Bytes[index] = (byte)(seed + index * 29);
        return owner;
    }

    private static byte[] Sequence(int length, int seed) =>
        Enumerable.Range(0, length).Select(index => (byte)(seed + index * 29)).ToArray();

    private static void Expect<TException>(Action action) where TException : Exception
    {
        try { action(); }
        catch (TException) { return; }
        throw new InvalidOperationException($"Expected {typeof(TException).Name} from an invalid handoff contract.");
    }

    private static void Require(bool condition, string failure)
    {
        if (!condition) throw new InvalidOperationException(failure);
    }
}
