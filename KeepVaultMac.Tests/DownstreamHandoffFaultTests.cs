using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using KalynaArchiver.Services;

internal static class DownstreamHandoffFaultTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("security.downstream-suite-handoff-faults", "All 12 suite ownership/cipher handoffs reject missing and 00/01/FF material", SuiteFaults, TestResource.ProcessGlobal, "Security"),
        new("security.downstream-mac-handoff-faults", "Serial and parallel MAC tree handoffs reject missing and 00/01/FF material", MacFaults, TestResource.ProcessGlobal, "Security"),
        new("security.downstream-recovery-handoff-faults", "Recovery parent/certification handoffs reject missing and 00/01/FF material", RecoveryFaults, TestResource.ProcessGlobal, "Security"),
        new("security.downstream-disposed-owner-faults", "Cleared owners reject reads after disposal and failed-unlock retry", DisposedOwners, TestResource.ProcessGlobal, "Security"),
        new("security.downstream-null-width-contracts", "Owner APIs reject real null and default/truncated key material", NullWidthContracts, TestResource.ProcessGlobal, "Security"),
    ];

    private enum Fault { Missing, Zero, ByteOne, AllBitsOne }
    private sealed record Receipt(string Boundary, string Fault, string Context, int InjectionHits,
        bool NoCompletedResult, bool CallerOwnedAliasesErased, bool LockAllocationBaselineRestored,
        string ErasureObservationScope = "Caller-owned arrays and successful/failed owner disposal; internal temporary spans are not retained");

    private sealed class Probe(string? target = null, Fault? fault = null)
    {
        private int _injected;
        private int _peakCpuPermits;
        internal readonly ConcurrentDictionary<string, int> Observed = new(StringComparer.Ordinal);
        internal int InjectionHits => Volatile.Read(ref _injected);
        internal int PeakCpuPermits => Volatile.Read(ref _peakCpuPermits);
        internal void Visit(string boundary, Span<byte> material)
        {
            // Leaf consumer callbacks run inside their actual CPU lease.
            // Observe owned permits directly instead of inferring concurrency
            // from a requested worker count or a sampling timer.
            int active = CpuWorkBudget.ActiveWorkersForTests;
            int previous;
            do { previous = Volatile.Read(ref _peakCpuPermits); if (active <= previous) break; }
            while (Interlocked.CompareExchange(ref _peakCpuPermits, active, previous) != previous);
            Observed.AddOrUpdate(boundary, 1, (_, count) => count + 1);
            if (boundary != target || !fault.HasValue || Interlocked.CompareExchange(ref _injected, 1, 0) != 0) return;
            if (fault == Fault.Missing)
            {
                // A missing producer handoff raises its required-input failure.
                // Actual NULL references/pointers are tested separately; Span
                // cannot represent a non-empty NULL buffer safely.
                throw new ArgumentNullException("material", "Injected missing producer handoff.");
            }
            material.Fill(fault switch { Fault.Zero => (byte)0, Fault.ByteOne => (byte)1, _ => (byte)255 });
        }
    }

    private static void Require(bool good, string message)
    {
        if (!good) throw new InvalidOperationException(message);
    }
    private static byte[] Public(int length, int seed = 7) => Enumerable.Range(0, length).Select(index => (byte)(index * 29 + seed)).ToArray();
    private static void Erase(params byte[][] arrays)
    {
        foreach (byte[] array in arrays) CryptographicOperations.ZeroMemory(array);
    }
    private static bool IsErased(byte[] bytes) => bytes.All(value => value == 0);
    private static bool HasFailure<T>(Exception exception) where T : Exception => exception is T
        || exception is AggregateException aggregate && aggregate.Flatten().InnerExceptions.Any(HasFailure<T>)
        || exception is TargetInvocationException invocation && invocation.InnerException is not null && HasFailure<T>(invocation.InnerException);
    private static void RequireInjectedFailure(Exception error, Fault fault)
    {
        Require(fault == Fault.Missing ? HasFailure<ArgumentNullException>(error) : HasFailure<CryptographicException>(error),
            "The targeted handoff did not report its expected fail-closed cause.");
    }
    private static void Emit(string id, IReadOnlyList<Receipt> cases, object? normal = null) =>
        Console.WriteLine("handoff_fault_matrix=" + JsonSerializer.Serialize(new { TestId = id, Cases = cases, Normal = normal,
            Scope = "Public synthetic fixtures; no key bytes or addresses; NULL producer failure and ABI NULL tests are distinct" }));

    private static RoleKeyMaterial FixtureRoles(EncryptionSuiteParameters parameters, out byte[][] aliases)
    {
        LockedSensitiveBuffer? encryption = null, sha3 = null, skein = null;
        try
        {
            encryption = LockedSensitiveBuffer.Create(parameters.EncryptionKeyBytes);
            sha3 = LockedSensitiveBuffer.Create(parameters.Sha3MacKeyBytes);
            skein = LockedSensitiveBuffer.Create(parameters.SkeinMacKeyBytes);
            byte[] first = Public(parameters.EncryptionKeyBytes, 7), second = Public(parameters.Sha3MacKeyBytes, 13), third = Public(parameters.SkeinMacKeyBytes, 19);
            try { first.CopyTo(encryption.Bytes, 0); second.CopyTo(sha3.Bytes, 0); third.CopyTo(skein.Bytes, 0); }
            finally { Erase(first, second, third); }
            aliases = [encryption.Bytes, sha3.Bytes, skein.Bytes];
            var result = new RoleKeyMaterial(encryption, sha3, skein);
            encryption = null; sha3 = null; skein = null;
            return result;
        }
        finally { SecureMemory.ZeroAndDisposeAll(encryption, sha3, skein); }
    }

    private static List<string> SuiteBoundaries(EncryptionSuiteParameters parameters)
    {
        string prefix = $"v13/{parameters.Algorithm}/suite-copy";
        var result = new List<string> { prefix + "/encryption", prefix + "/sha3-mac", prefix + "/skein-mac" };
        if (parameters.Cascade is { } layout)
        {
            for (int stage = 0; stage < layout.Stages.Count; stage++)
            {
                CascadeStage spec = layout.Stages[stage];
                result.Add($"{prefix}/stage-{stage}/{spec.Cipher}");
                result.Add(stage == layout.Stages.Count - 1 && layout.OutermostIsAead
                    ? $"cipher/stage-{stage}/XChaCha20Poly1305/aead-copy"
                    : $"cipher/stage-{stage}/{spec.Cipher}/ctr-copy");
            }
        }
        else result.Add($"cipher/{parameters.Suite}/standalone-consumer");
        return result;
    }

    private static Task SuiteFaults()
    {
        using IDisposable worker = NativeCipherWorkerBudget.EnterScope(1);
        var rows = new List<Receipt>();
        var normal = new List<object>();
        EncryptionSuite[] suites = Enum.GetValues<EncryptionSuite>();
        Require(suites.Length == 12, "The suite handoff inventory must cover all 12 suites.");
        int outerAead = 0;
        foreach (EncryptionSuite suite in suites)
        {
            EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(suite);
            List<string> expected = SuiteBoundaries(parameters);
            Probe success = RunSuite(parameters, null, null, rows);
            foreach (string boundary in expected) Require(success.Observed.TryGetValue(boundary, out int count) && count == 1,
                "A production suite boundary is missing or duplicated: " + boundary);
            Require(success.Observed.Keys.Where(id => id.Contains("/suite-copy/", StringComparison.Ordinal) || id.StartsWith("cipher/", StringComparison.Ordinal))
                .ToHashSet(StringComparer.Ordinal).SetEquals(expected), "The production suite handoff inventory changed without coverage.");
            if (parameters.Cascade is { OutermostIsAead: true }) outerAead++;
            normal.Add(new { Suite = suite.ToString(), Boundaries = expected, SuccessfulProductionChunk = true });
            foreach (string boundary in expected)
            foreach (Fault fault in Enum.GetValues<Fault>()) RunSuite(parameters, boundary, fault, rows);
        }
        Require(outerAead == 5, "The five outer AEAD suite copies were not covered.");
        Emit("security.downstream-suite-handoff-faults", rows, normal);
        return Task.CompletedTask;
    }

    private static Probe RunSuite(EncryptionSuiteParameters parameters, string? target, Fault? fault, List<Receipt> rows)
    {
        long baseline = SecureMemory.LockedAllocationsForTests;
        RoleKeyMaterial? roles = null;
        KalynaContainerService.SuiteKeyMaterial? suite = null;
        byte[][] roleAliases = [], suiteAliases = [];
        byte[] input = Public(2049), output = Public(2049), counter = Public(parameters.StageNonceBytes, 5), tweak = Public(parameters.TweakBytes, 11), tag = Public(16, 17);
        var probe = new Probe(target, fault);
        bool completed = false;
        try
        {
            roles = FixtureRoles(parameters, out roleAliases);
            using IDisposable mutation = DerivedSecretHandoff.UseMutationForTests(probe.Visit);
            try
            {
                suite = KalynaContainerService.SuiteKeyMaterial.FromRoleKeys(roles, parameters);
                suiteAliases = [suite.EncryptionKey, suite.Sha3MacKey, suite.SkeinMacKey];
                KalynaContainerService.EncryptSuiteChunkForTests(parameters, suite.EncryptionKey, tweak, counter, input, output, input.Length, "public-handoff-AAD"u8, tag);
                completed = true;
            }
            catch (Exception error) when (fault.HasValue) { RequireInjectedFailure(error, fault.Value); }
            Require(fault.HasValue ? !completed && probe.InjectionHits == 1 : completed && probe.InjectionHits == 0,
                "The suite fault did not reach exactly one targeted guard or returned success.");
        }
        finally
        {
            suite?.Dispose();
            roles?.Dispose();
            Erase(input, output, counter, tweak, tag);
        }
        Require(roleAliases.All(IsErased) && suiteAliases.All(IsErased), "A caller-owned suite/role array survived owner cleanup.");
        Require(SecureMemory.LockedAllocationsForTests == baseline, "A suite handoff fault leaked a sensitive lock.");
        if (target is not null) rows.Add(new(target, fault!.Value.ToString(), parameters.Suite.ToString(), probe.InjectionHits,
            !completed, true, true));
        return probe;
    }

    private static readonly string[] MacBoundaries =
    [
        "mac/tree/sha3-parent-consumer", "mac/tree/skein-parent-consumer",
        "mac/tree/sha3-leaf-derived", "mac/tree/sha3-root-derived",
        "mac/tree/skein-leaf-derived", "mac/tree/skein-root-derived",
        "mac/tree/sha3-root-consumer", "mac/tree/skein-root-consumer",
        "mac/tree/sha3-leaf-consumer", "mac/tree/skein-leaf-consumer",
    ];

    private static async Task MacFaults()
    {
        Require(CpuTopology.AvailableWorkers >= 2, "A real host with at least two CPU workers is required for the parallel MAC handoff case.");
        var rows = new List<Receipt>();
        var normal = new List<object>();
        (byte[] Sha3, byte[] Skein) serial = ([], []), parallel = ([], []);
        try
        {
            foreach (int workers in new[] { 1, 2 })
            {
                var successful = await RunMac(workers, null, null, rows).ConfigureAwait(false);
                if (workers == 1) serial = successful.Tags; else parallel = successful.Tags;
                foreach (string boundary in MacBoundaries) Require(successful.Probe.Observed.ContainsKey(boundary), "Missing production MAC boundary: " + boundary);
                Require(successful.Probe.Observed.Keys.Where(id => id.StartsWith("mac/", StringComparison.Ordinal)).ToHashSet(StringComparer.Ordinal)
                    .SetEquals(MacBoundaries), "The MAC handoff inventory changed without coverage.");
                if (workers == 2) Require(successful.PeakCpuPermits >= 2, "The parallel MAC case did not obtain at least two actual CPU permits.");
                normal.Add(new { Workers = workers, Leaves = 3, PeakActualCpuPermits = successful.PeakCpuPermits, Boundaries = MacBoundaries, SuccessfulProductionMac = true });
                foreach (string boundary in MacBoundaries)
                foreach (Fault fault in Enum.GetValues<Fault>()) await RunMac(workers, boundary, fault, rows).ConfigureAwait(false);
            }
            Require(serial.Sha3.AsSpan().SequenceEqual(parallel.Sha3) && serial.Skein.AsSpan().SequenceEqual(parallel.Skein), "Serial and parallel handoff traversals produced different MAC tags.");
        }
        finally { Erase(serial.Sha3, serial.Skein, parallel.Sha3, parallel.Skein); }
        Emit("security.downstream-mac-handoff-faults", rows, normal);
    }

    private static async Task<(Probe Probe, (byte[] Sha3, byte[] Skein) Tags, int PeakCpuPermits)> RunMac(int workers, string? target, Fault? fault, List<Receipt> rows)
    {
        string directory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var policy = new ArchiveOperationPolicy(directory, directory, memoryBudgetBytes: 256L << 20, maxCpuWorkers: workers);
        long baseline = SecureMemory.LockedAllocationsForTests;
        byte[] sha3 = Public(64, 13), skein = Public(128, 19), data = Public(2 * ParallelContainerAuthenticator.LeafBytes + 333);
        var probe = new Probe(target, fault);
        bool completed = false;
        bool resultTransferred = false;
        (byte[] Sha3, byte[] Skein) tags = ([], []);
        try
        {
            try
            {
                using IDisposable policyScope = policy.EnterScope();
                using IDisposable workerScope = ParallelContainerAuthenticator.UseWorkerCountForTests(workers);
                using IDisposable mutation = DerivedSecretHandoff.UseMutationForTests(probe.Visit);
                using var stream = new MemoryStream(data, writable: false);
                try
                {
                    var result = await ParallelContainerAuthenticator.ComputeAsync(stream, 0, ["public-MAC-prefix"u8.ToArray()], sha3, skein, CancellationToken.None).ConfigureAwait(false);
                    tags = (result.Sha3Tag, result.SkeinTag);
                    completed = true;
                }
                catch (Exception error) when (fault.HasValue) { RequireInjectedFailure(error, fault.Value); }
                Require(fault.HasValue ? !completed && probe.InjectionHits == 1 : completed && probe.InjectionHits == 0,
                    "The MAC fault did not reach exactly one targeted guard or returned tags.");
            }
            finally
            {
                Erase(sha3, skein, data);
            }
            Require(IsErased(sha3) && IsErased(skein), "A caller-owned MAC fixture survived cleanup.");
            Require(SecureMemory.LockedAllocationsForTests == baseline, "A MAC handoff fault leaked a sensitive lock.");
            if (target is not null) rows.Add(new(target, fault!.Value.ToString(), "MAC workers=" + workers, probe.InjectionHits, !completed, true, true,
                "Caller fixture erasure and lock accounting; private leaf/root spans are not retained"));
            resultTransferred = true;
            return (probe, tags, probe.PeakCpuPermits);
        }
        finally
        {
            if (!resultTransferred) Erase(tags.Sha3, tags.Skein);
        }
    }

    private static readonly string[] RecoveryBoundaries =
    [
        "recovery/parent/sha3-consumer", "recovery/parent/skein-consumer",
        "recovery/certification/sha3-output", "recovery/certification/skein-output",
        "recovery/certification/sha3-consumer", "recovery/certification/skein-consumer",
    ];

    private static RecoveryLocator PublicRecoveryLocator() => new(
        RecoveryProtectionMode.DualAuthenticatedEncrypted,
        MetadataOffset: 1024, MetadataEncodedLength: 4096, MetadataEnvelopeLength: 8192,
        MetadataStripeCount: 1, ArchiveLength: 256L << 20, EncryptionSuite: (int)EncryptionSuite.ParanoiaCascade,
        ArchiveId: Public(32, 31), SaltSha3Round1: Public(64, 37), SaltSkeinRound1: Public(64, 41),
        SaltSha3Round2: Public(64, 43), SaltSkeinRound2: Public(64, 47),
        EnvelopeSha3: Public(64, 53), EnvelopeSkein: Public(128, 59), FormatVersion: 4, ContainerVersion: 13);

    private static void ErasePublicLocator(RecoveryLocator locator) => Erase(locator.ArchiveId,
        locator.SaltSha3Round1 ?? [], locator.SaltSkeinRound1 ?? [],
        locator.SaltSha3Round2 ?? [], locator.SaltSkeinRound2 ?? [], locator.EnvelopeSha3, locator.EnvelopeSkein);

    private static Task RecoveryFaults()
    {
        var rows = new List<Receipt>();
        Probe normal = RunRecovery(null, null, rows);
        foreach (string boundary in RecoveryBoundaries) Require(normal.Observed.TryGetValue(boundary, out int count) && count == 1, "Missing/duplicated recovery boundary: " + boundary);
        Require(normal.Observed.Keys.Where(id => id.StartsWith("recovery/", StringComparison.Ordinal)).ToHashSet(StringComparer.Ordinal).SetEquals(RecoveryBoundaries),
            "The recovery handoff inventory changed without coverage.");
        foreach (string boundary in RecoveryBoundaries)
        foreach (Fault fault in Enum.GetValues<Fault>()) RunRecovery(boundary, fault, rows);
        Emit("security.downstream-recovery-handoff-faults", rows, new { Boundaries = RecoveryBoundaries });
        return Task.CompletedTask;
    }

    private static Probe RunRecovery(string? target, Fault? fault, List<Receipt> rows)
    {
        long baseline = SecureMemory.LockedAllocationsForTests;
        byte[] parentSha3 = Public(64, 13), parentSkein = Public(128, 19), sha3Message = Public(41, 23), skeinMessage = Public(43, 29);
        byte[] payload = Public(257, 61);
        RecoveryLocator locator = PublicRecoveryLocator();
        (byte[] Sha3, byte[] Skein) tags = ([], []);
        var children = new List<byte[]>();
        var probe = new Probe(target, fault);
        IDisposable? keys = null;
        bool completed = false;
        using IDisposable childObserver = RecoveryService.UseRecoveryKeyDerivationHookForTests((_, first, second) =>
        {
            if (!children.Contains(first)) children.Add(first);
            if (second is not null && !children.Contains(second)) children.Add(second);
        });
        try
        {
            using IDisposable mutation = DerivedSecretHandoff.UseMutationForTests(probe.Visit);
            try
            {
                keys = RecoveryService.DeriveRecoveryCertificationKeysForTests(parentSha3, parentSkein, sha3Message, skeinMessage);
                using var stream = new MemoryStream(payload, writable: false);
                tags = RecoveryService.ComputeMetadataCertificationForTests(locator, stream, keys);
                Require(tags.Sha3.Length == 64 && tags.Skein.Length == 128, "The actual recovery certification consumer returned invalid tags.");
                completed = true;
            }
            catch (Exception error) when (fault.HasValue) { RequireInjectedFailure(error, fault.Value); }
            Require(fault.HasValue ? !completed && probe.InjectionHits == 1 : completed && probe.InjectionHits == 0,
                "The recovery fault did not reach exactly one targeted guard or returned keys.");
        }
        finally
        {
            keys?.Dispose();
            Erase(parentSha3, parentSkein, sha3Message, skeinMessage, payload, tags.Sha3, tags.Skein);
            ErasePublicLocator(locator);
        }
        Require(children.All(IsErased), "A derived recovery key survived failure or successful owner disposal.");
        Require(SecureMemory.LockedAllocationsForTests == baseline, "A recovery handoff fault leaked a sensitive lock.");
        if (target is not null) rows.Add(new(target, fault!.Value.ToString(), "KPAR2 certification", probe.InjectionHits, !completed, true, true,
            "Actual AfterSha3/AfterSkein child array aliases plus caller parents"));
        return probe;
    }

    private static void MustBeDisposed(Action read)
    {
        try { read(); }
        catch (ObjectDisposedException) { return; }
        catch (TargetInvocationException error) when (error.InnerException is ObjectDisposedException) { return; }
        throw new InvalidOperationException("A cleared sensitive owner still allowed new access.");
    }
    private static byte[] RecoveryProperty(IDisposable owner, string name) =>
        (byte[])(owner.GetType().GetProperty(name, BindingFlags.Public | BindingFlags.Instance)?.GetValue(owner)
            ?? throw new InvalidOperationException("Recovery key property missing."));

    private static Task DisposedOwners()
    {
        Require(SecureMemory.SensitiveBufferBeforeUnlockForTests is null && SecureMemory.MacMemoryUnlockOverrideForTests is null,
            "Owner retry fixtures require exclusive ownership of cleanup hooks.");
        long baseline = SecureMemory.LockedAllocationsForTests;
        long retained = SecureMemory.RetainedFailedLockRollbacksForTests;
        foreach (bool failFirstUnlock in new[] { false, true })
        {
            LockedSensitiveBuffer owner = LockedSensitiveBuffer.Create(128);
            byte[] alias = owner.Bytes;
            byte[] initial = Public(128);
            try { initial.CopyTo(alias, 0); }
            finally { Erase(initial); }
            try
            {
                if (failFirstUnlock) SecureMemory.SensitiveBufferBeforeUnlockForTests = () => throw new IOException("Injected owner before-unlock failure.");
                bool failed = false;
                try { owner.Dispose(); } catch (IOException) { failed = true; }
                Require(failed == failFirstUnlock && IsErased(alias), "Locked owner did not erase before its unlock failure.");
                MustBeDisposed(() => _ = owner.Bytes);
                if (failFirstUnlock) Require(SecureMemory.LockedAllocationsForTests == baseline + 1, "A failed locked owner lost its retained pin.");
                SecureMemory.SensitiveBufferBeforeUnlockForTests = null;
                owner.Dispose();
                MustBeDisposed(() => _ = owner.Bytes);
            }
            finally { SecureMemory.SensitiveBufferBeforeUnlockForTests = null; owner.Dispose(); }
            Require(SecureMemory.LockedAllocationsForTests == baseline, "Locked owner retry leaked a lock.");
        }
        foreach (bool failFirstUnlock in new[] { false, true })
        {
            EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(EncryptionSuite.ParanoiaCascade);
            byte[] flat = Public(parameters.DerivedKeyBytes);
            KalynaContainerService.SuiteKeyMaterial suite = KalynaContainerService.SuiteKeyMaterial.Create(flat, parameters);
            byte[][] aliases = [suite.EncryptionKey, suite.Sha3MacKey, suite.SkeinMacKey];
            try { ExerciseUnlockRetry(suite, aliases, failFirstUnlock, () =>
                { MustBeDisposed(() => _ = suite.EncryptionKey); MustBeDisposed(() => _ = suite.Sha3MacKey); MustBeDisposed(() => _ = suite.SkeinMacKey); }); }
            finally { SecureMemory.MacMemoryUnlockOverrideForTests = null; suite.Dispose(); Erase(flat); }
            Require(SecureMemory.LockedAllocationsForTests == baseline, "Suite owner retry leaked a lock.");
        }
        foreach (bool failFirstUnlock in new[] { false, true })
        {
            byte[] first = Public(64, 13), second = Public(128, 19), firstMessage = Public(41), secondMessage = Public(43);
            IDisposable owner = RecoveryService.DeriveRecoveryCertificationKeysForTests(first, second, firstMessage, secondMessage);
            byte[][] aliases = [RecoveryProperty(owner, "Sha3Key"), RecoveryProperty(owner, "SkeinKey")];
            try { ExerciseUnlockRetry(owner, aliases, failFirstUnlock, () =>
                { MustBeDisposed(() => _ = RecoveryProperty(owner, "Sha3Key")); MustBeDisposed(() => _ = RecoveryProperty(owner, "SkeinKey")); }); }
            finally { SecureMemory.MacMemoryUnlockOverrideForTests = null; owner.Dispose(); Erase(first, second, firstMessage, secondMessage); }
            Require(SecureMemory.LockedAllocationsForTests == baseline, "Recovery owner retry leaked a lock.");
        }
        Require(SecureMemory.RetainedFailedLockRollbacksForTests == retained, "Owner retry retained a failed release after recovery.");
        Console.WriteLine("handoff_owner_lifecycle=" + JsonSerializer.Serialize(new { OwnerTypes = new[] { "LockedSensitiveBuffer", "SuiteKeyMaterial", "RecoveryKeys" },
            SuccessAndFailedUnlockCases = 6, GettersClosed = true, ActualAliasesErased = true, LockAllocationBaselineRestored = true }));
        return Task.CompletedTask;
    }

    private static void ExerciseUnlockRetry(IDisposable owner, byte[][] aliases, bool failFirstUnlock, Action assertClosed)
    {
        int hits = 0;
        if (failFirstUnlock) SecureMemory.MacMemoryUnlockOverrideForTests = (_, _) =>
        { Interlocked.Increment(ref hits); Marshal.SetLastPInvokeError(5); return -1; };
        bool failed = false;
        try { owner.Dispose(); } catch (Exception error) when (HasFailure<CryptographicException>(error)) { failed = true; }
        Require(failed == failFirstUnlock && (!failFirstUnlock || hits > 0), "The physical page-unlock fault was not observed.");
        Require(aliases.All(IsErased), "A cleared owner retained nonzero bytes after unlock failure.");
        assertClosed();
        SecureMemory.MacMemoryUnlockOverrideForTests = null;
        owner.Dispose();
        assertClosed();
        Require(aliases.All(IsErased), "Retry resurrected secret material.");
    }

    private static async Task MustRejectAsync<T>(Func<Task> action) where T : Exception
    {
        try { await action().ConfigureAwait(false); }
        catch (Exception error) when (HasFailure<T>(error)) { return; }
        throw new InvalidOperationException("Required NULL/default/width validation was missing.");
    }
    private static void MustReject<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (Exception error) when (HasFailure<T>(error)) { return; }
        throw new InvalidOperationException("Required NULL/default/width validation was missing.");
    }

    private static async Task NullWidthContracts()
    {
        long baseline = SecureMemory.LockedAllocationsForTests;
        EncryptionSuiteParameters parameters = EncryptionSuiteCatalog.Get(EncryptionSuite.Aes256);
        MustReject<ArgumentNullException>(() => new LockedSensitiveBuffer(null!, null!));
        MustReject<ArgumentNullException>(() => new LockedSensitiveBuffer(Public(128), null!));
        using (RoleKeyMaterial roles = FixtureRoles(parameters, out _))
        {
            MustReject<ArgumentNullException>(() => new RoleKeyMaterial(null!, roles.Sha3MacKey, roles.SkeinMacKey));
            MustReject<ArgumentNullException>(() => new RoleKeyMaterial(roles.EncryptionKey, null!, roles.SkeinMacKey));
            MustReject<ArgumentNullException>(() => new RoleKeyMaterial(roles.EncryptionKey, roles.Sha3MacKey, null!));
            MustReject<ArgumentNullException>(() => KalynaContainerService.SuiteKeyMaterial.FromRoleKeys(null!, parameters));
            MustReject<ArgumentNullException>(() => KalynaContainerService.SuiteKeyMaterial.FromRoleKeys(roles, null!));
            MustReject<ArgumentNullException>(() => KalynaContainerService.SuiteKeyMaterial.Create(Public(parameters.DerivedKeyBytes), null!));
            MustReject<CryptographicException>(() => KalynaContainerService.SuiteKeyMaterial.Create(default, parameters));
            MustReject<CryptographicException>(() => KalynaContainerService.SuiteKeyMaterial.Create(Public(parameters.DerivedKeyBytes - 1), parameters));
            using LockedSensitiveBuffer tooShort = LockedSensitiveBuffer.Create(parameters.EncryptionKeyBytes - 1);
            byte[] initial = Public(tooShort.Bytes.Length);
            try { initial.CopyTo(tooShort.Bytes, 0); }
            finally { Erase(initial); }
            var malformed = new RoleKeyMaterial(tooShort, roles.Sha3MacKey, roles.SkeinMacKey);
            MustReject<CryptographicException>(() => KalynaContainerService.SuiteKeyMaterial.FromRoleKeys(malformed, parameters));
            roles.Dispose();
            MustReject<ObjectDisposedException>(() => KalynaContainerService.SuiteKeyMaterial.FromRoleKeys(roles, parameters));
        }
        byte[] first = Public(64, 13), second = Public(128, 19), data = Public(17), output = Public(17), tag = Public(16), key = Public(32), nonce = Public(16);
        RecoveryLocator locator = PublicRecoveryLocator();
        try
        {
            MustReject<ArgumentNullException>(() => RecoveryService.DeriveRecoveryCertificationKeysForTests(null!, second, data, data));
            MustReject<ArgumentNullException>(() => RecoveryService.DeriveRecoveryCertificationKeysForTests(first, null!, data, data));
            MustReject<ArgumentNullException>(() => RecoveryService.DeriveRecoveryCertificationKeysForTests(first, second, null!, data));
            MustReject<ArgumentNullException>(() => RecoveryService.DeriveRecoveryCertificationKeysForTests(first, second, data, null!));
            MustReject<ArgumentException>(() => RecoveryService.DeriveRecoveryCertificationKeysForTests([], second, data, data));
            MustReject<ArgumentException>(() => RecoveryService.DeriveRecoveryCertificationKeysForTests(first, [], data, data));
            MustReject<ArgumentException>(() => RecoveryService.DeriveRecoveryCertificationKeysForTests(first[..^1], second, data, data));
            MustReject<ArgumentException>(() => RecoveryService.DeriveRecoveryCertificationKeysForTests(first, second[..^1], data, data));
            using var stream = new MemoryStream(data, writable: false);
            using IDisposable recoveryKeys = RecoveryService.DeriveRecoveryCertificationKeysForTests(first, second, data, data);
            MustReject<ArgumentNullException>(() => RecoveryService.ComputeMetadataCertificationForTests(null!, stream, recoveryKeys));
            MustReject<ArgumentNullException>(() => RecoveryService.ComputeMetadataCertificationForTests(locator, null!, recoveryKeys));
            MustReject<ArgumentNullException>(() => RecoveryService.ComputeMetadataCertificationForTests(locator, stream, null!));
            using LockedSensitiveBuffer wrongOwner = LockedSensitiveBuffer.Create(128);
            MustReject<ArgumentException>(() => RecoveryService.ComputeMetadataCertificationForTests(locator, stream, wrongOwner));
            recoveryKeys.Dispose();
            MustReject<ObjectDisposedException>(() => RecoveryService.ComputeMetadataCertificationForTests(locator, stream, recoveryKeys));
            await MustRejectAsync<ArgumentNullException>(() => ParallelContainerAuthenticator.ComputeAsync(stream, 0, [data], null!, second, default)).ConfigureAwait(false);
            await MustRejectAsync<ArgumentNullException>(() => ParallelContainerAuthenticator.ComputeAsync(stream, 0, [data], first, null!, default)).ConfigureAwait(false);
            await MustRejectAsync<ArgumentException>(() => ParallelContainerAuthenticator.ComputeAsync(stream, 0, [data], [], second, default)).ConfigureAwait(false);
            await MustRejectAsync<ArgumentException>(() => ParallelContainerAuthenticator.ComputeAsync(stream, 0, [data], first, [], default)).ConfigureAwait(false);
            MustReject<ArgumentNullException>(() => KalynaContainerService.EncryptSuiteChunkForTests(null!, key, [], nonce, data, output, data.Length, [], tag));
            MustReject<ArgumentNullException>(() => KalynaContainerService.EncryptSuiteChunkForTests(parameters, null!, [], nonce, data, output, data.Length, [], tag));
            MustReject<ArgumentNullException>(() => KalynaContainerService.EncryptSuiteChunkForTests(parameters, key, [], null!, data, output, data.Length, [], tag));
            MustReject<ArgumentNullException>(() => KalynaContainerService.EncryptSuiteChunkForTests(parameters, key, [], nonce, null!, output, data.Length, [], tag));
            MustReject<ArgumentNullException>(() => KalynaContainerService.EncryptSuiteChunkForTests(parameters, key, [], nonce, data, null!, data.Length, [], tag));
            MustReject<ArgumentNullException>(() => KalynaContainerService.EncryptSuiteChunkForTests(parameters, key, [], nonce, data, output, data.Length, [], null!));
            MustReject<CryptographicException>(() => KalynaContainerService.EncryptSuiteChunkForTests(parameters, [], [], nonce, data, output, data.Length, [], tag));
        }
        finally { Erase(first, second, data, output, tag, key, nonce); ErasePublicLocator(locator); }
        Require(SecureMemory.LockedAllocationsForTests == baseline, "NULL/default/width owner cases leaked locks.");
    }
}
