using System.Text.Json;
using KalynaArchiver.Services;

internal static class OperationPhaseProfileTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("diagnostics.rev12-phase-bounds", "bounded, inert-by-default timing profile with nested async ownership and no secret-bearing schema", BoundsAsync, TestResource.Light, "Diagnostics"),
        new("diagnostics.rev12-phase-equivalence", "opt-in and failed observations preserve actual synthetic v13 output, repair and cleanup", EquivalenceAsync, TestResource.ProcessGlobal, "Diagnostics"),
    ];

    private static async Task BoundsAsync()
    {
        Require(!OperationPhaseProfile.IsEnabledForTests, "A diagnostic observer is active by default.");
        using (OperationPhaseProfile.Measure(OperationPhaseProfile.Phase.CipherAes, 31)) { }
        var measurements = new OperationPhaseProfile.Measurements(timelineCapacity: 3);
        using (OperationPhaseProfile.ObserveForTests(measurements))
        {
            using var outer = OperationPhaseProfile.Measure(OperationPhaseProfile.Phase.ArchiveEncryption);
            await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() =>
            {
                using var timer = OperationPhaseProfile.Measure(OperationPhaseProfile.Phase.CipherAes, 31);
                timer.Complete(47); // Actual public read count replaces the request; Dispose is idempotent.
                timer.Dispose();
            })));
            var child = new OperationPhaseProfile.Measurements(timelineCapacity: 0);
            using (OperationPhaseProfile.ObserveForTests(child))
            using (OperationPhaseProfile.Measure(OperationPhaseProfile.Phase.PayloadRead, 7)) { }
            Require(child.Snapshot().Aggregates.Single(x => x.Phase == "PayloadRead").Calls == 1, "Nested diagnostic ownership failed.");
            using (OperationPhaseProfile.Measure(OperationPhaseProfile.Phase.PayloadWrite, 11)) { }
        }
        Require(!OperationPhaseProfile.IsEnabledForTests, "A disposed diagnostic scope remained active.");
        var idempotent = new OperationPhaseProfile.Measurements(0);
        IDisposable idempotentScope = OperationPhaseProfile.ObserveForTests(idempotent);
        idempotentScope.Dispose();
        idempotentScope.Dispose();
        Require(!OperationPhaseProfile.IsEnabledForTests, "Double disposal restored the wrong diagnostic owner.");
        OperationPhaseProfile.ProfileSnapshot snapshot = measurements.Snapshot();
        OperationPhaseProfile.PhaseAggregate aes = snapshot.Aggregates.Single(x => x.Phase == "CipherAes");
        Require(snapshot.ObservationAvailable && snapshot.Timeline.Length == 3 && snapshot.OmittedTimelineEntries == 15,
            "Timeline capacity or aggregate retention is incorrect.");
        Require(aes.Calls == 16 && aes.PublicBytesSum == 16 * 47 && aes.WallSecondsSum >= 0,
            "Concurrent/idempotent timers changed counts or the actual byte basis.");
        Require(snapshot.Aggregates.Single(x => x.Phase == "PayloadRead").Calls == 0,
            "A child observation leaked into its parent's aggregates.");
        Require(snapshot.Interpretation.Contains("overlap", StringComparison.Ordinal), "Profile sums do not declare interval overlap.");
        string json = JsonSerializer.Serialize(snapshot);
        foreach (string forbidden in new[] { "credentialHash", "memoryKiB", "PMI16", "nonceBytes", "tagBytes", "filePath", "password", "pinValue" })
            Require(!json.Contains(forbidden, StringComparison.OrdinalIgnoreCase), "The profile schema exposes secret-bearing data.");
        bool rejected = false;
        try { _ = new OperationPhaseProfile.Measurements(OperationPhaseProfile.Measurements.MaximumTimelineEntries + 1); }
        catch (ArgumentOutOfRangeException) { rejected = true; }
        Require(rejected, "An unbounded diagnostic timeline was allowed.");
    }

    private static async Task EquivalenceAsync()
    {
        IReadOnlyDictionary<string, string> reference = await FactorInputRev12Tests.AllPathsAsync();
        var measurements = new OperationPhaseProfile.Measurements(128);
        var mac = new ParallelContainerAuthenticator.PhaseMeasurementsForTests();
        IReadOnlyDictionary<string, string> observed;
        using (OperationPhaseProfile.ObserveForTests(measurements))
        using (ParallelContainerAuthenticator.ObservePhasesForTests(mac))
            observed = await FactorInputRev12Tests.AllPathsAsync();
        Require(reference.Count == observed.Count && reference.All(pair => observed.TryGetValue(pair.Key, out string? digest) && digest == pair.Value),
            "Diagnostic observation changed deterministic container/cipher/tag output.");
        OperationPhaseProfile.ProfileSnapshot snapshot = measurements.Snapshot();
        string[] required = ["KdfRound1", "KdfRound2", "Argon2Sha3Round1", "Argon2SkeinRound1", "Argon2Sha3Round2", "Argon2SkeinRound2",
            "KeySchedule", "ChunkNonce", "CipherAes", "CipherMars", "CipherCamellia", "CipherSerpent", "CipherShacal2", "CipherKalyna", "CipherThreefish",
            "AeadEncryptAndTag", "AeadVerifyAndDecrypt", "GlobalAuthentication", "VerifiedGlobalBinding", "LocalRangeTags", "LocalRangeVerification",
            "PayloadRead", "PayloadWrite", "RecoveryCreate", "RecoveryVerifyRepair"];
        foreach (string phase in required)
            Require(snapshot.Aggregates.Single(x => x.Phase == phase).Calls > 0, "A required real synthetic-fixture phase is absent: " + phase);
        Require(mac.Seconds().Values.Any(seconds => seconds > 0), "The reused global MAC phase observer did not measure actual authentication.");
        var failed = new OperationPhaseProfile.Measurements(1);
        failed.Record((OperationPhaseProfile.Phase)(-1), 0, 1, 0); // Fail the observer only, never the archive operation.
        using (OperationPhaseProfile.ObserveForTests(failed))
        {
            IReadOnlyDictionary<string, string> unaffected = await FactorInputRev12Tests.AllPathsAsync();
            Require(reference.All(pair => unaffected[pair.Key] == pair.Value), "An unavailable observation changed product output.");
        }
        Require(!failed.Snapshot().ObservationAvailable && !OperationPhaseProfile.IsEnabledForTests,
            "Observer failure or ownership cleanup did not stay isolated.");
        Console.WriteLine("    REV12_SYNTHETIC_PHASE_PROFILE_JSON=" + JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            testMode = "Synthetic 4 KiB fixtures, scoped test Argon2 memory only; not production-KDF performance evidence",
            diagnosticOutputEquivalent = true,
            phaseProfile = snapshot,
            globalMacPhasesWallSecondsSum = mac.Seconds(),
        }));
    }

    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
}
