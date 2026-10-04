using System.Text.Json;
using KalynaArchiver.Services;

internal static class AdaptiveWindowRev12Tests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("resources.rev12-adaptive-window", "REV12 accepted-window probes, loss rollback, no retry loop and fresh resource authority", RunAsync, TestResource.Light, "Resources"),
    ];

    private static Task RunAsync()
    {
        VerifyMeasuredFeedback();
        var auto = new ResourcePreferences();
        var normal = new ResourceObservation(16, 16L << 30, 16L << 30, 64L << 20, 12L << 30, MemoryPressure.Normal, true);
        var ready = new PhaseResourceDemand(64L << 10, 512L << 20, ReadyWorkers: 16);
        ResolvedOperationPlan Plan(PhaseResourceDemand work, ResourcePreferences? preferences = null, ResourceObservation? observation = null) =>
            ResourcePlanner.Resolve(preferences ?? auto, observation ?? normal, work);
        Require(Plan(ready).ActiveSlots == 2, "Ready work did not start at the minimum second-slot window.");
        foreach (int healthy in new[] { 0, 1, 2, 3, 16 })
        {
            Require(Plan(ready with { PreviousSlots = 4, HealthySamples = healthy }).ActiveSlots == 4,
                "An existing healthy window collapsed without a regression or resource limit.");
        }
        Require(Plan(ready with { PreviousSlots = 4, HealthySamples = 2, ThroughputImproved = true }).ActiveSlots == 4,
            "Growth bypassed its three healthy-sample boundary.");
        Require(Plan(ready with { PreviousSlots = 4, HealthySamples = 3, ThroughputImproved = true }).ActiveSlots == 5,
            "Beneficial joined-boundary growth did not admit exactly one new slot.");
        Require(Plan(ready with { PreviousSlots = 5, HealthySamples = 0 }).ActiveSlots == 5,
            "A newly grown window required perpetual rate increases to remain available.");
        Require(Plan(ready with { PreviousSlots = 5, ThroughputRegressed = true, ThroughputImproved = true, HealthySamples = 3 }).ActiveSlots == 4,
            "Explicit regression failed to shrink or was overridden by an improvement flag.");
        foreach (MemoryPressure pressure in new[] { MemoryPressure.Elevated, MemoryPressure.Critical })
            Require(Plan(ready with { PreviousSlots = 16, HealthySamples = 3, ThroughputImproved = true }, observation: normal with { Pressure = pressure }).ActiveSlots == 1,
                "Pressure retained optional slot allocations.");
        foreach ((long bytes, int expected) in new[] { (1024L, 1), (16L << 20, 1), ((16L << 20) + 1, 2), (32L << 20, 2), ((32L << 20) + 1, 3) })
            Require(Plan(ready with { ReadyBytes = bytes, PreviousSlots = 16 }).ActiveSlots == expected,
                "The concrete remaining work did not bound the window.");
        foreach (int cpu in new[] { 1, 2, 3, 16, 32 })
        {
            var manual = auto with { CpuMode = ResourceMode.Manual, ManualCpuLimit = cpu };
            Require(Plan(ready with { PreviousSlots = 16, HealthySamples = 3, ThroughputImproved = true }, manual).ActiveSlots == Math.Min(cpu, 16),
                "The active window exceeded the manual or observed CPU ceiling.");
        }
        Require(Plan(ready with { PreviousSlots = 16, HealthySamples = 3, ThroughputImproved = true },
            auto with { QueueMode = ResourceMode.Manual, ManualQueueLimit = 3 }).ActiveSlots == 3,
            "A growing window exceeded the manual queue ceiling.");
        Require(Plan(ready with { PreviousSlots = 8 }, auto with { MemoryMode = ResourceMode.Manual, ManualMemoryLimitBytes = 64L << 20 }).ActiveSlots == 1,
            "Mandatory bytes were ignored when admitting optional slots below a manual memory ceiling.");
        var exactlyTwo = normal with
        {
            PhysicalMemoryBytes = 1L << 30, ProcessLimitBytes = 1L << 30,
            ProcessResidentBytes = 64L << 20,
            ReclaimableMemoryBytes = (128L << 20) + (64L << 20) + (64L << 10),
        };
        Require(Plan(ready with { PreviousSlots = 8 }, observation: exactlyTwo).ActiveSlots == 2,
            "Optional slots exceeded freshly observed RAM after the OS reserve and mandatory costs.");
        Require(Plan(ready with { MandatoryBytes = (64L << 10) + 1, PreviousSlots = 8 }, observation: exactlyTwo).ActiveSlots == 1,
            "Higher mandatory costs failed to reduce admission monotonically.");
        Require(Plan(ready with { ReadyBytes = long.MaxValue, PreviousSlots = int.MaxValue,
            HealthySamples = int.MaxValue, ThroughputImproved = true }).ActiveSlots == 16,
            "Large public counts overflowed or bypassed admission bounds.");
        Expect<ArgumentOutOfRangeException>(() => Plan(ready with { PreviousSlots = 0 }));
        Expect<ArgumentOutOfRangeException>(() => Plan(ready with { HealthySamples = -1 }));
        Expect<ArgumentOutOfRangeException>(() => Plan(ready with { RequestedSlots = 0 }));
        Expect<IOException>(() => Plan(ready, observation: normal with { Reliable = false }));
        return Task.CompletedTask;
    }
    private static void VerifyMeasuredFeedback()
    {
        var trace = new List<object>();
        var normal = new ResourceObservation(16, 16L << 30, 16L << 30, 64L << 20, 12L << 30, MemoryPressure.Normal, true);
        var ready = new PhaseResourceDemand(64L << 10, 512L << 20, ReadyWorkers: 16);
        var auto = new ResourcePreferences();
        AdaptiveChunkWindow state = default;
        int current = 2;
        void Reset(int slots = 2) { state = default; current = slots; state.ApplyResolvedWindow(slots); }
        AdaptiveWindowDecision Step(string scenario, double rate, bool complete = true, bool allowProbe = true,
            ResourceObservation? observation = null, ResourcePreferences? preferences = null, long? readyBytes = null)
        {
            int previous = current;
            AdaptiveWindowDecision decision = state.Observe(current, rate, complete, allowProbe);
            ResolvedOperationPlan plan = ResourcePlanner.Resolve(preferences ?? auto, observation ?? normal,
                ready with { PreviousSlots = current, RequestedSlots = decision.RequestedSlots, ReadyBytes = readyBytes ?? ready.ReadyBytes });
            current = plan.ActiveSlots;
            state.ApplyResolvedWindow(current);
            trace.Add(new { scenario, previous, requested = decision.RequestedSlots, resolved = current,
                rate = double.IsFinite(rate) ? rate : 0, rateValid = double.IsFinite(rate) && rate > 0,
                complete, decision = decision.Reason.ToString(), state.AcceptedSlots, state.ProbeSlots,
                state.RejectedSlots, state.AcceptedRate, plan.MaximumAdmittedSlots });
            Require(current <= plan.MaximumAdmittedSlots, "Feedback exceeded fresh admission authority.");
            return decision;
        }
        void StartProbe(string scenario)
        {
            Require(Step(scenario, 400).RequestedSlots == 2 && Step(scenario, 402).RequestedSlots == 2,
                "Growth used fewer than three complete healthy batches.");
            Require(Step(scenario, 400).Reason == AdaptiveWindowReason.ProbeStarted && current == 3
                && state.AcceptedSlots == 2 && state.AcceptedRate == 400, "A probe lost its accepted-window comparison rate.");
        }

        Reset(); StartProbe("poor-three");
        Require(Step("poor-three", 344).Reason == AdaptiveWindowReason.ProbeRejectedLoss
            && current == 2 && state.RejectedSlots == 3 && state.AcceptedRate == 400,
            "A complete 14% loss at three slots did not immediately roll back against the retained two-slot baseline.");
        for (int index = 0; index < 40; index++)
        {
            Step("no-noise-retry", index % 3 == 0 ? 409 : 400);
            Require(current == 2 && state.ProbeSlots == 0, "A rejected adjacent window was probed repeatedly from warm-up noise.");
        }
        Step("rejected-pressure-change", 400, observation: normal with { Pressure = MemoryPressure.Critical });
        Require(current == 1 && state.RejectedSlots == 0,
            "A real pressure admission change permanently retained an old rejected-window conclusion.");
        Step("rejected-pressure-restored", 200); Step("rejected-pressure-restored", 200); Step("rejected-pressure-restored", 200);
        Step("rejected-pressure-restored-two", 400); Step("rejected-pressure-restored-two", 400);
        Require(Step("rejected-pressure-restored-two", 400).Reason == AdaptiveWindowReason.ProbeAccepted && current == 2,
            "Restored resources could not reaccept profitable two-slot work.");
        Step("rejected-pressure-restored-three", 400); Step("rejected-pressure-restored-three", 400);
        Require(Step("rejected-pressure-restored-three", 400).Reason == AdaptiveWindowReason.ProbeStarted && current == 3,
            "A previously rejected three-slot window stayed globally forbidden after a genuine resource regime change.");
        Step("rejected-pressure-restored-three", 430); Step("rejected-pressure-restored-three", 430);
        Require(Step("rejected-pressure-restored-three", 430).Reason == AdaptiveWindowReason.ProbeAccepted && current == 3,
            "A larger window could not show genuine benefit after changed resource authority.");
        Reset(); StartProbe("exact-loss-boundary");
        Require(Step("exact-loss-boundary", 360).Reason == AdaptiveWindowReason.ProbeRejectedLoss && current == 2,
            "Exactly ten percent probe loss bypassed the rollback boundary.");
        Reset(); StartProbe("no-benefit");
        Require(Step("no-benefit", 410).Reason == AdaptiveWindowReason.ProbePending
            && Step("no-benefit", 412).Reason == AdaptiveWindowReason.ProbePending && current == 3,
            "A bounded probe ended before its three full samples without a loss.");
        Require(Step("no-benefit", 408).Reason == AdaptiveWindowReason.ProbeRejectedNoBenefit && current == 2,
            "An unprofitable probe remained accepted after three complete samples.");
        Reset(); StartProbe("exact-benefit-boundary");
        Step("exact-benefit-boundary", 420); Step("exact-benefit-boundary", 420);
        Require(Step("exact-benefit-boundary", 420).Reason == AdaptiveWindowReason.ProbeAccepted && current == 3,
            "Exactly five percent median benefit failed its acceptance boundary.");
        Reset(); StartProbe("profitable-three");
        Step("profitable-three", 425); Step("profitable-three", 430);
        Require(Step("profitable-three", 427).Reason == AdaptiveWindowReason.ProbeAccepted
            && current == 3 && state.AcceptedSlots == 3 && state.AcceptedRate == 427,
            "A genuinely profitable three-slot window was not accepted.");
        Step("profitable-four", 426); Step("profitable-four", 428);
        Require(Step("profitable-four", 427).Reason == AdaptiveWindowReason.ProbeStarted && current == 4,
            "Accepted growth was artificially capped at two or three slots.");
        Step("profitable-four", 475); Step("profitable-four", 480);
        Require(Step("profitable-four", 479).Reason == AdaptiveWindowReason.ProbeAccepted && current == 4,
            "The four-slot probe did not use the retained accepted three-slot rate.");
        Step("profitable-five", 478); Step("profitable-five", 480); Step("profitable-five", 479);
        Step("profitable-five", 530); Step("profitable-five", 532);
        Require(Step("profitable-five", 531).Reason == AdaptiveWindowReason.ProbeAccepted && current == 5,
            "Further profitable independent work was stopped by a fixed product slot limit.");

        foreach (double invalid in new[] { 0, -1, double.NaN, double.PositiveInfinity, double.NegativeInfinity })
        {
            Reset(); StartProbe("invalid-probe");
            Require(Step("invalid-probe", invalid).Reason == AdaptiveWindowReason.InvalidRate && current == 2,
                "Invalid throughput admitted or retained a probe.");
            Reset(1);
            Require(Step("invalid-minimum", invalid).Reason == AdaptiveWindowReason.InvalidRate && current == 1,
                "Invalid throughput overflowed or dropped the minimum safe window.");
        }
        Reset(); Step("tail", 400); Step("tail", 402);
        for (int index = 0; index < 10; index++)
            Require(Step("tail", 10_000, complete: false).Reason == AdaptiveWindowReason.IncompleteBatch && current == 2,
                "Partial tail work was treated as throughput evidence for growth.");
        Require(Step("tail", 400).Reason == AdaptiveWindowReason.ProbeStarted, "Partial batches destroyed the complete-batch hysteresis.");
        Require(Step("tail-probe", double.NaN, complete: false).Reason == AdaptiveWindowReason.IncompleteBatch && current == 3,
            "A partial probe batch was used to accept or reject a scaling claim.");
        Require(Step("tail-probe", 344).Reason == AdaptiveWindowReason.ProbeRejectedLoss && current == 2,
            "A tail batch reset the retained comparison rate.");
        Reset(1);
        for (int index = 0; index < 16; index++)
        {
            Step("unknown-ready-work", 400, allowProbe: false, readyBytes: 0);
            Require(current == 1 && state.IsCold && state.AcceptedRate == 0,
                "Unproven future non-seekable work or a cold first batch created an optional larger window.");
        }
        Reset(1);
        Step("cold-start", 100, allowProbe: false);
        Require(current == 1 && state.AcceptedRate == 0 && state.IsCold,
            "The cold initial batch was assigned a mature accepted-window rate.");
        AdaptiveWindowDecision startup = state.RequestProvenLongStreamStart();
        ResolvedOperationPlan startPlan = ResourcePlanner.Resolve(auto, normal,
            ready with { RequestedSlots = startup.RequestedSlots, PreviousSlots = 1 });
        current = startPlan.ActiveSlots; state.ApplyResolvedWindow(current);
        Require(startup.Reason == AdaptiveWindowReason.ProvenLongStreamStart && current == 2
            && !state.IsCold && state.AcceptedRate == 0,
            "The first proven longer-stream policy window reused the cold one-slot rate or skipped admission.");
        Step("cold-start-two", 400); Step("cold-start-two", 402);
        Require(Step("cold-start-two", 400).Reason == AdaptiveWindowReason.ProbeStarted && state.AcceptedRate == 400,
            "Two slots did not establish their own complete-batch rate before a larger probe.");

        foreach (string authority in new[] { "cpu", "queue", "pressure", "ram", "remaining-work" })
        {
            Reset(); StartProbe(authority);
            ResourcePreferences preferences = authority switch
            {
                "cpu" => auto with { CpuMode = ResourceMode.Manual, ManualCpuLimit = 1 },
                "queue" => auto with { QueueMode = ResourceMode.Manual, ManualQueueLimit = 1 },
                "ram" => auto with { MemoryMode = ResourceMode.Manual, ManualMemoryLimitBytes = 64L << 20 },
                _ => auto,
            };
            ResourceObservation observation = authority == "pressure" ? normal with { Pressure = MemoryPressure.Critical } : normal;
            Step(authority, 430, observation: observation, preferences: preferences,
                readyBytes: authority == "remaining-work" ? 1024 : null);
            Require(current == 1 && state.ProbeSlots == 0 && state.AcceptedSlots == 1,
                "A pending probe overrode changed " + authority + " authority.");
            Step(authority + "-restored", 200); Step(authority + "-restored", 200);
            Require(Step(authority + "-restored", 200).Reason == AdaptiveWindowReason.ProbeStarted && current == 2,
                "Restored resource capacity was persisted as a false manual slot preference.");
        }
        // A fixed diagnostic request is only a desired value. It uses the same
        // pure capacity calculation and cannot bypass any of the public caps.
        foreach (int fixedSlots in new[] { 1, 2, 3, 4, 10, int.MaxValue })
        foreach (int cap in new[] { 1, 2, 3 })
        {
            ResolvedOperationPlan plan = ResourcePlanner.Resolve(auto with { CpuMode = ResourceMode.Manual, ManualCpuLimit = cap }, normal,
                ready with { RequestedSlots = fixedSlots, PreviousSlots = fixedSlots });
            Require(plan.ActiveSlots == Math.Min(fixedSlots, cap), "A fixed request skipped the manual/fresh CPU authority.");
            Require(ResourcePlanner.Resolve(auto, normal with { Pressure = MemoryPressure.Critical },
                ready with { RequestedSlots = fixedSlots }).ActiveSlots == 1, "A fixed request skipped fresh memory pressure.");
            Require(ResourcePlanner.Resolve(auto, normal, ready with { ReadyBytes = 1024, RequestedSlots = fixedSlots }).ActiveSlots == 1,
                "A fixed request allocated windows for absent remaining work.");
        }
        VerifyBoundedDiagnosticWindows(state);
        Console.WriteLine("    REV12_ADAPTIVE_WINDOW_TRACE_JSON=" + JsonSerializer.Serialize(new
        { schemaVersion = 1, scope = "Deterministic public throughput/control regression fixtures, no product performance claim", trace }));
    }

    private static void VerifyBoundedDiagnosticWindows(AdaptiveChunkWindow state)
    {
        Require(!OperationPhaseProfile.IsEnabledForTests, "A pipeline observer is enabled by default.");
        OperationPhaseProfile.RecordWindowDecision(2, 3, 3, 16, 2, true, 32L << 20, 400,
            AdaptiveWindowReason.ProbeStarted, state);
        var profile = new OperationPhaseProfile.Measurements(2, pipelineOnly: true);
        using (OperationPhaseProfile.ObserveForTests(profile))
        {
            using (OperationPhaseProfile.Measure(OperationPhaseProfile.Phase.CipherAes)) { }
            for (int index = 0; index < 4; index++)
            {
                using (OperationPhaseProfile.Measure(OperationPhaseProfile.Phase.ResourceObservation)) { }
                using (OperationPhaseProfile.Measure(OperationPhaseProfile.Phase.ResourcePlanning)) { }
                using (OperationPhaseProfile.Measure(OperationPhaseProfile.Phase.WindowDecision)) { }
                OperationPhaseProfile.RecordWindowDecision(2, 3, 3, 16, 2, true, 32L << 20, 400,
                    AdaptiveWindowReason.ProbeStarted, state);
            }
        }
        OperationPhaseProfile.ProfileSnapshot snapshot = profile.Snapshot();
        Require(snapshot.ObservationAvailable && snapshot.WindowDecisions.Length == 2 && snapshot.OmittedWindowDecisions == 2,
            "An opt-in public window trace is unbounded or loses its truncation count.");
        Require(snapshot.Aggregates.Single(x => x.Phase == "CipherAes").Calls == 0
            && snapshot.Aggregates.Single(x => x.Phase == "ResourceObservation").Calls == 4
            && snapshot.Aggregates.Single(x => x.Phase == "ResourcePlanning").Calls == 4
            && snapshot.Aggregates.Single(x => x.Phase == "WindowDecision").Calls == 4,
            "Pipeline-only observation added cipher timers or lost closed resource boundaries.");
        Require(!OperationPhaseProfile.IsEnabledForTests, "A disposed window trace remained active.");
    }
    private static void Require(bool value, string message) => MacComprehensiveTests.Require(value, message);
    private static void Expect<T>(Action action) where T : Exception
    { try { action(); } catch (T) { return; } throw new InvalidOperationException("Expected adaptive planner refusal was not raised."); }
}
