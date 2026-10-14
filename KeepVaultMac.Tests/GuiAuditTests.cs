using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using Avalonia.Threading;
using KalynaArchiver;
using KalynaArchiver.Gui;
using KalynaArchiver.Services;
using Microsoft.Win32.SafeHandles;

internal static class GuiAuditTests
{
    internal static IReadOnlyList<TestCase> All =>
    [
        new("audit.fixed-cli-isolation", "release audit accepts only fixed case selectors without activating hooks", ParseIsolationAsync,
            TestResource.ProcessGlobal, "Security"),
        new("audit.passive-cpu-observer", "passive CPU grant observations preserve queueing/cancellation/ownership", CpuObservationAsync,
            TestResource.ProcessGlobal, "Security"),
        new("audit.metadata-allowlist", "audit receipt has a bounded metadata-only schema and no release-verdict authority", MetadataSchemaAsync,
            TestResource.Light, "Security"),
        new("audit.initialization-close-join", "actual window disposal joins slow public initialization before entropy reset and suppresses closed-window dialogs",
            () => MacGuiTests.RunOnUiThread(InitializationCloseJoin), TestResource.Gui, "GUI"),
    ];

    private static Task ParseIsolationAsync()
    {
        ReleaseAuditSession? current = ReleaseAuditSession.Current;
        var random = EntropyMixer.RandomFillForTests;
        var memory = SecureMemory.MacMemoryLockOverrideForTests;
        var cleanup = SecureMemory.SensitiveBufferBeforeUnlockForTests;
        var replay = ConsumedEntropySnapshot.AfterReplayRecordForReleaseAudit;
        long samples = EntropyMixer.SampleCount;
        string[] valid = ["profile", "rng-routing", "rng-shuffle1", "rng-shuffle2", "rng-xor", "mlock-first",
            "cleanup-before-unlock", "cancel-shuffle1", "cancel-shuffle2", "cancel-replay-sha3", "cancel-replay-sha512"];
        foreach (string value in valid)
            Require(ReleaseAuditSession.TryParseArguments(["--release-audit", value], out string? parsed) && parsed == value,
                "A fixed audit selector was rejected.");
        foreach (string[] arguments in new string[][]
        {
            ["--release-audit"], ["--release-audit", "unknown"], ["--release-audit", "Profile"],
            ["--release-audit", "profile", "/tmp/foreign-output"], ["--release-audit=profile"],
            ["--release-audit", "rng-shuffle1", "--provider", "foreign.dll"],
            ["--other", "--release-audit", "profile"], ["--release-audit", "../profile"],
        })
        {
            try { ReleaseAuditSession.TryParseArguments(arguments, out _); throw new InvalidOperationException("Unsafe audit arguments were accepted."); }
            catch (ArgumentException) { }
        }
        Require(!ReleaseAuditSession.TryParseArguments([], out _) && !ReleaseAuditSession.TryParseArguments(["normal-file-activation"], out _),
            "Normal startup arguments activated an audit.");
        Require(ReferenceEquals(current, ReleaseAuditSession.Current) && ReferenceEquals(random, EntropyMixer.RandomFillForTests)
            && ReferenceEquals(memory, SecureMemory.MacMemoryLockOverrideForTests)
            && ReferenceEquals(cleanup, SecureMemory.SensitiveBufferBeforeUnlockForTests)
            && ReferenceEquals(replay, ConsumedEntropySnapshot.AfterReplayRecordForReleaseAudit)
            && EntropyMixer.SampleCount == samples,
            "Pure audit parsing changed runtime hooks, records or the selected session.");
        return Task.CompletedTask;
    }

    private static async Task CpuObservationAsync()
    {
        Require(CpuWorkBudget.ActiveWorkersForTests == 0, "CPU test requires an isolated allocator.");
        var outer = new CpuWorkBudget.Measurements();
        var inner = new CpuWorkBudget.Measurements();
        using (CpuWorkBudget.ObserveForTests(outer))
        {
            using CpuWorkBudget.Lease first = await CpuWorkBudget.AcquireAsync(1, 1, default);
            Require(first.Workers == 1 && !CpuWorkBudget.IsOwnedByCurrentContext, "Observation changed the normal grant or ambient ownership.");
            using (CpuWorkBudget.ObserveForTests(inner))
            using (var cancelled = new CancellationTokenSource())
            {
                Task<CpuWorkBudget.Lease> waiter = CpuWorkBudget.AcquireAsync(1, 1, cancelled.Token).AsTask();
                Require(!waiter.IsCompleted, "Observation let a second team escape its normal ceiling.");
                cancelled.Cancel();
                try { using CpuWorkBudget.Lease unexpected = await waiter; throw new InvalidOperationException("Cancelled waiter obtained a grant."); }
                catch (OperationCanceledException) { }
            }
            first.Dispose();
            using CpuWorkBudget.Lease second = await CpuWorkBudget.AcquireAsync(1, 1, default);
            using (second.EnterScope())
                Require(CpuWorkBudget.IsOwnedByCurrentContext, "Normal explicit lease ownership was lost.");
        }
        CpuWorkBudget.BudgetSnapshot observed = outer.Snapshot();
        Require(observed.ObservationAvailable && observed.Admissions == 2 && observed.Releases == 2
            && observed.MinimumGrant == 1 && observed.MaximumGrant == 1 && observed.PeakReservedWorkers == 1
            && observed.AcquisitionWallSecondsSum >= 0 && inner.Snapshot().Admissions == 0
            && CpuWorkBudget.ActiveWorkersForTests == 0 && !CpuWorkBudget.IsOwnedByCurrentContext,
            "Passive measurements lost real grants, attributed a cancelled grant, or leaked permit/context ownership.");
        using (CpuWorkBudget.Lease unobserved = await CpuWorkBudget.AcquireAsync(1, 1, default)) { }
        Require(outer.Snapshot().Admissions == 2, "The disposed measurement scope remained active.");
    }

    private static Task MetadataSchemaAsync()
    {
        // Construct with deliberately known metadata. No runtime fault hook or
        // real archive is used by this serializer/privacy regression.
        var phases = new OperationPhaseProfile.Measurements(timelineCapacity: 4);
        var native = new NativeCipherExecutor.Measurements();
        var cpu = new CpuWorkBudget.Measurements();
        var receipt = new AuditReceipt(1, "profile", 1, "create", DateTime.UnixEpoch, DateTime.UnixEpoch,
            new("5.0.3", 21, 123, "Arm64", new string('A', 64), new string('B', 64)),
            new("public-fixture", 256L << 20, 3, 5, new string('C', 64)),
            "not-completed", true, 1, 0, 1, 0.5, 0, 2, 0, 0, 0, 0, 0,
            phases.Snapshot(), native.Snapshot(), cpu.Snapshot(), [], [], 0, 0, false, false, false, 0, null, null,
            "No overall release verdict.");
        byte[] encoded = JsonSerializer.SerializeToUtf8Bytes(receipt, AuditJsonContext.Default.AuditReceipt);
        Require(encoded.Length < 64_000, "Empty audit metadata is unexpectedly large.");
        using JsonDocument document = JsonDocument.Parse(encoded);
        Require(document.RootElement.GetProperty("outcome").GetString() == "not-completed"
            && !document.RootElement.TryGetProperty("pass", out _)
            && !document.RootElement.TryGetProperty("releaseApproved", out _),
            "Audit schema invents release approval authority.");
        foreach (string forbidden in new[] { "password", "pin", "factorA", "factorB", "salt", "pmi", "nonce", "rawRecords", "randomBytes", "pointer", "exception", "credential", "sourcePath", "outputPath" })
            Require(!ContainsProperty(document.RootElement, forbidden), "A forbidden secret/path/log property reached the audit schema.");
        return Task.CompletedTask;
    }

    private static void InitializationCloseJoin(MainWindow window)
    {
        // This exercises the real lifetime owner and Window.Dispose with a
        // slow public worker. It never selects an audit, sets trusted flags,
        // skips hardening, or claims installed/startup-integrity evidence.
        Require(ReleaseAuditSession.Current is null, "The lifecycle regression requires an ordinary isolated test window.");
        const BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;
        FieldInfo Field(string name) => typeof(MainWindow).GetField(name, flags)!;
        var clock = Stopwatch.StartNew();
        while ((string?)Field("_integrityStatusKey").GetValue(window) == "integrityChecking")
        {
            Require(clock.Elapsed < TimeSpan.FromSeconds(15), "The ordinary window's integrity check did not finish.");
            Dispatcher.UIThread.RunJobs(); Thread.Sleep(1);
        }
        var owner = (ReleaseAuditInitialization)Field("_releaseAuditInitialization").GetValue(window)!;
        var lifetime = (CancellationTokenSource)Field("_lifetime").GetValue(window)!;
        CancellationToken token = lifetime.Token;
        EntropyMixer.Reset();
        long lockedBefore = SecureMemory.LockedBytesForTests;
        long allocationsBefore = SecureMemory.LockedAllocationsForTests;
        long reservedBefore = SecureMemory.ReservedWorkingSetBytesForTests;
        ulong ResetVersion() => (ulong)typeof(EntropyMixer).GetField("_resetVersion", BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;
        ulong resetBefore = ResetVersion();
        string directory = MacSafeFileSystem.ResolveExistingRealPath(Directory.CreateTempSubdirectory("kv-audit-init-lifetime-").FullName);
        using var started = new ManualResetEventSlim();
        using var cancelled = new ManualResetEventSlim();
        using var finish = new ManualResetEventSlim();
        SafeFileHandle? publicHandle = null;
        int exited = 0;
        Task worker = owner.Start(cancellation =>
        {
            try
            {
                using SafeFileHandle root = MacSafeFileSystem.OpenDirectoryHandle(directory);
                publicHandle = MacSafeFileSystem.CreateFileAtExclusive(root, "public-initialization.txt", 0x0180);
                using (publicHandle)
                using (var stream = new FileStream(publicHandle, FileAccess.Write))
                {
                    stream.Write("public audit lifetime fixture"u8); stream.Flush(flushToDisk: true);
                    byte[] publicRecord = new byte[SensitiveMouseRecordStore.RecordBytes];
                    publicRecord.AsSpan().Fill(0x3C);
                    EntropyMixer.AddCanonicalRecord(publicRecord);
                    started.Set();
                    Require(cancellation.WaitHandle.WaitOne(TimeSpan.FromSeconds(10)), "Window disposal did not cancel the registered worker.");
                    cancelled.Set();
                    Require(finish.Wait(TimeSpan.FromSeconds(10)), "The controlled slow initializer was not released.");
                    cancellation.ThrowIfCancellationRequested();
                }
            }
            finally { Volatile.Write(ref exited, 1); }
        }, token);
        Task? controller = null;
        try
        {
            Require(started.Wait(TimeSpan.FromSeconds(10)), "The public initialization worker did not acquire its real resources.");
            controller = Task.Run(() =>
            {
                try
                {
                    Require(cancelled.Wait(TimeSpan.FromSeconds(10)), "The close path did not reach its real initialization cancellation.");
                    Require(!worker.IsCompleted && Volatile.Read(ref exited) == 0 && publicHandle is { IsClosed: false },
                        "The slow-worker fixture did not retain its resource until join.");
                    Require(ResetVersion() == resetBefore && EntropyMixer.SampleCount > 0,
                        "Window disposal reset shared entropy before its initializer had exited.");
                }
                finally { finish.Set(); }
            });
            window.Dispose();
            controller.GetAwaiter().GetResult();
            Require(worker.IsCanceled && Volatile.Read(ref exited) == 1 && publicHandle is { IsClosed: true },
                "Window disposal returned before the cancelled worker released its actual file handle.");
            Require(ResetVersion() == resetBefore + 1 && EntropyMixer.SampleCount == 0
                && SecureMemory.LockedBytesForTests == lockedBefore && SecureMemory.LockedAllocationsForTests == allocationsBefore
                && SecureMemory.ReservedWorkingSetBytesForTests == reservedBefore,
                "Joined initialization left a late pool publication or a real locked/reserved owner behind.");
            bool restarted = false;
            try { owner.Start(_ => restarted = true, CancellationToken.None); throw new InvalidOperationException("Closed initialization owner accepted a late start."); }
            catch (ObjectDisposedException) { }
            Require(!restarted, "A worker started after the closed owner's refusal.");
            Task suppressed = (Task)typeof(MainWindow).GetMethod("ReportReleaseAuditInitializationFailureAsync", flags)!.Invoke(window, null)!;
            Require(suppressed.IsCompletedSuccessfully, "A disposed window attempted an initialization error dialog.");
            suppressed.GetAwaiter().GetResult();
        }
        finally
        {
            finish.Set();
            try { lifetime.Cancel(); } catch (ObjectDisposedException) { }
            owner.CloseAndJoin();
            if (controller is not null) controller.GetAwaiter().GetResult();
            EntropyMixer.Reset();
            File.Delete(Path.Combine(directory, "public-initialization.txt"));
            Directory.Delete(directory);
        }
    }

    private static bool ContainsProperty(JsonElement element, string name)
    {
        if (element.ValueKind == JsonValueKind.Object)
            foreach (JsonProperty property in element.EnumerateObject())
                if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase) || ContainsProperty(property.Value, name)) return true;
        if (element.ValueKind == JsonValueKind.Array)
            foreach (JsonElement item in element.EnumerateArray()) if (ContainsProperty(item, name)) return true;
        return false;
    }

    private static void Require(bool condition, string message)
    { if (!condition) throw new InvalidOperationException(message); }
}
