using KalynaArchiver.Services;

internal static class KdfAdmissionRev12Tests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("resources.rev12-kdf-minimum-admission", "REV12 public KDF lower-bound admission is read-only, typed and KAT-aware", RunAsync, TestResource.ProcessGlobal, "Resources"),
    ];

    private static async Task RunAsync()
    {
        string root = Directory.CreateTempSubdirectory("kv-rev12-kdf-admission-").FullName;
        Func<ResourceObservation>? previousObserver = PlatformResourceObserver.ObservationForTests;
        var normal = new ResourceObservation(16, 16L << 30, 16L << 30, 64L << 20, 12L << 30, MemoryPressure.Normal, true);
        long workingBefore = OperationMemoryBudget.WorkingReservedBytesForTests;
        long entropyBefore = OperationMemoryBudget.EntropyReservedBytes;
        try
        {
            PlatformResourceObserver.ObservationForTests = () => normal;
            long matrix = checked((long)V13MasterKdf.MemoryMinKiB * 1024);
            Require(V13MasterKdf.AdmissionMinimumMemoryKiB == V13MasterKdf.MemoryMinKiB,
                "The public production minimum was replaced by a test profile outside its scope.");
            ArchiveOperationPolicy Policy(long bytes) => new(string.Empty, root,
                preferences: new ResourcePreferences { MemoryMode = ResourceMode.Manual, ManualMemoryLimitBytes = bytes });
            var small = Policy(64L << 20);
            var exact = Policy(checked(matrix + ResourcePlanner.OperationBaseBytes + entropyBefore));
            ExpectKnown(() => OperationMemoryBudget.RequireKnownMinimumKdfAdmission(small));
            OperationMemoryBudget.RequireKnownMinimumKdfAdmission(exact);
            Require(OperationMemoryBudget.WorkingReservedBytesForTests == workingBefore
                && OperationMemoryBudget.EntropyReservedBytes == entropyBefore,
                "The read-only minimum check reserved or removed memory.");

            // Charge the existing public ledger seam without allocating a matrix.
            using (OperationMemoryBudget.ReserveEntropy(4096, exact.EntropyCaptureBudgetBytes))
            {
                ExpectKnown(() => OperationMemoryBudget.RequireKnownMinimumKdfAdmission(exact));
                OperationMemoryBudget.RequireKnownMinimumKdfAdmission(Policy(checked(exact.MemoryBudgetBytes + 4096)));
            }

            // A reliable observation proving insufficient capacity is expected;
            // missing/failed observation is not reclassified as known capacity.
            PlatformResourceObserver.ObservationForTests = () => normal with
            { ReclaimableMemoryBytes = (normal.PhysicalMemoryBytes / 32) + matrix + ResourcePlanner.OperationBaseBytes - 1 };
            ExpectKnown(() => OperationMemoryBudget.RequireKnownMinimumKdfAdmission(exact));
            PlatformResourceObserver.ObservationForTests = () => normal with { Reliable = false };
            ExpectUnknownIo(() => OperationMemoryBudget.RequireKnownMinimumKdfAdmission(exact));
            PlatformResourceObserver.ObservationForTests = () => throw new IOException("public injected OS observation failure");
            ExpectUnknownIo(() => OperationMemoryBudget.RequireKnownMinimumKdfAdmission(exact));
            PlatformResourceObserver.ObservationForTests = () => normal;

            using (V13MasterKdf.UseMemoryCostForTests(8192))
            {
                Require(V13MasterKdf.AdmissionMinimumMemoryKiB == 8192, "The scoped KAT minimum did not match its actual matrix.");
                OperationMemoryBudget.RequireKnownMinimumKdfAdmission(small);
                using OperationMemoryBudget.Lease owner = await OperationMemoryBudget.AcquireAsync(small, CancellationToken.None);
                using IDisposable ownerScope = owner.EnterScope();
                using IDisposable policyScope = small.EnterScope();
                using OperationMemoryBudget.HeavyLease held = await OperationMemoryBudget.AcquireWorkingAsync(56L << 20, CancellationToken.None);
                ExpectKnown(() => OperationMemoryBudget.RequireKnownMinimumKdfAdmission(small));
            }
            Require(V13MasterKdf.AdmissionMinimumMemoryKiB == V13MasterKdf.MemoryMinKiB,
                "The KAT lower bound escaped its scope.");
            Require(OperationMemoryBudget.WorkingReservedBytesForTests == workingBefore
                && OperationMemoryBudget.EntropyReservedBytes == entropyBefore,
                "The admission regression retained an operation or record reservation.");
        }
        finally
        {
            PlatformResourceObserver.ObservationForTests = previousObserver;
            Directory.Delete(root, recursive: true);
        }
    }

    private static void ExpectKnown(Action check)
    { try { check(); } catch (KdfMinimumAdmissionRefusalException) { return; } throw new InvalidOperationException("A confirmed minimum-capacity refusal was not reported with its dedicated type."); }
    private static void ExpectUnknownIo(Action check)
    {
        try { check(); }
        catch (KdfMinimumAdmissionRefusalException) { throw new InvalidOperationException("An observation failure was incorrectly classified as known insufficient capacity."); }
        catch (IOException) { return; }
        throw new InvalidOperationException("An OS observation failure did not remain an ordinary I/O failure.");
    }
    private static void Require(bool value, string error) => MacComprehensiveTests.Require(value, error);
}
