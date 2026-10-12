using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml;
using System.Xml.Linq;
using KalynaArchiver.Services;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Gui;

/// <summary>
/// A process-local, fixed public-fixture diagnostic session. This is not an
/// archive API or a configurable fault injector. Selection precedes Avalonia;
/// initialization and hook installation require normal startup integrity.
/// Every fault process is single-use and cannot publish a prepared result.
/// </summary>
internal sealed class ReleaseAuditSession : IDisposable
{
    internal const string PublicPassword = "N!r7$Vq2#Lm8%Tx3&Jd9*Wp4+Kg5=Zu6?Ce";
    internal const string PublicPin = "428317";
    internal const long FixtureBytes = 256L << 20;
    private const int MaximumOperations = 64;
    private const int MaximumExportBytes = 1 << 20;
    private const string FixtureName = "public-fixture";
    private readonly string _caseId;
    private readonly AuditSettingsStore _settings = new();
    private SafeFileHandle? _root;
    private MacFileIdentity _rootIdentity;
    private MacOriginalDeletionService.CreationSnapshot? _sourceSnapshot;
    private AuditProcessIdentity? _identity;
    private AuditFixture? _fixture;
    private AuditOperation? _operation;
    private int _sequence;
    private int _faultTriggered;
    private bool _faultConsumed;
    private bool _unexpectedFaultSuccess;
    private bool _disposed;
    private bool _initialized;
    private bool _hooksOwned;
    private CancellationTokenSource? _faultCancellation;
    private bool? _originalComparison;
    private long _baselineLockedBytes;
    private long _baselineLockedAllocations;
    private long _baselineReservedBytes;

    private ReleaseAuditSession(string caseId) => _caseId = caseId;
    internal static ReleaseAuditSession? Current { get; private set; }
    internal IAppSettingsStore Settings => _settings;
    internal string CaseId => _caseId;
    internal bool IsFault => _caseId != "profile";
    internal bool IsInitialized => _initialized && !_disposed;
    internal bool FaultConsumed => _faultConsumed;
    internal string WorkRoot { get; private set; } = string.Empty;
    internal string SourceRoot => Path.Combine(WorkRoot, FixtureName);
    internal string ArchivePath => Path.Combine(WorkRoot, "public-fixture.kzpaq");
    internal string ExtractionPath => Path.Combine(WorkRoot, "extracted-public-fixture");

    internal static bool IsKnownCase(string value) => value is
        "profile" or "rng-routing" or "rng-shuffle1" or "rng-shuffle2" or "rng-xor"
        or "mlock-first" or "cleanup-before-unlock"
        or "cancel-shuffle1" or "cancel-shuffle2" or "cancel-replay-sha3" or "cancel-replay-sha512";

    // Pure parser: no filesystem, hooks, RNG, settings, or process changes.
    internal static bool TryParseArguments(string[] arguments, out string? caseId)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        caseId = null;
        if (!arguments.Any(argument => argument.StartsWith("--release-audit", StringComparison.Ordinal)))
            return false;
        if (arguments.Length != 2 || arguments[0] != "--release-audit" || !IsKnownCase(arguments[1]))
            throw new ArgumentException("The release audit accepts exactly one fixed case identifier and no additional arguments.");
        caseId = arguments[1];
        return true;
    }

    internal static void SelectForThisProcess(string[] arguments)
    {
        if (Current is not null) throw new InvalidOperationException("An audit process cannot change its selected case.");
        if (TryParseArguments(arguments, out string? selected)) Current = new ReleaseAuditSession(selected!);
    }

    internal void InitializeAfterTrustedStartup(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_initialized) throw new InvalidOperationException("The release audit is initialized only once.");
        RequireNoFaultHooks();
        _identity = ReadActualProcessIdentity();
        cancellationToken.ThrowIfCancellationRequested();
        string parentPath = MacSafeFileSystem.ResolveExistingRealPath(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        using SafeFileHandle parent = MacSafeFileSystem.OpenDirectoryHandle(parentPath);
        string name = "Keep Vault Release Audit-" + Guid.NewGuid().ToString("N");
        MacSafeFileSystem.MkdirAt(parent, name, 0x01C0);
        _root = MacSafeFileSystem.OpenDirectoryHandleAt(parent, name);
        _rootIdentity = MacSafeFileSystem.GetIdentity(_root);
        MacSafeFileSystem.SetUnixFileMode(_root, 0x01C0);
        WorkRoot = Path.Combine(parentPath, name);
        RequireRoot();
        _baselineLockedBytes = SecureMemory.LockedBytesForTests;
        _baselineLockedAllocations = SecureMemory.LockedAllocationsForTests;
        _baselineReservedBytes = SecureMemory.ReservedWorkingSetBytesForTests;
        using IDisposable policy = new ArchiveOperationPolicy(WorkRoot, WorkRoot).EnterScope();
        if (IsFault)
        {
            // This explicit diagnostic fixture is not a claim of human entropy
            // capture. Routing and all locks still use the reviewed OS paths.
            EntropyMixer.Reset();
            AddPublicRecordsUntilReady(cancellationToken);
            _fixture = new("public-canonical-records-fault-fixture", 0, 0, 0, null);
        }
        else
        {
            AuditFixture expected = CreatePublicFixture(cancellationToken);
            _sourceSnapshot = MacOriginalDeletionService.CaptureCreationSnapshot([SourceRoot], cancellationToken);
            _fixture = ReadPublicManifest(cancellationToken);
            RequireDeclaredTopology();
            if (_fixture != expected) throw new InvalidDataException("The generated public fixture differs from its declared bytes.");
        }
        cancellationToken.ThrowIfCancellationRequested();
        _initialized = true;
    }

    internal bool Allows(string operation) => IsInitialized && (!IsFault
        ? operation is "generate" or "create" or "extract" or "list" or "recovery" or "key-sheet"
        : operation == "generate" && !_faultConsumed);

    internal void RequirePublicCredentials(string? password, string? pin)
    {
        if (password != PublicPassword || pin != PublicPin)
            throw new InvalidOperationException("Release audit operations accept only the declared public test password and PIN.");
    }

    internal void RequirePublicCreation(string[] inputs, string archive, bool encrypted, bool deleteOriginals, int compression)
    {
        RequireRoot();
        if (IsFault || inputs.Length != 1 || !SamePath(inputs[0], SourceRoot)
            || !SamePath(archive, ArchivePath) || !encrypted || deleteOriginals || compression != 3)
            throw new InvalidOperationException("The release audit accepts only its unchanged public source, fixed encrypted destination, level 3, and retained originals.");
        _sourceSnapshot!.RequireUnchanged([SourceRoot], CancellationToken.None);
        RequireDeclaredTopology();
        AuditFixture actual = ReadPublicManifest();
        if (actual != _fixture) throw new InvalidDataException("The declared public source fixture changed.");
    }

    internal void RequirePublicArchive(string archive, string? output = null)
    {
        RequireRoot();
        if (IsFault || !SamePath(archive, ArchivePath) || output is not null && !SamePath(output, ExtractionPath))
            throw new InvalidOperationException("The release audit accepts only its own fixed archive and extraction destination.");
        using FileStream file = MacSafeFileSystem.OpenReadNoSymlinks(ArchivePath, requireSingleLink: true);
    }

    internal void RequireOwnedOutput(string path)
    {
        RequireRoot();
        if (IsFault || !SamePath(Path.GetDirectoryName(Path.GetFullPath(path))!, WorkRoot))
            throw new InvalidOperationException("Audit test PDFs must remain in the private audit working directory.");
    }

    internal AuditOperation BeginOperation(string operation, ArchiveOperationPolicy policy, CancellationTokenSource cancellation)
    {
        RequireRoot();
        if (!Allows(operation) || _operation is not null || _sequence >= MaximumOperations)
            throw new InvalidOperationException("This audit operation is unavailable or already active.");
        if (!SamePath(policy.WorkingDirectory, WorkRoot))
            throw new InvalidOperationException("Audit working files must remain in the owned private working directory.");
        RequireNoFaultHooks();
        var observation = new AuditOperation(operation, ++_sequence, policy);
        _operation = observation;
        _originalComparison = null;
        EntropyMixer.PreparationPhaseForTests = observation.ObserveEntropyPhase;
        _hooksOwned = true;
        if (IsFault)
        {
            _faultConsumed = true;
            _faultCancellation = cancellation;
            InstallFixedFault();
        }
        return observation;
    }

    internal void BeforeGenerate()
    {
        if (_caseId == "rng-routing")
        {
            // Exercise the real capture API with a fixed public record, inside
            // this isolated GUI negative case, before generation can publish.
            Span<byte> record = stackalloc byte[80];
            record.Fill(0x53);
            try { EntropyMixer.AddCanonicalRecord(record); }
            finally { CryptographicOperations.ZeroMemory(record); }
        }
    }

    internal void RejectFaultPublication()
    {
        if (!IsFault) return;
        _unexpectedFaultSuccess = true;
        throw new InvalidOperationException("A controlled release-audit fault unexpectedly returned a result. Publication is blocked.");
    }

    internal async Task VerifyPublicExtractionAsync(string output, CancellationToken token)
    {
        if (IsFault) throw new InvalidOperationException("Fault cases cannot extract archives.");
        RequirePublicArchive(ArchivePath, output);
        using (OperationPhaseProfile.Measure(OperationPhaseProfile.Phase.OriginalTreeComparison, FixtureBytes))
        {
            MacOriginalDeletionService.VerificationResult result = await MacOriginalDeletionService.VerifyExtractionAsync(
                [SourceRoot], output, null, token, _sourceSnapshot).ConfigureAwait(false);
            _originalComparison = result.Verified && result.BytesCompared == FixtureBytes;
            if (_originalComparison != true) throw new InvalidDataException("The actual product original comparison failed for the public fixture.");
        }
    }

    internal IDisposable? ObserveDialogWait() => _operation?.ObserveDialogWait();
    internal void MarkWorkStart() => _operation?.MarkWorkStart();

    internal string? CompleteOperation(bool success, bool failure, bool cancelled, bool factorPublished)
    {
        AuditOperation? operation = _operation;
        _operation = null;
        if (operation is null) return null;
        operation.Dispose(); // restore all passive scopes after actual callers joined
        ClearOwnedHooks();
        int pendingBeforeRetry = EntropyMixer.PendingCleanupCountForTests;
        bool? retrySucceeded = null;
        if (IsFault)
        {
            try
            {
                EntropyMixer.Reset();
                SecureMemory.RetryRetainedFailedLockRollbacksForTests();
                retrySucceeded = EntropyMixer.PendingCleanupCountForTests == 0
                    && SecureMemory.LockedBytesForTests == _baselineLockedBytes
                    && SecureMemory.LockedAllocationsForTests == _baselineLockedAllocations
                    && SecureMemory.ReservedWorkingSetBytesForTests == _baselineReservedBytes;
            }
            catch { retrySucceeded = false; }
        }
        AuditReceipt receipt = operation.CreateReceipt(_caseId, _identity!, _fixture!, success, failure, cancelled,
            _faultTriggered, _unexpectedFaultSuccess, factorPublished, pendingBeforeRetry,
            retrySucceeded, _originalComparison);
        return Export(receipt, $"operation-{operation.Sequence:000}-{operation.Name}.json");
    }

    private void InstallFixedFault()
    {
        if (_caseId == "mlock-first")
        {
            SecureMemory.MacMemoryLockOverrideForTests = (_, _) =>
            {
                Interlocked.Increment(ref _faultTriggered);
                Marshal.SetLastPInvokeError(12); // ENOMEM; never pretend an OS lock succeeded
                return -1;
            };
        }
        else if (_caseId == "cleanup-before-unlock")
        {
            SecureMemory.SensitiveBufferBeforeUnlockForTests = () =>
            {
                if (Interlocked.CompareExchange(ref _faultTriggered, 1, 0) == 0)
                    throw new IOException("Controlled public-fixture cleanup failure after zeroing and before real unlock.");
            };
        }
        else if (_caseId is "cancel-replay-sha3" or "cancel-replay-sha512")
        {
            bool second = _caseId == "cancel-replay-sha512";
            ConsumedEntropySnapshot.AfterReplayRecordForReleaseAudit = (sha512, processed) =>
            {
                if (sha512 == second && processed >= 1 && Interlocked.CompareExchange(ref _faultTriggered, 1, 0) == 0)
                    _faultCancellation!.Cancel();
            };
        }
        else
        {
            EntropyRandomRole role = _caseId switch
            {
                "rng-routing" => EntropyRandomRole.PoolRouting,
                "rng-shuffle1" or "cancel-shuffle1" => EntropyRandomRole.PoolShuffleRound1,
                "rng-shuffle2" or "cancel-shuffle2" => EntropyRandomRole.PoolShuffleRound2,
                "rng-xor" => EntropyRandomRole.OutputXor,
                _ => throw new InvalidOperationException("Unknown fixed fault case."),
            };
            bool cancel = _caseId.StartsWith("cancel-", StringComparison.Ordinal);
            EntropyMixer.RandomFillForTests = (buffer, actualRole) =>
            {
                if (!cancel && actualRole == role)
                {
                    Interlocked.Increment(ref _faultTriggered);
                    throw new CryptographicException("Controlled public-fixture OS-random adapter failure.");
                }
                EntropyMixer.FillSystemRandomCore(buffer);
                if (cancel && actualRole == role && Interlocked.CompareExchange(ref _faultTriggered, 1, 0) == 0)
                    _faultCancellation!.Cancel();
            };
        }
    }

    private static void RequireNoFaultHooks()
    {
        if (EntropyMixer.RandomFillForTests is not null || EntropyMixer.PreparationPhaseForTests is not null
            || ConsumedEntropySnapshot.AfterReplayRecordForReleaseAudit is not null
            || SecureMemory.MacMemoryLockOverrideForTests is not null
            || SecureMemory.MacMemoryUnlockOverrideForTests is not null
            || SecureMemory.SensitiveBufferBeforeUnlockForTests is not null
            || CpuTopology.AvailabilityForTests is not null)
            throw new InvalidOperationException("An audit session cannot run with other active diagnostic overrides.");
    }

    private void ClearOwnedHooks()
    {
        if (!_hooksOwned) return;
        _hooksOwned = false;
        EntropyMixer.PreparationPhaseForTests = null;
        if (!IsFault) return;
        EntropyMixer.RandomFillForTests = null;
        SecureMemory.MacMemoryLockOverrideForTests = null;
        SecureMemory.SensitiveBufferBeforeUnlockForTests = null;
        ConsumedEntropySnapshot.AfterReplayRecordForReleaseAudit = null;
        _faultCancellation = null;
    }

    private static void AddPublicRecordsUntilReady(CancellationToken cancellationToken)
    {
        Span<byte> record = stackalloc byte[80];
        try
        {
            // A finite synthetic-fixture bound is not a production timeout or
            // capture bypass. Actual record admission/routing remains required.
            for (int index = 0; !EntropyMixer.GetPoolStatus().IsReady; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (index >= 262_144) throw new InvalidOperationException("The bounded public record fixture could not become ready.");
                for (int at = 0; at < record.Length; at++) record[at] = unchecked((byte)(index * 17 + at * 29));
                EntropyMixer.AddCanonicalRecord(record);
            }
        }
        finally { CryptographicOperations.ZeroMemory(record); }
    }

    private AuditFixture CreatePublicFixture(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using SafeFileHandle source = NewDirectory(_root!, FixtureName);
        using SafeFileHandle empty = NewDirectory(source, "empty");
        using SafeFileHandle nested = NewDirectory(empty, "nested");
        using SafeFileHandle stillEmpty = NewDirectory(nested, "still empty");
        using SafeFileHandle hidden = NewDirectory(source, ".hidden");
        using SafeFileHandle unicode = NewDirectory(hidden, "Unicode_Grüße_日本_🙂");
        byte[] small = Encoding.UTF8.GetBytes("Öffentliche synthetische Keep Vault REV12 Daten.\n");
        WritePublicFile(unicode, "small.txt", small);
        WritePublicFile(source, "empty-file.bin", []);
        using SafeFileHandle payload = MacSafeFileSystem.CreateFileAtExclusive(source, "payload.bin", 0x0180);
        using var stream = new FileStream(payload, FileAccess.Write, 1 << 20, isAsync: false);
        using var payloadHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[1 << 20];
        ulong state = 0x4B56313352455612UL;
        long written = 0;
        while (written < FixtureBytes - small.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int length = (int)Math.Min(buffer.Length, FixtureBytes - small.Length - written);
            if ((written / (16L << 20)) % 4 == 2)
            {
                for (int at = 0; at < length; at += 8)
                {
                    state = unchecked(state + 0x9E3779B97F4A7C15UL);
                    ulong value = state;
                    value = unchecked((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9UL);
                    value = unchecked((value ^ (value >> 27)) * 0x94D049BB133111EBUL); value ^= value >> 31;
                    for (int i = 0; i < Math.Min(8, length - at); i++) buffer[at + i] = (byte)(value >> (8 * i));
                }
            }
            else for (int at = 0; at < length; at++) buffer[at] = (byte)((written + at) & 255);
            payloadHash.AppendData(buffer.AsSpan(0, length));
            stream.Write(buffer, 0, length); written += length;
        }
        stream.Flush(flushToDisk: true);
        return ManifestFromDeclaredFiles([
            (".hidden/Unicode_Grüße_日本_🙂/small.txt", (long)small.Length, Convert.ToHexString(SHA256.HashData(small))),
            ("empty-file.bin", 0L, Convert.ToHexString(SHA256.HashData(Array.Empty<byte>()))),
            ("payload.bin", written, Convert.ToHexString(payloadHash.GetHashAndReset())),
        ]);
    }

    private static SafeFileHandle NewDirectory(SafeFileHandle parent, string name)
    {
        MacSafeFileSystem.MkdirAt(parent, name, 0x01C0);
        return MacSafeFileSystem.OpenDirectoryHandleAt(parent, name);
    }

    private static void WritePublicFile(SafeFileHandle directory, string name, byte[] bytes)
    {
        using SafeFileHandle handle = MacSafeFileSystem.CreateFileAtExclusive(directory, name, 0x0180);
        using var stream = new FileStream(handle, FileAccess.Write, 4096, isAsync: false);
        stream.Write(bytes); stream.Flush(flushToDisk: true);
    }

    private AuditFixture ReadPublicManifest(CancellationToken cancellationToken = default)
    {
        RequireRoot();
        string[] directories = [".hidden", ".hidden/Unicode_Grüße_日本_🙂", "empty", "empty/nested", "empty/nested/still empty"];
        string[] files = [".hidden/Unicode_Grüße_日本_🙂/small.txt", "empty-file.bin", "payload.bin"];
        foreach (string name in directories)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using SafeFileHandle directory = MacSafeFileSystem.OpenDirectoryHandle(Path.Combine(SourceRoot, name));
        }
        var declared = new List<(string Name, long Bytes, string Sha256)>();
        foreach (string name in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using FileStream stream = MacSafeFileSystem.OpenReadNoSymlinks(Path.Combine(SourceRoot, name), requireSingleLink: true);
            long length = stream.Length;
            string hash = Convert.ToHexString(SHA256.HashData(stream));
            cancellationToken.ThrowIfCancellationRequested();
            declared.Add((name, length, hash));
        }
        return ManifestFromDeclaredFiles(declared);
    }

    private void RequireDeclaredTopology()
    {
        string[] expectedFiles = [".hidden/Unicode_Grüße_日本_🙂/small.txt", "empty-file.bin", "payload.bin"];
        string[] expectedDirectories = [".", ".hidden", ".hidden/Unicode_Grüße_日本_🙂", "empty", "empty/nested", "empty/nested/still empty"];
        string[] actualFiles = _sourceSnapshot!.Files.Keys.Select(path => Path.GetRelativePath(SourceRoot, path)).Order(StringComparer.Ordinal).ToArray();
        string[] actualDirectories = _sourceSnapshot.Directories.Where(entry => entry.Value.Strict)
            .Select(entry => Path.GetRelativePath(SourceRoot, entry.Key)).Order(StringComparer.Ordinal).ToArray();
        if (!actualFiles.SequenceEqual(expectedFiles.Order(StringComparer.Ordinal), StringComparer.Ordinal)
            || !actualDirectories.SequenceEqual(expectedDirectories.Order(StringComparer.Ordinal), StringComparer.Ordinal))
            throw new InvalidDataException("The public fixture contains an undeclared entry.");
    }

    private static AuditFixture ManifestFromDeclaredFiles(IEnumerable<(string Name, long Bytes, string Sha256)> files)
    {
        string[] directories = [".hidden", ".hidden/Unicode_Grüße_日本_🙂", "empty", "empty/nested", "empty/nested/still empty"];
        using var manifest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (string name in directories) manifest.AppendData(Encoding.UTF8.GetBytes("D:" + name + "\n"));
        long bytes = 0; int fileCount = 0;
        foreach (var file in files.OrderBy(entry => entry.Name, StringComparer.Ordinal))
        {
            manifest.AppendData(Encoding.UTF8.GetBytes($"F:{file.Name}:{file.Bytes.ToString(CultureInfo.InvariantCulture)}:{file.Sha256}\n"));
            bytes = checked(bytes + file.Bytes); fileCount++;
        }
        return new("REV12-public-mixed-256MiB-v1", bytes, fileCount, directories.Length,
            Convert.ToHexString(manifest.GetHashAndReset()));
    }

    private static AuditProcessIdentity ReadActualProcessIdentity()
    {
        string executable = Environment.ProcessPath ?? throw new InvalidOperationException("Actual executable identity unavailable.");
        if (!IntegrityService.TryGetSealedBundleLayout(executable, out string contents, out _))
            throw new InvalidOperationException("Release audit requires the normally verified installed application bundle.");
        using FileStream binary = MacSafeFileSystem.OpenReadNoSymlinks(executable, requireSingleLink: true);
        string coreHash = Convert.ToHexString(SHA256.HashData(binary));
        using FileStream plist = MacSafeFileSystem.OpenReadNoSymlinks(Path.Combine(contents, "Info.plist"), requireSingleLink: true);
        if (plist.Length > 65_536) throw new InvalidDataException("Audit bundle metadata is oversized.");
        string plistHash = Convert.ToHexString(SHA256.HashData(plist));
        plist.Position = 0;
        using XmlReader reader = XmlReader.Create(plist, new XmlReaderSettings
        { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, MaxCharactersInDocument = 65_536 });
        XElement[] entries = XDocument.Load(reader).Root?.Element("dict")?.Elements().ToArray()
            ?? throw new InvalidDataException("Audit bundle metadata is unavailable.");
        string Read(string key)
        {
            for (int i = 0; i + 1 < entries.Length; i++)
                if (entries[i].Name.LocalName == "key" && entries[i].Value == key && entries[i + 1].Name.LocalName == "string")
                    return entries[i + 1].Value;
            throw new InvalidDataException("Audit bundle version metadata is incomplete.");
        }
        string version = Read("CFBundleShortVersionString"), build = Read("CFBundleVersion");
        if (version != "5.0.3" || !int.TryParse(build, out int buildNumber) || buildNumber < 1)
            throw new InvalidDataException("Audit bundle version metadata is invalid.");
        return new(version, buildNumber, Environment.ProcessId, RuntimeInformation.ProcessArchitecture.ToString(), coreHash, plistHash);
    }

    private string Export(AuditReceipt receipt, string name)
    {
        RequireRoot();
        byte[] encoded = JsonSerializer.SerializeToUtf8Bytes(receipt, AuditJsonContext.Default.AuditReceipt);
        if (encoded.Length > MaximumExportBytes) throw new InvalidDataException("The bounded audit export exceeded its limit.");
        using SafeFileHandle handle = MacSafeFileSystem.CreateFileAtExclusive(_root!, name, 0x0180);
        using var stream = new FileStream(handle, FileAccess.Write, 4096, isAsync: false);
        stream.Write(encoded); stream.Flush(flushToDisk: true);
        RequireRoot();
        return Path.Combine(WorkRoot, name);
    }

    private void RequireRoot()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_root is null || !MacSafeFileSystem.GetIdentity(_root).SameObject(_rootIdentity))
            throw new IOException("The owned private audit directory is unavailable.");
        MacSafeFileSystem.RequirePathStillNamesHandle(_root, WorkRoot);
        if ((MacSafeFileSystem.GetIdentity(_root).Mode & 0x01FF) != 0x01C0)
            throw new IOException("The audit working directory is not private.");
    }

    private static bool SamePath(string first, string second) => string.Equals(
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(first)),
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(second)), StringComparison.Ordinal);

    public void Dispose()
    {
        if (_disposed) return;
        if (_operation is not null) throw new InvalidOperationException("The active audit operation must complete and join before disposal.");
        ClearOwnedHooks();
        _sourceSnapshot?.Dispose();
        _sourceSnapshot = null;
        _root?.Dispose(); _root = null;
        _disposed = true;
        // Preserve public evidence/fixtures for review. No path-based deletion
        // is performed, and no sensitive material was exported by this class.
    }

    private sealed class AuditSettingsStore : IAppSettingsStore
    {
        private readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);
        public string? Read(string key) => _values.GetValueOrDefault(key);
        public void Write(string key, string value) => _values[key] = value;
    }
}

/// <summary>
/// Owns the one audit-preparation worker until it has actually exited. The
/// initializer is synchronous background-only work, so window disposal may
/// cancel and join it without requiring the UI dispatcher. This internal
/// lifetime owner exposes no CLI/configuration/provider or fault selection.
/// </summary>
internal sealed class ReleaseAuditInitialization
{
    private readonly object _gate = new();
    private Task? _worker;
    private bool _closed;

    internal Task Start(Action<CancellationToken> initialize, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(initialize);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            if (_worker is not null) throw new InvalidOperationException("Audit preparation may start only once.");
            // Registration and close are serialized, including the window-
            // closed-before-scheduling race. The worker never awaits UI work.
            return _worker = Task.Run(() => initialize(token), token);
        }
    }

    internal void CloseAndJoin()
    {
        Task? worker;
        lock (_gate)
        {
            _closed = true;
            worker = _worker;
        }
        if (worker is null) return;
        Exception? interruptedJoin = null;
        while (true)
        {
            try { worker.GetAwaiter().GetResult(); break; }
            catch (Exception failure)
            {
                // A terminal initialization error/cancellation is observed by
                // its async owner. An interrupted wait must not let Dispose
                // advance to shared-pool reset while this worker still runs.
                if (worker.IsCompleted) break;
                interruptedJoin ??= failure;
            }
        }
        if (interruptedJoin is not null)
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(interruptedJoin).Throw();
    }
}

internal sealed class AuditOperation : IDisposable
{
    private readonly OperationPhaseProfile.Measurements _phases = new();
    private readonly NativeCipherExecutor.Measurements _native = new();
    private readonly ParallelContainerAuthenticator.PhaseMeasurementsForTests _mac = new();
    private readonly CpuWorkBudget.Measurements _cpu = new();
    private readonly List<IDisposable> _scopes = [];
    private readonly object _gate = new();
    private readonly List<AuditEntropyPhase> _entropy = [];
    private readonly long _start = Stopwatch.GetTimestamp();
    private readonly DateTime _startedUtc = DateTime.UtcNow;
    private readonly double _cpuStart = ReadProcessCpuSeconds();
    private readonly int _requestedCpu, _cpuCeiling;
    private readonly long _lockedBefore = SecureMemory.LockedBytesForTests;
    private readonly long _reservationsBefore = SecureMemory.ReservedWorkingSetBytesForTests;
    private long _workStart, _finish, _dialogTicks, _omittedEntropy;
    private bool _disposed;
    private volatile bool _observationUnavailable;
    internal string Name { get; }
    internal int Sequence { get; }

    internal AuditOperation(string name, int sequence, ArchiveOperationPolicy policy)
    {
        Name = name; Sequence = sequence;
        _requestedCpu = policy.RequestedCpuWorkers; _cpuCeiling = policy.MaxCpuWorkers;
        try
        {
            _scopes.Add(OperationPhaseProfile.ObserveForTests(_phases));
            _scopes.Add(NativeCipherExecutor.ObserveForTests(_native));
            _scopes.Add(ParallelContainerAuthenticator.ObservePhasesForTests(_mac));
            _scopes.Add(CpuWorkBudget.ObserveForTests(_cpu));
        }
        catch { Dispose(); throw; }
    }
    internal void MarkWorkStart() => Interlocked.CompareExchange(ref _workStart, Stopwatch.GetTimestamp(), 0);
    private static double ReadProcessCpuSeconds()
    {
        using Process process = Process.GetCurrentProcess();
        return process.TotalProcessorTime.TotalSeconds;
    }
    internal void ObserveEntropyPhase(string phase)
    {
        try
        {
            if (phase is not ("shuffle1" or "sha3" or "shuffle2" or "sha512" or "cleanup" or "before-publication")) return;
            lock (_gate)
            {
                if (_entropy.Count < 256) _entropy.Add(new(phase, (double)(Stopwatch.GetTimestamp() - _start) / Stopwatch.Frequency));
                else _omittedEntropy++;
            }
        }
        catch { _observationUnavailable = true; }
    }
    internal IDisposable ObserveDialogWait() => new DialogInterval(this);
    private sealed class DialogInterval(AuditOperation owner) : IDisposable
    {
        private readonly long _start = Stopwatch.GetTimestamp();
        private int _disposed;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
                Interlocked.Add(ref owner._dialogTicks, Math.Max(0, Stopwatch.GetTimestamp() - _start));
        }
    }
    public void Dispose()
    {
        if (_disposed) return;
        _finish = Stopwatch.GetTimestamp();
        for (int at = _scopes.Count - 1; at >= 0; at--)
            try { _scopes[at].Dispose(); }
            catch { _observationUnavailable = true; }
        _scopes.Clear(); _disposed = true;
    }
    internal AuditReceipt CreateReceipt(string caseId, AuditProcessIdentity identity, AuditFixture fixture,
        bool success, bool failure, bool cancelled, int faultCount, bool unexpectedSuccess, bool factorPublished,
        int pendingBeforeRetry, bool? retrySucceeded, bool? originalComparison)
    {
        if (!_disposed) throw new InvalidOperationException("The audit must finish before export.");
        double wall = (double)(_finish - _start) / Stopwatch.Frequency;
        double dialog = (double)Interlocked.Read(ref _dialogTicks) / Stopwatch.Frequency;
        double? work = _workStart == 0 ? null : Math.Max(0, (double)(_finish - _workStart) / Stopwatch.Frequency - dialog);
        OperationPhaseProfile.ProfileSnapshot phases = _phases.Snapshot();
        NativeCipherExecutor.SchedulingSnapshot native = _native.Snapshot();
        CpuWorkBudget.BudgetSnapshot cpu = _cpu.Snapshot();
        double processCpu;
        using (Process process = Process.GetCurrentProcess()) processCpu = Math.Max(0, process.TotalProcessorTime.TotalSeconds - _cpuStart);
        bool observed = !_observationUnavailable && phases.ObservationAvailable && native.observationAvailable && cpu.ObservationAvailable;
        return new(1, caseId, Sequence, Name, _startedUtc, DateTime.UtcNow, identity, fixture,
            unexpectedSuccess ? "unexpected-fault-result-blocked" : failure ? "failure" : cancelled ? "cancelled" : success ? "success" : "not-completed",
            observed, wall, dialog, work, processCpu, _requestedCpu, _cpuCeiling,
            _lockedBefore, SecureMemory.LockedBytesForTests, _reservationsBefore, SecureMemory.ReservedWorkingSetBytesForTests,
            CpuWorkBudget.ActiveWorkersForTests, phases, native, cpu, _mac.Seconds(), [.. _entropy], _omittedEntropy,
            faultCount, unexpectedSuccess, factorPublished,
            caseId != "profile" && faultCount > 0 && !unexpectedSuccess && !factorPublished && (failure || cancelled),
            pendingBeforeRetry, retrySucceeded, originalComparison,
            "Native AOT GUI diagnostic observations, not an overall release verdict. Fixture preparation and human entropy collection precede operation timing. Work wall excludes measured application dialogs but may include unmeasured file-picker/user waits; overlapping phase/queue/join sums are not CPU or end-to-end walltime. Fault cases use public canonical records and simulated adapter failures, not evidence of human mouse capture or an actual Apple RNG/mlock hardware failure. Source bytes and compressed/cipher phase bytes are distinct throughput bases.");
    }
}

internal sealed record AuditProcessIdentity(string ProductVersion, int BundleBuild, int ProcessId,
    string ProcessArchitecture, string CoreSha256, string InfoPlistSha256);
internal sealed record AuditFixture(string Identifier, long SourceBytes, int Files, int Directories, string? ManifestSha256);
internal sealed record AuditEntropyPhase(string Phase, double AtSeconds);
internal sealed record AuditReceipt(int SchemaVersion, string CaseId, int Sequence, string Operation,
    DateTime StartedUtc, DateTime TerminalUtc, AuditProcessIdentity Process, AuditFixture PublicFixture,
    string Outcome, bool ObservationAvailable, double HandlerWallSeconds, double ApplicationDialogWallSeconds,
    double? WorkWallSecondsExcludingApplicationDialogs, double ProcessCpuSeconds, int RequestedCpuWorkers,
    int InitialCpuCeiling, long LockedBytesBefore, long LockedBytesAfter, long ReservedBytesBefore, long ReservedBytesAfter,
    int ActiveCpuWorkersAfterJoin, OperationPhaseProfile.ProfileSnapshot PhaseProfile,
    NativeCipherExecutor.SchedulingSnapshot NativeScheduling, CpuWorkBudget.BudgetSnapshot CpuReservations,
    Dictionary<string, double> GlobalMacWallSecondsSum, AuditEntropyPhase[] EntropyPhases, long OmittedEntropyPhases,
    int ControlledFaultTriggers, bool UnexpectedFaultResult, bool FactorPublished, bool ExpectedControlledFaultObserved,
    int PendingCleanupBeforeRetry, bool? CleanupRetrySucceeded, bool? ProductOriginalComparison, string Interpretation);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(AuditReceipt))]
internal partial class AuditJsonContext : JsonSerializerContext { }
