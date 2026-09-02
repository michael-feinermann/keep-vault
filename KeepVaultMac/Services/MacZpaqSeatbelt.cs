#if KEEPVAULT_MACOS
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace KalynaArchiver.Services;

internal enum MacZpaqSandboxOperation
{
    AddFile,
    AddStreaming,
    ExtractVerified,
    ExtractStreaming,
    ListVerified,
    ListStreaming,
    SystemTool,
}

/// <summary>
/// Owns one descriptor-bound Seatbelt policy and all of the identities that
/// make its path grants meaningful. No macOS ZPAQ process is constructed
/// outside this type.
/// </summary>
internal sealed partial class MacZpaqSeatbelt : IDisposable
{
    private const string SandboxExecPath = "/usr/bin/sandbox-exec";
    private const string CanaryExecPath = "/usr/bin/true";
    private const string PrivateTemporaryRoot = "/private/tmp";
    private const string ProfileName = "zpaq.sb";
    private const string ForbiddenHomeName = "forbidden-home";
    private const string ForbiddenTmpName = "forbidden-tmp";
    private const string ForbiddenReadName = "known-readable";
    private const string ForbiddenWriteName = "must-not-exist";
    private const string InheritedDescriptorName = "inherited-fd";
    private const string UnixSocketName = "canary.sock";
    private const string CanaryMarker = "keepvault_sandbox_canary=verified";
    private const int FGetFd = 1;
    private const int FSetFd = 2;
    private const int FdCloseOnExec = 1;
    private const int ErrNoEntry = 2;
    private const ushort OwnerDirectoryMode = 0x01C0; // 0700
    private const ushort OwnerFileMode = 0x0180;      // 0600

    private string _executablePath = string.Empty;
    private IReadOnlyList<string> _arguments = Array.Empty<string>();
    private string _workingDirectory = string.Empty;
    private MacZpaqSandboxOperation _operation;
    private TrustedNativeFileLease? _trustedExecutable;
    private FileStream? _systemExecutable;
    private FileStream? _sandboxExecutable;
    private FileStream? _canaryExecutable;
    private SafeFileHandle? _temporaryRootHandle;
    private SafeFileHandle? _policyRootHandle;
    private MacFileIdentity _policyRootIdentity;
    private DirectorySecurityIdentity _policyRootSecurityIdentity;
    private FileStream? _profile;
    private MacFileIdentity _profileIdentity;
    private SafeFileHandle? _workingDirectoryHandle;
    private DirectorySecurityIdentity _workingDirectoryIdentity;
    private SafeFileHandle? _outputParentHandle;
    private DirectorySecurityIdentity _outputParentIdentity;
    private SafeFileHandle? _forbiddenHomeHandle;
    private SafeFileHandle? _forbiddenTmpHandle;
    private FileStream? _forbiddenRead;
    private FileStream? _inheritedDescriptor;
    private string _profileRootPath = string.Empty;
    private string _profilePath = string.Empty;
    private string _profileText = string.Empty;
    private string _forbiddenReadPath = string.Empty;
    private string _forbiddenHomeWritePath = string.Empty;
    private string _forbiddenTmpWritePath = string.Empty;
    private string _unixSocketPath = string.Empty;
    private string _allowedShmName = string.Empty;
    private string _deniedShmName = string.Empty;
    private string? _inputRoot;
    private string? _outputPath;
    private string? _outputRoot;
    private int _disposed;

    internal static Action<string>? InitializationHookForTests { get; set; }
    internal static Action<string, int>? PostStartValidationHookForTests { get; set; }

    private MacZpaqSeatbelt()
    {
    }

    private void Initialize(
        string executable,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        TrustedNativeFileLease? trustedExecutable)
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException();
        }

        _arguments = arguments;
        _trustedExecutable = trustedExecutable;
        _executablePath = RequireBoundExecutable(executable, trustedExecutable, out _systemExecutable);
        _sandboxExecutable = OpenRootOwnedSystemExecutable(SandboxExecPath);
        InitializationHookForTests?.Invoke("sandbox-executable");
        _canaryExecutable = OpenRootOwnedSystemExecutable(CanaryExecPath);
        InitializationHookForTests?.Invoke("canary-executable");
        _temporaryRootHandle = OpenAndValidatePrivateTemporaryRoot();
        InitializationHookForTests?.Invoke("temporary-root");

        string policyRootName = "keep-vault-zpaq-sandbox-" + RandomHex(16);
        _profileRootPath = Path.Combine(PrivateTemporaryRoot, policyRootName);
        MacSafeFileSystem.MkdirAt(_temporaryRootHandle!, policyRootName, OwnerDirectoryMode);
        _policyRootIdentity = MacSafeFileSystem.GetIdentityAt(_temporaryRootHandle!, policyRootName);
        _policyRootHandle = MacSafeFileSystem.OpenDirectoryHandleAt(_temporaryRootHandle!, policyRootName);
        MacSafeFileSystem.SetUnixFileMode(_policyRootHandle, OwnerDirectoryMode);
        RequireCallerOwnedMode(_policyRootHandle, OwnerDirectoryMode, directory: true, "ZPAQ policy root");
        RequireSameEntry(_temporaryRootHandle!, policyRootName, _policyRootHandle, "ZPAQ policy root");
        InitializationHookForTests?.Invoke("policy-root");

        _operation = Classify(arguments);
        string requestedWorkingDirectory = _operation is MacZpaqSandboxOperation.ListVerified
            or MacZpaqSandboxOperation.ListStreaming
            ? _profileRootPath
            : workingDirectory;
        _workingDirectory = RequirePhysicalDirectory(requestedWorkingDirectory, out _workingDirectoryHandle);
        _workingDirectoryIdentity = CaptureDirectorySecurityIdentity(_workingDirectoryHandle);
        InitializationHookForTests?.Invoke("working-directory");

        (_inputRoot, _outputPath, _outputRoot) = ResolveOperationPaths(
            _operation,
            arguments,
            _workingDirectory,
            out _outputParentHandle,
            out _outputParentIdentity);
        InitializationHookForTests?.Invoke("operation-paths");

        MacSafeFileSystem.MkdirAt(_policyRootHandle, ForbiddenHomeName, OwnerDirectoryMode);
        MacSafeFileSystem.MkdirAt(_policyRootHandle, ForbiddenTmpName, OwnerDirectoryMode);
        _forbiddenHomeHandle = MacSafeFileSystem.OpenDirectoryHandleAt(_policyRootHandle, ForbiddenHomeName);
        _forbiddenTmpHandle = MacSafeFileSystem.OpenDirectoryHandleAt(_policyRootHandle, ForbiddenTmpName);
        MacSafeFileSystem.SetUnixFileMode(_forbiddenHomeHandle, OwnerDirectoryMode);
        MacSafeFileSystem.SetUnixFileMode(_forbiddenTmpHandle, OwnerDirectoryMode);
        RequireCallerOwnedMode(_forbiddenHomeHandle, OwnerDirectoryMode, directory: true, "canary HOME root");
        RequireCallerOwnedMode(_forbiddenTmpHandle, OwnerDirectoryMode, directory: true, "canary temporary root");
        InitializationHookForTests?.Invoke("forbidden-roots");

        SafeFileHandle forbiddenReadHandle = MacSafeFileSystem.CreateFileAtExclusive(
            _forbiddenHomeHandle,
            ForbiddenReadName,
            OwnerFileMode);
        _forbiddenRead = CreateOwnedFileStream(forbiddenReadHandle);
        _forbiddenRead.WriteByte(0x4B);
        _forbiddenRead.Flush(flushToDisk: true);
        _forbiddenRead.Position = 0;
        InitializationHookForTests?.Invoke("forbidden-read");

        SafeFileHandle inheritedHandle = MacSafeFileSystem.CreateFileAtExclusive(
            _policyRootHandle,
            InheritedDescriptorName,
            OwnerFileMode);
        _inheritedDescriptor = CreateOwnedFileStream(inheritedHandle);
        InitializationHookForTests?.Invoke("inherited-descriptor");

        _profilePath = Path.Combine(_profileRootPath, ProfileName);
        _forbiddenReadPath = Path.Combine(_profileRootPath, ForbiddenHomeName, ForbiddenReadName);
        _forbiddenHomeWritePath = Path.Combine(_profileRootPath, ForbiddenHomeName, ForbiddenWriteName);
        _forbiddenTmpWritePath = Path.Combine(_profileRootPath, ForbiddenTmpName, ForbiddenWriteName);
        _unixSocketPath = Path.Combine(_profileRootPath, UnixSocketName);
        _allowedShmName = "/kv12-" + RandomHex(12);
        do
        {
            _deniedShmName = "/kv12-" + RandomHex(12);
        }
        while (string.Equals(_deniedShmName, _allowedShmName, StringComparison.Ordinal));

        SafeFileHandle profileHandle = MacSafeFileSystem.CreateFileAtExclusive(
            _policyRootHandle,
            ProfileName,
            OwnerFileMode);
        _profile = CreateOwnedFileStream(profileHandle, 4096);
        _profileText = BuildProfile(_operation);
        byte[] profileBytes = Encoding.UTF8.GetBytes(_profileText);
        try
        {
            _profile.Write(profileBytes);
            _profile.Flush(flushToDisk: true);
            _profile.Position = 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(profileBytes);
        }
        _profileIdentity = MacSafeFileSystem.GetIdentity(_profile.SafeFileHandle);
        RequireCallerOwnedMode(_profile.SafeFileHandle, OwnerFileMode, directory: false, "ZPAQ Seatbelt profile");
        // Directory size/timestamps legitimately changed while the children
        // above were created. Rebind the final initialized identity only after
        // every owned object and durable profile byte is in place.
        _policyRootIdentity = MacSafeFileSystem.GetIdentity(_policyRootHandle);
        _policyRootSecurityIdentity = CaptureDirectorySecurityIdentity(_policyRootHandle);
        InitializationHookForTests?.Invoke("profile");
        RequireValid();
    }

    private static MacZpaqSeatbelt CreateInitialized(
        string executable,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        TrustedNativeFileLease? trustedExecutable)
    {
        var policy = new MacZpaqSeatbelt();
        try
        {
            policy.Initialize(executable, arguments, workingDirectory, trustedExecutable);
            return policy;
        }
        catch (Exception operationFailure)
        {
            try
            {
                policy.Dispose();
            }
            catch (Exception cleanupFailure)
            {
                throw new AggregateException(operationFailure, cleanupFailure);
            }
            throw;
        }
    }

    internal static async Task<MacZpaqSeatbelt> CreateForZpaqAsync(
        TrustedNativeFileLease trustedExecutable,
        IEnumerable<string> arguments,
        string workingDirectory,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(trustedExecutable);
        string[] stableArguments = arguments?.ToArray()
            ?? throw new ArgumentNullException(nameof(arguments));
        MacZpaqSeatbelt? policy = null;
        try
        {
            policy = CreateInitialized(
                trustedExecutable.Path,
                stableArguments,
                workingDirectory,
                trustedExecutable);
            await policy.RunCanaryAsync(cancellationToken).ConfigureAwait(false);
            return policy;
        }
        catch (Exception operationFailure)
        {
            if (policy is null)
            {
                throw;
            }
            try
            {
                policy.Dispose();
            }
            catch (Exception cleanupFailure)
            {
                throw new AggregateException(operationFailure, cleanupFailure);
            }
            throw;
        }
    }

    internal static MacZpaqSeatbelt CreateForSystemTool(
        string executable,
        IEnumerable<string> arguments,
        string workingDirectory) =>
        CreateInitialized(
            executable,
            arguments?.ToArray() ?? throw new ArgumentNullException(nameof(arguments)),
            workingDirectory,
            trustedExecutable: null);

    internal Process CreateProductionProcess()
    {
        RequireValid();
        if (_operation == MacZpaqSandboxOperation.SystemTool)
        {
            return BuildProcess(_arguments);
        }

        var productionArguments = new List<string>(_arguments);
        if (_operation is MacZpaqSandboxOperation.ExtractVerified
            or MacZpaqSandboxOperation.ListVerified)
        {
            productionArguments.Add("-kv-shm-name");
            productionArguments.Add(_allowedShmName);
        }
        return BuildProcess(productionArguments);
    }

    internal void RequireValid()
    {
        ThrowIfDisposed();
        RequireRootOwnedSystemExecutable(
            _sandboxExecutable ?? throw new ObjectDisposedException(nameof(MacZpaqSeatbelt)),
            SandboxExecPath);
        RequireRootOwnedSystemExecutable(
            _canaryExecutable ?? throw new ObjectDisposedException(nameof(MacZpaqSeatbelt)),
            CanaryExecPath);
        if (_trustedExecutable is not null)
        {
            MacSafeFileSystem.RequirePathStillNamesHandle(
                _trustedExecutable.Stream.SafeFileHandle,
                _trustedExecutable.Path);
        }
        else if (_systemExecutable is not null)
        {
            RequireRootOwnedSystemExecutable(_systemExecutable, _executablePath);
        }

        SafeFileHandle policyRoot = _policyRootHandle
            ?? throw new ObjectDisposedException(nameof(MacZpaqSeatbelt));
        FileStream profile = _profile
            ?? throw new ObjectDisposedException(nameof(MacZpaqSeatbelt));
        RequireDirectorySecurityIdentity(
            policyRoot,
            _policyRootSecurityIdentity,
            "ZPAQ policy root");
        MacSafeFileSystem.RequirePathStillNamesHandle(policyRoot, _profileRootPath);
        if (!MacSafeFileSystem.GetIdentity(profile.SafeFileHandle).SameObjectAndMetadata(_profileIdentity))
        {
            throw new IOException("The bound ZPAQ Seatbelt profile changed while in use.");
        }
        MacSafeFileSystem.RequirePathStillNamesHandle(profile.SafeFileHandle, _profilePath);

        SafeFileHandle working = _workingDirectoryHandle
            ?? throw new ObjectDisposedException(nameof(MacZpaqSeatbelt));
        RequireDirectorySecurityIdentity(
            working,
            _workingDirectoryIdentity,
            "ZPAQ working directory");
        MacSafeFileSystem.RequirePathStillNamesHandle(working, _workingDirectory);

        if (_outputParentHandle is not null)
        {
            RequireDirectorySecurityIdentity(
                _outputParentHandle,
                _outputParentIdentity,
                "ZPAQ output parent");
            string outputParent = Path.GetDirectoryName(_outputPath!)!;
            MacSafeFileSystem.RequirePathStillNamesHandle(_outputParentHandle, outputParent);
        }
    }

    internal void RequireValidAfterStart(string stage, int processId)
    {
        PostStartValidationHookForTests?.Invoke(stage, processId);
        RequireValid();
    }

    internal void RequireNoSharedMemoryResidue()
    {
        ThrowIfDisposed();
        bool found = RemoveSharedMemoryIfPresent(_allowedShmName);
        found |= RemoveSharedMemoryIfPresent(_deniedShmName);
        if (found)
        {
            throw new IOException("ZPAQ left or recreated a bound POSIX shared-memory object.");
        }
    }

    private async Task RunCanaryAsync(CancellationToken cancellationToken)
    {
        RequireValid();
        using var tcpListener = new TcpListener(IPAddress.Loopback, 0);
        tcpListener.Start(backlog: 1);
        int port = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
        using var unixListener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        unixListener.Bind(new UnixDomainSocketEndPoint(_unixSocketPath));
        unixListener.Listen(backlog: 1);
        MacFileIdentity unixSocketIdentity = MacSafeFileSystem.GetIdentityAt(
            _policyRootHandle!,
            UnixSocketName);

        int inheritedDescriptor = GetDescriptor(_inheritedDescriptor!.SafeFileHandle);
        if (Fcntl(inheritedDescriptor, FSetFd, 0) != 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not make the ZPAQ canary descriptor inheritable.");
        }

        var canaryArguments = new[]
        {
            "--keepvault-sandbox-canary",
            "--deny-read", _forbiddenReadPath,
            "--deny-home-write", _forbiddenHomeWritePath,
            "--deny-tmp-write", _forbiddenTmpWritePath,
            "--tcp-port", port.ToString(CultureInfo.InvariantCulture),
            "--unix-socket", _unixSocketPath,
            "--exec", CanaryExecPath,
            "--inherited-fd", inheritedDescriptor.ToString(CultureInfo.InvariantCulture),
            "--shm-mode", UsesVerifiedSharedMemory(_operation) ? "exact" : "none",
            "--allowed-shm", _allowedShmName,
            "--denied-shm", _deniedShmName,
        };

        Exception? operationFailure = null;
        try
        {
            await RunCanaryProcessAsync(
                canaryArguments,
                CanaryMarker,
                "canary-policy",
                cancellationToken).ConfigureAwait(false);
            await RunCanaryProcessAsync(
                ["--keepvault-sandbox-exec-canary", "--exec", CanaryExecPath],
                "keepvault_sandbox_exec_canary=verified",
                "canary-exec",
                cancellationToken).ConfigureAwait(false);
            RequireValid();
            if (tcpListener.Pending() || unixListener.Poll(0, SelectMode.SelectRead))
            {
                throw new InvalidOperationException("The ZPAQ Seatbelt canary reached a forbidden local listener.");
            }
            RequireCanaryFilesystemUnchanged();
            RequireNoSharedMemoryResidue();
        }
        catch (Exception exception)
        {
            operationFailure = exception;
        }
        finally
        {
            var cleanupFailures = new List<Exception>();
            try
            {
                if (Fcntl(inheritedDescriptor, FSetFd, FdCloseOnExec) != 0)
                {
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not restore close-on-exec for the ZPAQ canary descriptor.");
                }
            }
            catch (Exception exception)
            {
                cleanupFailures.Add(exception);
            }
            try
            {
                MacFileIdentity current = MacSafeFileSystem.GetIdentityAt(_policyRootHandle!, UnixSocketName);
                if (!current.SameObject(unixSocketIdentity))
                {
                    throw new IOException("The ZPAQ canary socket path was substituted.");
                }
                MacSafeFileSystem.UnlinkAt(_policyRootHandle!, UnixSocketName);
            }
            catch (Exception exception)
            {
                cleanupFailures.Add(exception);
            }
            try
            {
                bool found = RemoveSharedMemoryIfPresent(_allowedShmName);
                found |= RemoveSharedMemoryIfPresent(_deniedShmName);
                if (found)
                {
                    throw new IOException("The ZPAQ canary left or recreated shared memory.");
                }
            }
            catch (Exception exception)
            {
                cleanupFailures.Add(exception);
            }

            if (operationFailure is not null)
            {
                if (cleanupFailures.Count != 0)
                {
                    throw new AggregateException([operationFailure, .. cleanupFailures]);
                }
                ExceptionDispatchInfo.Capture(operationFailure).Throw();
            }
            if (cleanupFailures.Count == 1)
            {
                ExceptionDispatchInfo.Capture(cleanupFailures[0]).Throw();
            }
            if (cleanupFailures.Count > 1)
            {
                throw new AggregateException(cleanupFailures);
            }
        }
    }

    private async Task RunCanaryProcessAsync(
        IReadOnlyList<string> arguments,
        string expectedErrorMarker,
        string validationStage,
        CancellationToken cancellationToken)
    {
        Process? process = null;
        Task<string>? stdout = null;
        Task<string>? stderr = null;
        bool started = false;
        Exception? operationFailure = null;
        var cleanupFailures = new List<Exception>();
        string capturedOutput = string.Empty;
        string capturedError = string.Empty;
        try
        {
            process = BuildProcess(arguments);
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            if (!process.Start())
            {
                throw new InvalidOperationException("The ZPAQ Seatbelt canary could not be started.");
            }
            started = true;
            RequireValidAfterStart(validationStage, process.Id);
            stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
            stderr = process.StandardError.ReadToEndAsync(cancellationToken);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            capturedOutput = await stdout.ConfigureAwait(false);
            capturedError = await stderr.ConfigureAwait(false);
            if (process.ExitCode != 0
                || capturedOutput.Length != 0
                || !string.Equals(capturedError.Trim(), expectedErrorMarker, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The ZPAQ Seatbelt kernel-enforcement canary failed.");
            }
            RequireValid();
        }
        catch (Exception exception)
        {
            operationFailure = exception;
        }
        finally
        {
            if (started && operationFailure is not null && process is not null)
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                    }
                }
                catch (Exception exception)
                {
                    cleanupFailures.Add(exception);
                }
                try
                {
                    using var cleanupTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    await process.WaitForExitAsync(cleanupTimeout.Token).ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    cleanupFailures.Add(exception);
                }
            }
            foreach (Task<string>? reader in new[] { stdout, stderr })
            {
                if (reader is null)
                {
                    continue;
                }
                try
                {
                    using var readerTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    await reader.WaitAsync(readerTimeout.Token).ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    if (operationFailure is null || !ReferenceEquals(exception, operationFailure))
                    {
                        cleanupFailures.Add(exception);
                    }
                }
            }
            if (process is not null)
            {
                try
                {
                    process.Dispose();
                }
                catch (Exception exception)
                {
                    cleanupFailures.Add(exception);
                }
            }
        }

        if (operationFailure is not null)
        {
            if (cleanupFailures.Count != 0)
            {
                throw new AggregateException([operationFailure, .. cleanupFailures]);
            }
            ExceptionDispatchInfo.Capture(operationFailure).Throw();
        }
        if (cleanupFailures.Count == 1)
        {
            ExceptionDispatchInfo.Capture(cleanupFailures[0]).Throw();
        }
        if (cleanupFailures.Count > 1)
        {
            throw new AggregateException(cleanupFailures);
        }
    }

    private Process BuildProcess(IEnumerable<string> nativeArguments)
    {
        RequireValid();
        var start = new ProcessStartInfo
        {
            FileName = SandboxExecPath,
            WorkingDirectory = _workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        start.Environment.Clear();
        start.Environment["LANG"] = "C";
        start.Environment["LC_ALL"] = "C";
        start.Environment["TZ"] = "UTC";
        // The 0600 descriptor-bound file is retained as an auditable copy, but
        // the launcher consumes the already-held immutable text. Reopening the
        // profile by name would let a same-UID process swap the private root in
        // the final validation-to-open window.
        start.ArgumentList.Add("-p");
        start.ArgumentList.Add(_profileText);
        AddProfileParameter(start, "EXECUTABLE", _executablePath);
        AddProfileParameter(start, "WORKING_DIRECTORY", _workingDirectory);
        AddProfileParameter(start, "CANARY_UNIX_SOCKET", _unixSocketPath);
        AddProfileParameter(start, "VERIFIED_SHM_NAME", _allowedShmName);
        if (_inputRoot is not null)
        {
            AddProfileParameter(start, "INPUT_ROOT", _inputRoot);
        }
        if (_outputPath is not null)
        {
            AddProfileParameter(start, "OUTPUT_FILE", _outputPath);
        }
        if (_outputRoot is not null)
        {
            AddProfileParameter(start, "OUTPUT_ROOT", _outputRoot);
        }
        start.ArgumentList.Add(_executablePath);
        foreach (string argument in nativeArguments)
        {
            start.ArgumentList.Add(argument);
        }
        return new Process { StartInfo = start };
    }

    private void RequireCanaryFilesystemUnchanged()
    {
        IReadOnlyList<MacDirectoryEntry> homeEntries = MacSafeFileSystem.ReadDirectoryEntriesNoFollow(_forbiddenHomeHandle!);
        if (homeEntries.Count != 1
            || !string.Equals(homeEntries[0].Name, ForbiddenReadName, StringComparison.Ordinal)
            || !homeEntries[0].Identity.SameObject(MacSafeFileSystem.GetIdentity(_forbiddenRead!.SafeFileHandle)))
        {
            throw new IOException("The ZPAQ Seatbelt canary changed its forbidden HOME tree.");
        }
        if (!MacSafeFileSystem.IsDirectoryEmptyDescriptor(_forbiddenTmpHandle!))
        {
            throw new IOException("The ZPAQ Seatbelt canary changed its forbidden temporary tree.");
        }
    }

    private static string BuildProfile(MacZpaqSandboxOperation operation)
    {
        var profile = new StringBuilder(
            "(version 1)\n"
            + "(deny default)\n"
            + "(deny network*)\n"
            + "(deny process-fork)\n"
            + "(allow process-exec (literal (param \"EXECUTABLE\")))\n"
            + "(allow file-read*\n"
            + "  (literal \"/\")\n"
            + "  (literal \"/dev/fd\")\n"
            + "  (literal (param \"EXECUTABLE\")))\n"
            + "(allow file-read-metadata\n"
            + "  (literal (param \"WORKING_DIRECTORY\"))\n"
            + "  (literal (param \"CANARY_UNIX_SOCKET\")))\n");
        switch (operation)
        {
            case MacZpaqSandboxOperation.AddFile:
                profile.Append(
                    "(allow file-read* (subpath (param \"INPUT_ROOT\")))\n"
                    + "(allow file-write* (literal (param \"OUTPUT_FILE\")))\n");
                break;
            case MacZpaqSandboxOperation.AddStreaming:
                profile.Append("(allow file-read* (subpath (param \"INPUT_ROOT\")))\n");
                break;
            case MacZpaqSandboxOperation.ExtractVerified:
            case MacZpaqSandboxOperation.ExtractStreaming:
                profile.Append(
                    "(allow file-read* (subpath (param \"OUTPUT_ROOT\")))\n"
                    + "(allow file-write* (subpath (param \"OUTPUT_ROOT\")))\n");
                break;
            case MacZpaqSandboxOperation.ListVerified:
            case MacZpaqSandboxOperation.ListStreaming:
            case MacZpaqSandboxOperation.SystemTool:
                // /bin/sh is a system selector on macOS whose shell variant
                // is resolved through this root-owned metadata file. The
                // selected root-owned bash image must be executable as well.
                // Keep both grants exact and limited to the system-tool test
                // seam; the production ZPAQ profiles never use this operation.
                if (operation == MacZpaqSandboxOperation.SystemTool)
                {
                    profile.Append(
                        "(allow process-exec (literal \"/bin/bash\"))\n"
                        + "(allow file-read*"
                        + " (literal \"/bin/bash\")"
                        + " (literal \"/private/var/select/sh\"))\n");
                }
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(operation));
        }
        if (UsesVerifiedSharedMemory(operation))
        {
            profile.Append(
                "(allow ipc-posix-shm-read-data\n"
                + "       ipc-posix-shm-write-create\n"
                + "       ipc-posix-shm-write-data\n"
                + "       ipc-posix-shm-write-unlink\n"
                + "  (ipc-posix-name (param \"VERIFIED_SHM_NAME\")))\n");
        }
        return profile.ToString();
    }

    internal static string BuildProfileForTests(MacZpaqSandboxOperation operation) =>
        BuildProfile(operation);

    private static MacZpaqSandboxOperation Classify(IReadOnlyList<string> arguments)
    {
        if (arguments.Count >= 2 && string.Equals(arguments[0], "add", StringComparison.Ordinal))
        {
            if (!Path.IsPathFullyQualified(arguments[1]))
            {
                throw new InvalidOperationException("A sandboxed ZPAQ file archive target must be absolute.");
            }
            return MacZpaqSandboxOperation.AddFile;
        }
        if (arguments.Count >= 3 && string.Equals(arguments[0], "--pipe", StringComparison.Ordinal))
        {
            return arguments[1] switch
            {
                "add" when arguments[2] == "-" => MacZpaqSandboxOperation.AddStreaming,
                "extract" when arguments[2] == "-" => MacZpaqSandboxOperation.ExtractStreaming,
                "list" when arguments[2] == "-" => MacZpaqSandboxOperation.ListStreaming,
                _ => throw new InvalidOperationException("Unsupported sandboxed ZPAQ pipe operation."),
            };
        }
        if (arguments.Count >= 3 && string.Equals(arguments[0], "--verified-stdin", StringComparison.Ordinal))
        {
            return arguments[1] switch
            {
                "extract" when arguments[2] == "-" => MacZpaqSandboxOperation.ExtractVerified,
                "list" when arguments[2] == "-" => MacZpaqSandboxOperation.ListVerified,
                _ => throw new InvalidOperationException("Unsupported sandboxed verified ZPAQ operation."),
            };
        }
        int explicitFileList = -1;
        for (int index = 0; index < arguments.Count; index++)
        {
            if (string.Equals(arguments[index], "--", StringComparison.Ordinal))
            {
                explicitFileList = index;
                break;
            }
        }
        if ((arguments.Count > 0
                && arguments[0].StartsWith("--keepvault-", StringComparison.Ordinal))
            || arguments.Take(explicitFileList < 0 ? arguments.Count : explicitFileList)
                .Any(static argument => string.Equals(argument, "-kv-shm-name", StringComparison.Ordinal)))
        {
            throw new InvalidOperationException("Internal ZPAQ sandbox options cannot enter through an application operation.");
        }
        return MacZpaqSandboxOperation.SystemTool;
    }

    private static (string? InputRoot, string? OutputPath, string? OutputRoot) ResolveOperationPaths(
        MacZpaqSandboxOperation operation,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        out SafeFileHandle? outputParent,
        out DirectorySecurityIdentity outputParentIdentity)
    {
        outputParent = null;
        outputParentIdentity = default;
        switch (operation)
        {
            case MacZpaqSandboxOperation.AddFile:
            {
                string output = Path.GetFullPath(arguments[1]);
                string parent = Path.GetDirectoryName(output)
                    ?? throw new InvalidOperationException("The ZPAQ output has no parent directory.");
                outputParent = MacSafeFileSystem.OpenDirectoryHandle(parent);
                outputParentIdentity = CaptureDirectorySecurityIdentity(outputParent);
                MacSafeFileSystem.RequirePathStillNamesHandle(outputParent, parent);
                if (File.Exists(output) || Directory.Exists(output))
                {
                    throw new IOException("The sandboxed ZPAQ archive output already exists.");
                }
                return (workingDirectory, output, null);
            }
            case MacZpaqSandboxOperation.AddStreaming:
                return (workingDirectory, null, null);
            case MacZpaqSandboxOperation.ExtractVerified:
            case MacZpaqSandboxOperation.ExtractStreaming:
                return (null, null, workingDirectory);
            case MacZpaqSandboxOperation.ListVerified:
            case MacZpaqSandboxOperation.ListStreaming:
            case MacZpaqSandboxOperation.SystemTool:
                return (null, null, null);
            default:
                throw new ArgumentOutOfRangeException(nameof(operation));
        }
    }

    private static string RequireBoundExecutable(
        string executable,
        TrustedNativeFileLease? trustedExecutable,
        out FileStream? systemExecutable)
    {
        string fullPath = Path.GetFullPath(executable);
        systemExecutable = null;
        if (trustedExecutable is not null)
        {
            if (!string.Equals(fullPath, trustedExecutable.Path, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The trusted ZPAQ lease does not match the requested executable.");
            }
            MacSafeFileSystem.RequirePathStillNamesHandle(trustedExecutable.Stream.SafeFileHandle, fullPath);
            return fullPath;
        }

        systemExecutable = OpenRootOwnedSystemExecutable(fullPath);
        return fullPath;
    }

    private static FileStream OpenRootOwnedSystemExecutable(string path)
    {
        string fullPath = Path.GetFullPath(path);
        FileStream stream = MacSafeFileSystem.OpenReadNoSymlinks(fullPath);
        try
        {
            RequireRootOwnedSystemExecutable(stream, fullPath);
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private static void RequireRootOwnedSystemExecutable(FileStream stream, string path)
    {
        MacSafeFileSystem.RequirePathStillNamesHandle(stream.SafeFileHandle, path);
        DarwinStat status = GetStatus(stream.SafeFileHandle);
        if ((status.Mode & 0xF000) != 0x8000
            || status.Uid != 0
            || (status.Mode & 0x0012) != 0
            || (status.Mode & 0x0040) == 0)
        {
            throw new IOException("A required ZPAQ system executable is not a physical root-owned non-writable executable.");
        }
    }

    private static SafeFileHandle OpenAndValidatePrivateTemporaryRoot()
    {
        string canonical = MacSafeFileSystem.ResolveExistingRealPath(PrivateTemporaryRoot);
        if (!string.Equals(canonical, PrivateTemporaryRoot, StringComparison.Ordinal))
        {
            throw new IOException("The fixed macOS temporary root does not resolve to /private/tmp.");
        }
        SafeFileHandle handle = MacSafeFileSystem.OpenDirectoryHandle(PrivateTemporaryRoot);
        try
        {
            DarwinStat status = GetStatus(handle);
            if ((status.Mode & 0xF000) != 0x4000
                || status.Uid != 0
                || (status.Mode & 0x0FFF) != 0x03FF)
            {
                throw new IOException("The fixed macOS temporary root is not root-owned mode 1777.");
            }
            MacSafeFileSystem.RequirePathStillNamesHandle(handle, PrivateTemporaryRoot);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static string RequirePhysicalDirectory(string path, out SafeFileHandle handle)
    {
        string fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        handle = MacSafeFileSystem.OpenDirectoryHandle(fullPath);
        MacSafeFileSystem.RequirePathStillNamesHandle(handle, fullPath);
        return fullPath;
    }

    private static void RequireCallerOwnedMode(
        SafeFileHandle handle,
        ushort permissions,
        bool directory,
        string description)
    {
        DarwinStat status = GetStatus(handle);
        ushort expectedType = directory ? (ushort)0x4000 : (ushort)0x8000;
        if ((status.Mode & 0xF000) != expectedType
            || status.Uid != GetEuid()
            || (status.Mode & 0x01FF) != permissions
            || (!directory && status.LinkCount != 1))
        {
            throw new IOException($"The {description} has unsafe ownership, type, mode, or link count.");
        }
    }

    private static void RequireSameEntry(
        SafeFileHandle parent,
        string name,
        SafeFileHandle opened,
        string description)
    {
        MacFileIdentity entry = MacSafeFileSystem.GetIdentityAt(parent, name);
        MacFileIdentity handle = MacSafeFileSystem.GetIdentity(opened);
        if (!entry.SameObject(handle))
        {
            throw new IOException($"The {description} path does not identify its bound descriptor.");
        }
    }

    private static void AddProfileParameter(ProcessStartInfo start, string name, string value)
    {
        if (string.IsNullOrEmpty(value)
            || value.IndexOf('\0') >= 0
            || value.Any(static character => char.IsControl(character)))
        {
            throw new InvalidOperationException("A ZPAQ Seatbelt parameter contains forbidden characters.");
        }
        start.ArgumentList.Add("-D");
        start.ArgumentList.Add(name + "=" + value);
    }

    private static FileStream CreateOwnedFileStream(SafeFileHandle handle, int bufferSize = 1)
    {
        try
        {
            return new FileStream(handle, FileAccess.ReadWrite, bufferSize, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static bool UsesVerifiedSharedMemory(MacZpaqSandboxOperation operation) =>
        operation is MacZpaqSandboxOperation.ExtractVerified
            or MacZpaqSandboxOperation.ListVerified;

    private static string RandomHex(int byteCount)
    {
        byte[] random = RandomNumberGenerator.GetBytes(byteCount);
        try
        {
            return Convert.ToHexStringLower(random);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
        }
    }

    private static int GetDescriptor(SafeFileHandle handle)
    {
        bool added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            return checked((int)handle.DangerousGetHandle());
        }
        finally
        {
            if (added)
            {
                handle.DangerousRelease();
            }
        }
    }

    private static DarwinStat GetStatus(SafeFileHandle handle)
    {
        bool added = false;
        try
        {
            handle.DangerousAddRef(ref added);
            int descriptor = checked((int)handle.DangerousGetHandle());
            if (FStat(descriptor, out DarwinStat status) != 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not inspect a bound ZPAQ security object.");
            }
            return status;
        }
        finally
        {
            if (added)
            {
                handle.DangerousRelease();
            }
        }
    }

    private static DirectorySecurityIdentity CaptureDirectorySecurityIdentity(SafeFileHandle handle)
    {
        DarwinStat status = GetStatus(handle);
        if ((status.Mode & 0xF000) != 0x4000)
        {
            throw new IOException("A bound ZPAQ path is no longer a directory.");
        }
        return new DirectorySecurityIdentity(
            status.Device,
            status.Inode,
            status.Uid,
            status.Gid,
            status.Mode);
    }

    private static void RequireDirectorySecurityIdentity(
        SafeFileHandle handle,
        DirectorySecurityIdentity expected,
        string description)
    {
        DirectorySecurityIdentity current = CaptureDirectorySecurityIdentity(handle);
        if (current != expected)
        {
            throw new IOException($"The bound {description} changed its identity, ownership, type, or mode while in use.");
        }
    }

    private static bool RemoveSharedMemoryIfPresent(string name)
    {
        if (!IsVerifiedSharedMemoryName(name))
        {
            return false;
        }
        if (ShmUnlink(name) == 0)
        {
            return true;
        }
        int error = Marshal.GetLastPInvokeError();
        if (error != ErrNoEntry)
        {
            throw new Win32Exception(error, "Could not prove that a ZPAQ shared-memory object is absent.");
        }
        return false;
    }

    private static bool IsVerifiedSharedMemoryName(string name) =>
        name.Length == 30
        && name.StartsWith("/kv12-", StringComparison.Ordinal)
        && name.AsSpan(6).IndexOfAnyExcept("0123456789abcdef") < 0;

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(MacZpaqSeatbelt));
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        var failures = new List<Exception>();
        void DisposeOne(IDisposable? value)
        {
            try
            {
                value?.Dispose();
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }

        try
        {
            bool found = RemoveSharedMemoryIfPresent(_allowedShmName);
            found |= RemoveSharedMemoryIfPresent(_deniedShmName);
            if (found)
            {
                failures.Add(new IOException("ZPAQ shared-memory residue was removed during policy cleanup."));
            }
        }
        catch (Exception exception)
        {
            failures.Add(exception);
        }

        DisposeOne(_profile);
        _profile = null;
        DisposeOne(_forbiddenRead);
        _forbiddenRead = null;
        DisposeOne(_inheritedDescriptor);
        _inheritedDescriptor = null;
        DisposeOne(_forbiddenHomeHandle);
        _forbiddenHomeHandle = null;
        DisposeOne(_forbiddenTmpHandle);
        _forbiddenTmpHandle = null;
        DisposeOne(_workingDirectoryHandle);
        _workingDirectoryHandle = null;
        DisposeOne(_outputParentHandle);
        _outputParentHandle = null;
        DisposeOne(_systemExecutable);
        DisposeOne(_sandboxExecutable);
        DisposeOne(_canaryExecutable);

        SafeFileHandle? policyRoot = _policyRootHandle;
        _policyRootHandle = null;
        if (policyRoot is not null)
        {
            try
            {
                MacSafeFileSystem.DeleteDirectoryContentsDescriptor(policyRoot);
                policyRoot.Dispose();
                policyRoot = null;
                MacSafeFileSystem.DeleteDirectoryTreeBound(_profileRootPath, _policyRootIdentity);
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
            finally
            {
                DisposeOne(policyRoot);
            }
        }
        else if (!string.IsNullOrEmpty(_profileRootPath)
            && _policyRootIdentity != default)
        {
            try
            {
                MacSafeFileSystem.DeleteDirectoryTreeBound(_profileRootPath, _policyRootIdentity);
            }
            catch (Exception exception)
            {
                failures.Add(exception);
            }
        }
        DisposeOne(_temporaryRootHandle);
        _temporaryRootHandle = null;

        if (failures.Count == 1)
        {
            ExceptionDispatchInfo.Capture(failures[0]).Throw();
        }
        if (failures.Count > 1)
        {
            throw new AggregateException("ZPAQ Seatbelt cleanup failed.", failures);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct DarwinStat
    {
        internal int Device;
        internal ushort Mode;
        internal ushort LinkCount;
        internal ulong Inode;
        internal uint Uid;
        internal uint Gid;
        internal int Rdev;
        internal DarwinTimespec AccessTime;
        internal DarwinTimespec ModificationTime;
        internal DarwinTimespec ChangeTime;
        internal DarwinTimespec BirthTime;
        internal long Size;
        internal long Blocks;
        internal int BlockSize;
        internal uint Flags;
        internal uint Generation;
        internal int Spare;
        internal fixed long Reserved[2];
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DarwinTimespec
    {
        internal long Seconds;
        internal long Nanoseconds;
    }

    private readonly record struct DirectorySecurityIdentity(
        int Device,
        ulong Inode,
        uint Uid,
        uint Gid,
        ushort Mode);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fstat", SetLastError = true)]
    private static partial int FStat(int descriptor, out DarwinStat status);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "geteuid")]
    private static partial uint GetEuid();

    [LibraryImport("libSystem.B.dylib", EntryPoint = "fcntl", SetLastError = true)]
    private static partial int Fcntl(int descriptor, int command, int argument);

    [LibraryImport("libSystem.B.dylib", EntryPoint = "shm_unlink", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int ShmUnlink(string name);
}
#endif
