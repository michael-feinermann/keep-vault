using System.Diagnostics;
using System.Security.Cryptography;
using KalynaArchiver.Services;

internal static partial class MacComprehensiveTests
{
    private static readonly string[] ZpaqPolicyInitializationStages =
    [
        "sandbox-executable",
        "canary-executable",
        "temporary-root",
        "policy-root",
        "working-directory",
        "operation-paths",
        "forbidden-roots",
        "forbidden-read",
        "inherited-descriptor",
        "profile",
    ];

    private static async Task TestZpaqSeatbeltRuntimeAsync()
    {
        Require(OperatingSystem.IsMacOS(), "The ZPAQ Seatbelt runtime gate requires macOS.");
        Require(File.Exists(MacZpaqRootAnchor.ExecutablePath),
            "The root-owned v12 ZPAQ anchor is absent. Run the verified macOS installer before the Seatbelt release gate.");
        using TrustedNativeFileLease trusted = NativeToolIntegrity.AcquireTrustedFile(
            MacZpaqRootAnchor.ExecutablePath);
        MacZpaqRootAnchor.RequireSecureInstalledSet(trusted.Stream);
        MacZpaqRootAnchor.RequireMatchesSealedApplicationCopy(trusted.Stream);

        TestZpaqSeatbeltProfileMatrix();
        await TestZpaqSeatbeltInitializationCleanupAsync(trusted).ConfigureAwait(false);
        await TestZpaqSeatbeltOperationCanariesAsync(trusted).ConfigureAwait(false);
        await TestZpaqSeatbeltPostStartCleanupAsync().ConfigureAwait(false);
        await TestZpaqInheritedDescriptorGuardAsync().ConfigureAwait(false);
        await TestZpaqLeadingDashFileListAsync().ConfigureAwait(false);
    }

    private static void TestZpaqSeatbeltProfileMatrix()
    {
        foreach (MacZpaqSandboxOperation operation in Enum.GetValues<MacZpaqSandboxOperation>())
        {
            string profile = MacZpaqSeatbelt.BuildProfileForTests(operation);
            Require(profile.StartsWith("(version 1)\n(deny default)\n", StringComparison.Ordinal),
                $"{operation} lost default-deny Seatbelt semantics.");
            Require(profile.Contains("(deny network*)", StringComparison.Ordinal)
                && profile.Contains("(deny process-fork)", StringComparison.Ordinal),
                $"{operation} lost network or child-process denial.");
            Require(profile.Contains(
                    "(allow process-exec (literal (param \"EXECUTABLE\")))",
                    StringComparison.Ordinal)
                && !profile.Contains("(allow process-exec)", StringComparison.Ordinal)
                && !profile.Contains("(allow process-exec (subpath", StringComparison.Ordinal),
                $"{operation} no longer binds process-exec to the exact ZPAQ executable.");
            Require(!profile.Contains("mach-", StringComparison.Ordinal)
                && !profile.Contains("ipc-posix-shm*", StringComparison.Ordinal)
                && !profile.Contains("regex", StringComparison.OrdinalIgnoreCase)
                && !profile.Contains("(subpath \"/private/tmp\")", StringComparison.Ordinal)
                && !profile.Contains("(subpath (param \"HOME", StringComparison.Ordinal),
                $"{operation} contains a broad IPC, HOME, or global-temporary grant.");

            bool verified = operation is MacZpaqSandboxOperation.ExtractVerified
                or MacZpaqSandboxOperation.ListVerified;
            Require(profile.Contains("ipc-posix-name (param \"VERIFIED_SHM_NAME\")", StringComparison.Ordinal) == verified,
                $"{operation} has the wrong exact POSIX-SHM capability.");
            Require(profile.Contains("INPUT_ROOT", StringComparison.Ordinal)
                    == (operation is MacZpaqSandboxOperation.AddFile or MacZpaqSandboxOperation.AddStreaming),
                $"{operation} has the wrong input-root capability.");
            Require(profile.Contains("OUTPUT_FILE", StringComparison.Ordinal)
                    == (operation == MacZpaqSandboxOperation.AddFile),
                $"{operation} has the wrong output-file capability.");
            Require(profile.Contains("OUTPUT_ROOT", StringComparison.Ordinal)
                    == (operation is MacZpaqSandboxOperation.ExtractVerified or MacZpaqSandboxOperation.ExtractStreaming),
                $"{operation} has the wrong extraction-root capability.");
        }
    }

    private static async Task TestZpaqSeatbeltInitializationCleanupAsync(TrustedNativeFileLease trusted)
    {
        string root = CreateTempRoot("keep-vault-zpaq-seatbelt-init-");
        try
        {
            foreach (string stage in ZpaqPolicyInitializationStages)
            {
                HashSet<string> before = EnumerateZpaqPolicyRoots();
                MacZpaqSeatbelt.InitializationHookForTests = current =>
                {
                    if (string.Equals(current, stage, StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException("Injected Seatbelt initialization failure.");
                    }
                };
                try
                {
                    await RequireThrowsAsync<Exception>(
                        async () =>
                        {
                            using MacZpaqSeatbelt ignored = await MacZpaqSeatbelt.CreateForZpaqAsync(
                                trusted,
                                ["--pipe", "list", "-", "-threads", "1"],
                                root,
                                CancellationToken.None).ConfigureAwait(false);
                        },
                        $"Seatbelt initialization stage {stage} did not fail under injection.").ConfigureAwait(false);
                }
                finally
                {
                    MacZpaqSeatbelt.InitializationHookForTests = null;
                }
                Require(before.SetEquals(EnumerateZpaqPolicyRoots()),
                    $"Seatbelt initialization stage {stage} leaked a private policy root.");
            }
        }
        finally
        {
            MacZpaqSeatbelt.InitializationHookForTests = null;
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task TestZpaqSeatbeltOperationCanariesAsync(TrustedNativeFileLease trusted)
    {
        string root = CreateTempRoot("keep-vault-zpaq-seatbelt-matrix-");
        string source = Path.Combine(root, "source.bin");
        await File.WriteAllBytesAsync(source, RandomNumberGenerator.GetBytes(4096)).ConfigureAwait(false);
        string extractRoot = Path.Combine(root, "extract");
        Directory.CreateDirectory(extractRoot);
        string output = Path.Combine(root, "new.zpaq");
        IReadOnlyList<(string Name, string[] Arguments, string WorkingDirectory)> matrix =
        [
            ("add-file", ["add", output, "-m0", "-threads", "1", "--", "source.bin"], root),
            ("add-stream", ["--pipe", "add", "-", "-method", "s0", "-threads", "1", "--", "source.bin"], root),
            ("extract-verified", ["--verified-stdin", "extract", "-", "-threads", "1"], extractRoot),
            ("extract-stream", ["--pipe", "extract", "-", "-threads", "1"], extractRoot),
            ("list-verified", ["--verified-stdin", "list", "-", "-threads", "1"], root),
            ("list-stream", ["--pipe", "list", "-", "-threads", "1"], root),
        ];
        HashSet<string> before = EnumerateZpaqPolicyRoots();
        try
        {
            foreach ((string name, string[] arguments, string workingDirectory) in matrix)
            {
                using MacZpaqSeatbelt policy = await MacZpaqSeatbelt.CreateForZpaqAsync(
                    trusted,
                    arguments,
                    workingDirectory,
                    CancellationToken.None).ConfigureAwait(false);
                policy.RequireValid();
                policy.RequireNoSharedMemoryResidue();
                Require(!File.Exists(output), $"The {name} policy canary created the production output.");
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
        Require(before.SetEquals(EnumerateZpaqPolicyRoots()),
            "Operation-specific Seatbelt canaries leaked a private policy root.");
    }

    private static async Task TestZpaqSeatbeltPostStartCleanupAsync()
    {
        foreach (string stage in new[] { "canary-policy", "canary-exec" })
        {
            int processId = 0;
            MacZpaqSeatbelt.PostStartValidationHookForTests = (current, pid) =>
            {
                if (string.Equals(current, stage, StringComparison.Ordinal))
                {
                    processId = pid;
                    throw new IOException("Injected post-start Seatbelt identity failure.");
                }
            };
            try
            {
                using FileStream stream = MacSafeFileSystem.OpenReadNoSymlinks(MacZpaqRootAnchor.ExecutablePath);
                using var lease = new TrustedNativeFileLease(MacZpaqRootAnchor.ExecutablePath, stream);
                await RequireThrowsAsync<Exception>(
                    async () =>
                    {
                        using MacZpaqSeatbelt ignored = await MacZpaqSeatbelt.CreateForZpaqAsync(
                            lease,
                            ["--pipe", "list", "-", "-threads", "1"],
                            Environment.CurrentDirectory,
                            CancellationToken.None).ConfigureAwait(false);
                    },
                    $"The {stage} post-start fault was accepted.").ConfigureAwait(false);
            }
            finally
            {
                MacZpaqSeatbelt.PostStartValidationHookForTests = null;
            }
            await RequireProcessExitedAsync(processId, stage).ConfigureAwait(false);
        }

        await RequireRunnerPostStartCleanupAsync("text", async () =>
        {
            _ = await ZpaqService.RunTextProcessAsync(
                "/bin/sleep",
                ["30"],
                Environment.CurrentDirectory,
                null,
                CancellationToken.None).ConfigureAwait(false);
        }).ConfigureAwait(false);

        string root = CreateTempRoot("keep-vault-zpaq-seatbelt-start-");
        try
        {
            string source = Path.Combine(root, "source.bin");
            await File.WriteAllBytesAsync(source, RandomNumberGenerator.GetBytes(2 * 1024 * 1024)).ConfigureAwait(false);
            await RequireRunnerPostStartCleanupAsync("stdout", async () =>
            {
                _ = await new ZpaqService().AddStreamingAsync(
                    [source],
                    0,
                    (stream, token) => stream.CopyToAsync(Stream.Null, token),
                    null,
                    CancellationToken.None).ConfigureAwait(false);
            }).ConfigureAwait(false);
            await RequireRunnerPostStartCleanupAsync("stdin", async () =>
            {
                _ = await new ZpaqService().ListStreamingAsync(
                    async (stream, token) =>
                    {
                        await Task.Delay(TimeSpan.FromSeconds(30), token).ConfigureAwait(false);
                        await stream.WriteAsync(new byte[] { 0 }, token).ConfigureAwait(false);
                    },
                    null,
                    CancellationToken.None).ConfigureAwait(false);
            }).ConfigureAwait(false);
        }
        finally
        {
            MacZpaqSeatbelt.PostStartValidationHookForTests = null;
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task RequireRunnerPostStartCleanupAsync(string stage, Func<Task> operation)
    {
        int processId = 0;
        MacZpaqSeatbelt.PostStartValidationHookForTests = (current, pid) =>
        {
            if (string.Equals(current, stage, StringComparison.Ordinal))
            {
                processId = pid;
                throw new IOException("Injected post-start runner failure.");
            }
        };
        try
        {
            await RequireThrowsAsync<Exception>(operation, $"The {stage} post-start runner fault was accepted.")
                .ConfigureAwait(false);
        }
        finally
        {
            MacZpaqSeatbelt.PostStartValidationHookForTests = null;
        }
        await RequireProcessExitedAsync(processId, stage).ConfigureAwait(false);
    }

    private static async Task RequireProcessExitedAsync(int processId, string stage)
    {
        Require(processId > 0, $"The {stage} hook did not observe a started child process.");
        for (int attempt = 0; attempt < 80; attempt++)
        {
            try
            {
                using Process process = Process.GetProcessById(processId);
                if (process.HasExited)
                {
                    return;
                }
            }
            catch (ArgumentException)
            {
                return;
            }
            await Task.Delay(25).ConfigureAwait(false);
        }
        throw new InvalidOperationException($"The {stage} post-start failure left child PID {processId} running.");
    }

    private static async Task TestZpaqInheritedDescriptorGuardAsync()
    {
        string source = Path.Combine(AppContext.BaseDirectory, "ZpaqInheritedFdHarness.c");
        Require(File.Exists(source), "The native inherited-descriptor harness source is absent.");
        string root = CreateTempRoot("keep-vault-zpaq-fd-harness-");
        try
        {
            string harness = Path.Combine(root, "fd-harness");
            ProcessResult build = await RunProcessAsync(
                "/usr/bin/xcrun",
                ["--sdk", "macosx", "clang", "-std=c17", "-Wall", "-Wextra", "-Werror", "-O2", source, "-o", harness],
                root).ConfigureAwait(false);
            Require(build.Succeeded, $"The inherited-descriptor harness did not compile: {build.StandardError}");
            ProcessResult run = await RunProcessAsync(
                harness,
                ["--zpaq", MacZpaqRootAnchor.ExecutablePath],
                root).ConfigureAwait(false);
            Require(run.Succeeded
                    && run.StandardOutput.Length == 0
                    && run.StandardError.Trim().Equals("keepvault_inherited_fd_guard=verified", StringComparison.Ordinal),
                $"The native ZPAQ entry guard did not close a descriptor explicitly mapped by posix_spawn: {run.StandardError}");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task TestZpaqLeadingDashFileListAsync()
    {
        string root = CreateTempRoot("keep-vault-zpaq-dash-list-");
        try
        {
            string input = Path.Combine(root, "input");
            Directory.CreateDirectory(input);
            string[] names = ["-key", "-method", "-to", "--keepvault-sandbox-canary"];
            foreach (string name in names)
            {
                await File.WriteAllTextAsync(Path.Combine(input, name), "v12:" + name).ConfigureAwait(false);
            }
            string archive = Path.Combine(root, "dash-names.zpaq");
            ProcessResult add = await new ZpaqService().AddAsync(
                archive,
                names.Select(name => Path.Combine(input, name)).ToArray(),
                0,
                null,
                CancellationToken.None).ConfigureAwait(false);
            Require(add.Succeeded, $"Explicit leading-dash ZPAQ file-list creation failed: {add.StandardError}");
            string output = Path.Combine(root, "output");
            ProcessResult extract = await new ZpaqService().ExtractAsync(
                archive,
                output,
                null,
                CancellationToken.None).ConfigureAwait(false);
            Require(extract.Succeeded, $"Leading-dash ZPAQ extraction failed: {extract.StandardError}");
            foreach (string name in names)
            {
                string extracted = Path.Combine(output, name);
                Require(File.Exists(extracted)
                        && string.Equals(await File.ReadAllTextAsync(extracted).ConfigureAwait(false), "v12:" + name, StringComparison.Ordinal),
                    $"The explicit ZPAQ file list lost or reinterpreted {name}.");
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static HashSet<string> EnumerateZpaqPolicyRoots() =>
        Directory.EnumerateDirectories("/private/tmp", "keep-vault-zpaq-sandbox-*", SearchOption.TopDirectoryOnly)
            .ToHashSet(StringComparer.Ordinal);
}
