using System.Text.Json;
using System.Text.RegularExpressions;
using KalynaArchiver.Services;

/// <summary>
/// Two cheap source-level gates that keep the code and the normative
/// specification from drifting apart.
/// </summary>
/// <remarks>
/// Both run in well under a second, so they can gate a documentation-only
/// change without a two-gibibyte Argon2id round. They exist because the two
/// failures they catch are the ones nothing else notices: a legacy construction
/// creeping back into production source, and a README that describes a
/// different key derivation than the one the code runs. A later reader who
/// trusts the wrong one of those two will "fix" the working side.
/// </remarks>
internal static class SpecLintTests
{
    private sealed record ForbiddenPattern(string Pattern, string Why);
    private sealed record LockFileExpectation(
        string Project,
        string ProjectFileName,
        string BaseTarget,
        string[] RuntimeIdentifiers,
        string? IlCompilerVersion,
        string? IlLinkVersion,
        string LockFileName = "packages.lock.json");

    private const string NativeAotPackVersion = "10.0.11";

    /// <summary>
    /// Constructions that must not exist in shipping source at all.
    /// </summary>
    private static readonly ForbiddenPattern[] ForbiddenInProductionSource =
    [
        new(@"Kalyna-ZPAQ/v10/", "a v10 cryptographic domain"),
        new(@"Kalyna-ZPAQ/v9/", "a v9 cryptographic domain"),
        new(@"Kalyna-ZPAQ/KPAR2/v3/", "a KPAR2 v3 domain"),
        new(@"keepvault_argon2id_v10", "the v10 native Argon2id export"),
        new(@"KZPAQ_ARGON2_V10_", "v10 native Argon2id constants"),
        new(@"\bV10MasterKdf\b", "the removed v10 master KDF"),
        new(@"\bV10KeyDerivation\b", "the removed v10 key derivation"),
        new(@"\bLegacyVersion\b", "a legacy format-version constant"),
        new(@"\bLegacyRecoveryAlgorithm\b", "a legacy KPAR2 algorithm constant"),
        new(@"Version\s*==\s*10\b", "an equality test against container version 10"),
        new(@"Version\s*!=\s*10\b", "an inequality test against container version 10"),
        new(@"version\s*:\s*10\b", "a call that selects derivation version 10"),
    ];

    private static readonly ForbiddenPattern[] ForbiddenInMacProductionSource =
    [
        new(@"KZPAQ1\\0", "the removed v11 container magic"),
        new(@"Kalyna-ZPAQ/v11/", "a v11 cryptographic domain"),
        new(@"keepvault_argon2id_v11", "the removed v11 native Argon2id export"),
        new(@"KZPAQ_ARGON2_V11_", "removed v11 native Argon2id constants"),
        new(@"\bV11MasterKdf\b", "the removed v11 master KDF"),
        new(@"Version\s*==\s*11\b", "an equality test against container version 11"),
        new(@"Version\s*!=\s*11\b", "an inequality test against container version 11"),
        new(@"version\s*:\s*11\b", "a call that selects derivation version 11"),
    ];

    internal static Task NoLegacyLintAsync()
    {
        string root = RepositoryLayout.FindRepositoryRoot();
        IReadOnlyList<string> sources = RepositoryLayout.EnumerateProductionSources(root);
        Require(sources.Count > 50, $"The production source sweep found only {sources.Count} files; the layout probably moved.");

        var swept = new HashSet<string>(sources.Select(Path.GetFullPath), StringComparer.OrdinalIgnoreCase);
        string nativeRoot = Path.Combine(root, "native");
        string[] nativeWrappers =
        [
            .. Directory.EnumerateFiles(nativeRoot)
                .Where(path => Path.GetExtension(path) is ".c" or ".cc" or ".cpp" or ".cxx" or ".h" or ".hh" or ".hpp" or ".hxx")
                .Select(Path.GetFullPath),
        ];
        Require(nativeWrappers.Length > 5, "The native-wrapper inventory is unexpectedly small.");
        string[] missedNativeWrappers = [.. nativeWrappers.Where(path => !swept.Contains(path))];
        Require(
            missedNativeWrappers.Length == 0,
            "The production source sweep misses native wrapper(s): "
            + string.Join(", ", missedNativeWrappers.Select(path => Path.GetRelativePath(root, path))));
        Require(
            nativeWrappers.Any(path => Path.GetExtension(path).Equals(".cpp", StringComparison.OrdinalIgnoreCase))
                && nativeWrappers.Any(path => Path.GetExtension(path).Equals(".hpp", StringComparison.OrdinalIgnoreCase)),
            "The NoLegacy self-test did not observe the active C++ and C++-header file types.");

        string[] requiredBuildSources =
        [
            Path.Combine(root, "tools", "Build-Native.cmd"),
            Path.Combine(root, "tools", "Build-Native-macOS.sh"),
            Path.Combine(root, "Directory.Build.props"),
        ];
        Require(
            requiredBuildSources.All(path => swept.Contains(Path.GetFullPath(path))),
            "The production source sweep misses a native build script or MSBuild properties file.");

        string[] requiredTrustAndVendorSources =
        [
            Path.Combine(root, "external", "cryptopp", "kalyna.cpp"),
            Path.Combine(root, "external", "cryptopp", "rijndael_simd.cpp"),
            Path.Combine(root, "KeepVaultMac", "Packaging", "KeepVault.entitlements"),
            Path.Combine(root, "QrCodeScanner", "Packaging", "QrScanner.entitlements"),
            Path.Combine(root, "KeepVaultMac", "packages.lock.json"),
            Path.Combine(root, "QrCodeScannerWindows", "packages.lock.json"),
        ];
        Require(
            requiredTrustAndVendorSources.All(path => swept.Contains(Path.GetFullPath(path))),
            "The production sweep misses a vendored cryptographic source, entitlement, or lock file.");

        var violations = new List<string>();
        foreach (string file in sources)
        {
            string text = RepositoryLayout.ReadText(file);
            string relative = Path.GetRelativePath(root, file);
            bool isMacProduction = relative.StartsWith($"KalynaArchiver{Path.DirectorySeparatorChar}Services{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                || relative.StartsWith($"KeepVaultMac{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                || relative.StartsWith($"KeepVaultMac.ReleaseVerifier{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                || relative.StartsWith($"QrCodeScanner{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                || relative.StartsWith($"native{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                || (relative.StartsWith($"tools{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                    && (relative.Contains("macOS", StringComparison.Ordinal)
                        || Path.GetExtension(relative) is ".c" or ".cc" or ".cpp" or ".h"));
            IEnumerable<ForbiddenPattern> forbiddenPatterns = isMacProduction
                ? ForbiddenInProductionSource.Concat(ForbiddenInMacProductionSource)
                : ForbiddenInProductionSource;
            foreach (ForbiddenPattern forbidden in forbiddenPatterns)
            {
                foreach (Match match in Regex.Matches(text, forbidden.Pattern, RegexOptions.None, TimeSpan.FromSeconds(5)))
                {
                    int line = text.Take(match.Index).Count(c => c == '\n') + 1;
                    violations.Add($"{relative}:{line} contains {forbidden.Why} ({match.Value})");
                }
            }
        }

        Require(
            violations.Count == 0,
            "Production source still carries legacy constructions:\n  " + string.Join("\n  ", violations));

        // The role context has to serialize the current schedule version. The
        // byte-exact KAT proves the value; this proves nobody reintroduced a
        // second, older constant to choose from.
        Require(SuiteKeySchedule.ContextVersion == 12, "The role-key schedule context version is not 12.");
        Require(ContainerKeyDerivation.ContainerVersion == 12, "The container key derivation is not pinned to v12.");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Every checked-in lock file must describe exactly the runtime the project
    /// it belongs to is built for.
    /// </summary>
    /// <remarks>
    /// The repository restores in locked mode. NuGet compares the project's
    /// runtime identifiers against the ones recorded in the lock file as a set,
    /// so a target left behind by a restore on a different operating system is
    /// not inert: it makes the set differ on the machine the project is
    /// actually built on and fails the restore with NU1004 before a single file
    /// is compiled. That is what a stale <c>osx-arm64</c> target did to both
    /// Windows projects - the Windows application could not be restored on
    /// Windows at all, while every macOS build stayed green and never saw it.
    /// A lock file is not reachable from any code path, so nothing but a check
    /// like this one notices.
    /// </remarks>
    internal static Task LockFileRuntimesAsync()
    {
        string root = RepositoryLayout.FindRepositoryRoot();
        // These are the complete target graphs, not merely an allowlist. A
        // missing RID is just as fatal to locked restore/release coverage as a
        // foreign RID, and the NativeAOT packs must remain pinned as direct
        // graph inputs for the two AOT deliverables.
        LockFileExpectation[] projects =
        [
            new("KalynaArchiver", "KalynaArchiver.csproj", "net9.0-windows7.0", ["win-x64"], null, "9.0.19"),
            new("KalynaArchiver.Tests", "KalynaArchiver.Tests.csproj", "net9.0-windows7.0", ["win-x64"], null, "9.0.19"),
            new("KalynaArchiver.Signing", "KalynaArchiver.Signing.csproj", "net9.0-windows7.0", ["win-x64"], null, "9.0.19"),
            new("KalynaReleaseVerifier", "KalynaReleaseVerifier.csproj", "net9.0-windows7.0", ["win-x64"], null, "9.0.19"),
            new("KalynaSigningTool", "KalynaSigningTool.csproj", "net9.0-windows7.0", ["win-x64"], null, "9.0.19"),
            new("KeepVaultMac", "KeepVaultMac.csproj", "net10.0", ["osx-arm64", "osx-x64"], NativeAotPackVersion, NativeAotPackVersion),
            new("KeepVaultMac.Tests", "KeepVaultMac.Tests.csproj", "net10.0", ["osx-arm64"], null, null),
            new("KeepVaultMac.ReleaseVerifier", "KeepVaultMac.ReleaseVerifier.csproj", "net10.0", ["osx-arm64", "osx-x64"], NativeAotPackVersion, NativeAotPackVersion),
            new("KeepVaultMac/Packaging/HybridSigner", "KeepVaultMac.HybridSigner.csproj", "net10.0", ["osx-arm64"], null, null),
            new("QrCodeScannerWindows", "QrScanner.csproj", "net9.0-windows10.0.19041", ["win-x64"], null, "9.0.19"),
            new("QrCodeScannerWindows", "QrScanner.Tests.csproj", "net9.0-windows10.0.19041", ["win-x64"], null, null, "packages.tests.lock.json"),
        ];

        var violations = new List<string>();
        var expectedLockFiles = new HashSet<string>(
            projects.Select(project =>
                Path.Combine(project.Project, project.LockFileName).Replace('\\', '/')),
            StringComparer.Ordinal);
        string[] actualLockFiles =
        [
            .. Directory.EnumerateFiles(root, "packages*.lock.json", SearchOption.AllDirectories)
                .Select(path => Path.GetRelativePath(root, path).Replace('\\', '/'))
                .Where(relative => !relative.Split('/').Any(segment =>
                    segment is ".git" or ".claude" or "bin" or "obj" or "obj_alt" or "build-obj")),
        ];
        string[] uncheckedLocks =
        [
            .. actualLockFiles.Where(path => !expectedLockFiles.Contains(path)).Order(StringComparer.Ordinal),
        ];
        if (uncheckedLocks.Length > 0)
        {
            violations.Add("Lock graph has unchecked lock file(s): " + string.Join(", ", uncheckedLocks) + ".");
        }

        var expectedProjectFiles = new HashSet<string>(
            projects.Select(project =>
                Path.Combine(project.Project, project.ProjectFileName).Replace('\\', '/')),
            StringComparer.Ordinal);
        string[] uncheckedProjects =
        [
            .. Directory.EnumerateFiles(root, "*.csproj", SearchOption.AllDirectories)
                .Select(path => Path.GetRelativePath(root, path).Replace('\\', '/'))
                .Where(relative => !relative.Split('/').Any(segment =>
                    segment is ".git" or ".claude" or "bin" or "obj" or "obj_alt" or "build-obj"))
                .Where(path => !expectedProjectFiles.Contains(path))
                .Order(StringComparer.Ordinal),
        ];
        if (uncheckedProjects.Length > 0)
        {
            violations.Add("Lock graph has unchecked project(s): " + string.Join(", ", uncheckedProjects) + ".");
        }

        foreach (LockFileExpectation project in projects)
        {
            string projectFile = Path.Combine(root, project.Project, project.ProjectFileName);
            if (!File.Exists(projectFile))
            {
                violations.Add($"{project.Project}/{project.ProjectFileName} is missing.");
            }

            string lockFile = Path.Combine(root, project.Project, project.LockFileName);
            if (!File.Exists(lockFile))
            {
                violations.Add($"{project.Project}/{project.LockFileName} is missing.");
                continue;
            }

            try
            {
                using JsonDocument document = JsonDocument.Parse(RepositoryLayout.ReadText(lockFile));
                ValidateLockFileDocument(project, document.RootElement, violations);
            }
            catch (JsonException ex)
            {
                violations.Add($"{project.Project}/{project.LockFileName} is malformed JSON: {ex.Message}");
            }
        }

        (string Path, string RollForward)[] globalJsonFiles =
        [
            ("global.json", "disable"),
            ("KeepVaultMac/global.json", "disable"),
            ("KeepVaultMac.Tests/global.json", "disable"),
            ("KeepVaultMac.ReleaseVerifier/global.json", "disable"),
        ];
        foreach ((string relativePath, string expectedRollForward) in globalJsonFiles)
        {
            string path = Path.Combine(root, relativePath);
            if (!File.Exists(path))
            {
                violations.Add($"{relativePath} is missing.");
                continue;
            }

            try
            {
                using JsonDocument document = JsonDocument.Parse(RepositoryLayout.ReadText(path));
                JsonElement sdk = document.RootElement.GetProperty("sdk");
                if (sdk.GetProperty("version").GetString() != "10.0.400"
                    || sdk.GetProperty("rollForward").GetString() != expectedRollForward
                    || sdk.GetProperty("allowPrerelease").ValueKind != JsonValueKind.False)
                {
                    violations.Add(
                        $"{relativePath} must preserve .NET SDK 10.0.400 with "
                        + $"{expectedRollForward} and no prereleases.");
                }
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
            {
                violations.Add($"{relativePath} has no valid pinned SDK contract: {ex.Message}");
            }
        }

        RunLockFileValidatorSelfTests(
            projects.First(project => project.IlCompilerVersion is not null),
            projects.Single(project => project.Project == "KeepVaultMac.Tests"));
        Require(violations.Count == 0, "Lock files do not match their build platform:\n  " + string.Join("\n  ", violations));
        return Task.CompletedTask;
    }

    private static void ValidateLockFileDocument(
        LockFileExpectation expectation,
        JsonElement root,
        List<string> violations)
    {
        string name = expectation.Project + "/" + expectation.LockFileName;
        if (!root.TryGetProperty("version", out JsonElement version)
            || version.ValueKind != JsonValueKind.Number
            || !version.TryGetInt32(out int lockVersion)
            || lockVersion != 1)
        {
            violations.Add($"{name} must use NuGet lock schema version 1.");
        }

        if (!root.TryGetProperty("dependencies", out JsonElement dependencies)
            || dependencies.ValueKind != JsonValueKind.Object)
        {
            violations.Add($"{name} has no dependency target object.");
            return;
        }

        string[] expectedTargets =
        [
            expectation.BaseTarget,
            .. expectation.RuntimeIdentifiers.Select(runtime => $"{expectation.BaseTarget}/{runtime}"),
        ];
        string[] actualTargets = [.. dependencies.EnumerateObject().Select(target => target.Name)];
        foreach (JsonProperty target in dependencies.EnumerateObject())
        {
            if (target.Value.ValueKind != JsonValueKind.Object)
            {
                violations.Add($"{name} target {target.Name} is not a dependency object.");
            }
        }
        string[] missing = [.. expectedTargets.Except(actualTargets, StringComparer.Ordinal).Order(StringComparer.Ordinal)];
        string[] foreign = [.. actualTargets.Except(expectedTargets, StringComparer.Ordinal).Order(StringComparer.Ordinal)];
        if (missing.Length > 0)
        {
            violations.Add($"{name} is missing target(s): {string.Join(", ", missing)}.");
        }
        if (foreign.Length > 0)
        {
            violations.Add($"{name} carries foreign target(s): {string.Join(", ", foreign)}.");
        }

        (string Package, string? ExpectedVersion)[] toolPacks =
        [
            ("Microsoft.DotNet.ILCompiler", expectation.IlCompilerVersion),
            ("Microsoft.NET.ILLink.Tasks", expectation.IlLinkVersion),
        ];
        if (!dependencies.TryGetProperty(expectation.BaseTarget, out JsonElement baseTarget)
            || baseTarget.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach ((string package, string? expectedVersion) in toolPacks)
        {
            foreach (JsonProperty target in dependencies.EnumerateObject())
            {
                if (!string.Equals(target.Name, expectation.BaseTarget, StringComparison.Ordinal)
                    && target.Value.ValueKind == JsonValueKind.Object
                    && target.Value.TryGetProperty(package, out JsonElement ridEntry))
                {
                    // NuGet's lock writer repeats a NativeAOT SDK pack in each
                    // RID target when the project has more than one runtime
                    // identifier. Those entries are valid only when they are
                    // the exact same pinned direct pack as the base target.
                    // Managed-only projects may never carry an SDK tool pack.
                    bool validRidCopy = expectedVersion is not null
                        && ridEntry.ValueKind == JsonValueKind.Object
                        && ridEntry.TryGetProperty("type", out JsonElement ridType)
                        && ridType.ValueKind == JsonValueKind.String
                        && ridType.GetString() == "Direct"
                        && ridEntry.TryGetProperty("requested", out JsonElement ridRequested)
                        && ridRequested.ValueKind == JsonValueKind.String
                        && ridRequested.GetString() == $"[{expectedVersion}, )"
                        && ridEntry.TryGetProperty("resolved", out JsonElement ridResolved)
                        && ridResolved.ValueKind == JsonValueKind.String
                        && ridResolved.GetString() == expectedVersion;
                    if (!validRidCopy)
                    {
                        violations.Add($"{name} carries an invalid SDK tool pack {package} outside its base dependency target.");
                    }
                }
            }

            bool found = baseTarget.TryGetProperty(package, out JsonElement entry)
                && entry.ValueKind == JsonValueKind.Object;
            if (expectedVersion is null)
            {
                if (found)
                {
                    violations.Add($"{name} unexpectedly carries the direct SDK tool pack {package}.");
                }
                continue;
            }

            if (!found)
            {
                violations.Add($"{name} is missing the direct SDK tool pack {package}.");
                continue;
            }

            string? type = entry.TryGetProperty("type", out JsonElement typeElement)
                && typeElement.ValueKind == JsonValueKind.String ? typeElement.GetString() : null;
            string? requested = entry.TryGetProperty("requested", out JsonElement requestedElement)
                && requestedElement.ValueKind == JsonValueKind.String ? requestedElement.GetString() : null;
            string? resolved = entry.TryGetProperty("resolved", out JsonElement resolvedElement)
                && resolvedElement.ValueKind == JsonValueKind.String ? resolvedElement.GetString() : null;
            if (type != "Direct"
                || requested != $"[{expectedVersion}, )"
                || resolved != expectedVersion)
            {
                violations.Add(
                    $"{name} must pin {package} directly to {expectedVersion}; "
                    + $"found type={type ?? "missing"}, requested={requested ?? "missing"}, resolved={resolved ?? "missing"}.");
            }
        }
    }

    private static void RunLockFileValidatorSelfTests(
        LockFileExpectation nativeAot,
        LockFileExpectation managed)
    {
        static List<string> ValidateSynthetic(
            LockFileExpectation expectation,
            bool includeAot,
            bool omitLastTarget = false,
            string? foreignTarget = null,
            bool omitCompiler = false,
            string? compilerVersion = null)
        {
            using JsonDocument document = CreateSyntheticLockFile(
                expectation,
                includeAot,
                omitLastTarget,
                foreignTarget,
                omitCompiler,
                compilerVersion);
            var found = new List<string>();
            ValidateLockFileDocument(expectation, document.RootElement, found);
            return found;
        }

        Require(ValidateSynthetic(nativeAot, includeAot: true).Count == 0, "The lock graph validator rejected a valid NativeAOT graph.");
        Require(ValidateSynthetic(managed, includeAot: false).Count == 0, "The lock graph validator rejected a valid managed graph.");
        Require(ValidateSynthetic(nativeAot, includeAot: true, omitLastTarget: true).Count > 0, "The lock graph validator accepted a missing RID target.");
        Require(ValidateSynthetic(nativeAot, includeAot: true, foreignTarget: "net10.0/linux-x64").Count > 0, "The lock graph validator accepted a foreign RID target.");
        Require(ValidateSynthetic(nativeAot, includeAot: true, omitCompiler: true).Count > 0, "The lock graph validator accepted a missing ILCompiler pack.");
        Require(ValidateSynthetic(nativeAot, includeAot: true, compilerVersion: "10.0.12").Count > 0, "The lock graph validator accepted an unpinned ILCompiler pack.");
        Require(ValidateSynthetic(managed, includeAot: true).Count > 0, "The lock graph validator accepted NativeAOT packs in a managed-only project.");
    }

    private static JsonDocument CreateSyntheticLockFile(
        LockFileExpectation expectation,
        bool includeAot,
        bool omitLastTarget,
        string? foreignTarget,
        bool omitCompiler,
        string? compilerVersion)
    {
        string[] targets =
        [
            expectation.BaseTarget,
            .. expectation.RuntimeIdentifiers.Select(runtime => $"{expectation.BaseTarget}/{runtime}"),
        ];
        if (omitLastTarget)
        {
            targets = targets[..^1];
        }

        var dependencies = targets.ToDictionary(
            target => target,
            _ => new Dictionary<string, object?>(StringComparer.Ordinal),
            StringComparer.Ordinal);
        if (foreignTarget is not null)
        {
            dependencies[foreignTarget] = new Dictionary<string, object?>(StringComparer.Ordinal);
        }
        if (includeAot)
        {
            string version = compilerVersion ?? NativeAotPackVersion;
            if (!omitCompiler)
            {
                dependencies[expectation.BaseTarget]["Microsoft.DotNet.ILCompiler"] = new
                {
                    type = "Direct",
                    requested = $"[{version}, )",
                    resolved = version,
                };
            }
            dependencies[expectation.BaseTarget]["Microsoft.NET.ILLink.Tasks"] = new
            {
                type = "Direct",
                requested = $"[{NativeAotPackVersion}, )",
                resolved = NativeAotPackVersion,
            };
        }

        return JsonDocument.Parse(JsonSerializer.Serialize(new { version = 1, dependencies }));
    }

    internal static Task SpecConsistencyAsync()
    {
        string root = RepositoryLayout.FindRepositoryRoot();
        string readme = RepositoryLayout.ReadText(Path.Combine(root, "README.md"));
        var missing = new List<string>();

        // The KDF identifiers the header actually carries. If the README names
        // a different mode, one of the two is wrong and only this test can say
        // which without running the whole KDF.
        void RequireInReadme(string needle, string what)
        {
            if (!readme.Contains(needle, StringComparison.Ordinal))
            {
                missing.Add($"{what}: expected \"{needle}\"");
            }
        }

        RequireInReadme(V12MasterKdf.KdfMode, "KDF mode");
        RequireInReadme(V12MasterKdf.KdfInputMode, "KDF input mode");
        RequireInReadme(V12MasterKdf.PasswordMode, "password mode");

        // The v12 factor split, stated the way the specification states it.
        RequireInReadme("A1 = A[0..64)", "factor A split");
        RequireInReadme("A2 = A[64..128)", "factor A split");
        RequireInReadme("B1 = B[0..64)", "factor B split");
        RequireInReadme("B2 = B[64..128)", "factor B split");
        RequireInReadme("LP(A1) || LP(B1)", "Q_S1 inputs");
        RequireInReadme("LP(A2) || LP(B2)", "Q_S2 inputs");
        RequireInReadme("key = A || B", "Skein credential key");

        // Cost parameters, as numbers rather than prose.
        RequireInReadme("1,048,576 to 2,097,136 KiB", "PMI-derived memory range");
        RequireInReadme("`t=4`, `p=4`", "Argon2id cost parameters");
        RequireInReadme("PIN of 6 to 16 digits", "PIN length policy");
        RequireInReadme("container format **v12**", "container version");
        RequireInReadme("Magic `KZPAQ2\\0`", "v12 container magic");

        string mainWindowSource = RepositoryLayout.ReadText(Path.Combine(root, "KeepVaultMac", "MainWindow.axaml.cs"));
        string programSource = RepositoryLayout.ReadText(Path.Combine(root, "KeepVaultMac", "Program.cs"));
        if (!mainWindowSource.Contains("ConfirmAsync(T(\"cupsSpoolWarning\"))", StringComparison.Ordinal))
        {
            missing.Add("physical key-sheet printing must confirm the CUPS spool warning");
        }
        if (!programSource.Contains("MacNativeAlert.ShowCritical", StringComparison.Ordinal)
            || !programSource.Contains("Environment.Exit(StartupConfigurationErrorExitCode)", StringComparison.Ordinal))
        {
            missing.Add("startup hardening failure must show the native alert and exit with EX_CONFIG");
        }

        Require(missing.Count == 0, "README no longer matches the normative specification:\n  " + string.Join("\n  ", missing));

        // Claims that must never come back in user-facing product
        // documentation. The Codex audit is a normative test plan and contains
        // forbidden legacy strings as search needles and negative examples; it
        // is deliberately not a product claim.
        const string AuditFileName = "KEEP_VAULT_V11_MACOS_CODEX_AUDIT.md";
        const string ReleaseFileName = "KEEP_VAULT_V12_MACOS_RELEASE.md";
        string docsDirectory = Path.Combine(root, "docs");
        string[] referenceDocuments =
        [
            .. Directory.EnumerateFiles(docsDirectory, "*.md")
                .Where(path => string.Equals(Path.GetFileName(path), AuditFileName, StringComparison.OrdinalIgnoreCase)),
        ];
        Require(referenceDocuments.Length == 1, "The historical Codex audit reference is missing or ambiguous.");
        Require(
            File.Exists(Path.Combine(docsDirectory, ReleaseFileName)),
            "The normative v12 macOS release contract is missing.");
        string[] docs =
        [
            Path.Combine(root, "README.md"),
            .. Directory.EnumerateFiles(docsDirectory, "*.md")
                .Where(path => !string.Equals(Path.GetFileName(path), AuditFileName, StringComparison.OrdinalIgnoreCase)),
        ];
        (string Pattern, string Why)[] forbidden =
        [
            (@"PIN\s*6\s*(-|–|to)\s*12", "a 6-12 PIN policy"),
            (@"512-bit (generated|password) factor", "512-bit factors"),
            (@"five entropy pools|six entropy pools", "a stale entropy-pool count"),
            (@"KPAR2[- ]v?3\b", "KPAR2 v3 support"),
            (@"DualArgon2id-SHA3\+Skein1024", "the pre-split KDF mode string"),
        ];
        var staleClaims = new List<string>();
        foreach (string doc in docs)
        {
            string text = RepositoryLayout.ReadText(doc);
            foreach ((string pattern, string why) in forbidden)
            {
                if (Regex.IsMatch(text, pattern, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5)))
                {
                    staleClaims.Add($"{Path.GetRelativePath(root, doc)} still claims {why}");
                }
            }
        }

        Require(staleClaims.Count == 0, "Documentation carries stale security claims:\n  " + string.Join("\n  ", staleClaims));
        return Task.CompletedTask;
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
