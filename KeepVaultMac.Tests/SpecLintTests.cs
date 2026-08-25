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

        var violations = new List<string>();
        foreach (string file in sources)
        {
            string text = RepositoryLayout.ReadText(file);
            foreach (ForbiddenPattern forbidden in ForbiddenInProductionSource)
            {
                foreach (Match match in Regex.Matches(text, forbidden.Pattern, RegexOptions.None, TimeSpan.FromSeconds(5)))
                {
                    int line = text.Take(match.Index).Count(c => c == '\n') + 1;
                    violations.Add($"{Path.GetRelativePath(root, file)}:{line} contains {forbidden.Why} ({match.Value})");
                }
            }
        }

        Require(
            violations.Count == 0,
            "Production source still carries legacy constructions:\n  " + string.Join("\n  ", violations));

        // The role context has to serialize the current schedule version. The
        // byte-exact KAT proves the value; this proves nobody reintroduced a
        // second, older constant to choose from.
        Require(SuiteKeySchedule.ContextVersion == 11, "The role-key schedule context version is not 11.");
        Require(ContainerKeyDerivation.ContainerVersion == 11, "The container key derivation is not pinned to v11.");
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
        // The runtimes each project legitimately declares. Anything else in
        // its lock file came from a restore on the wrong operating system.
        (string Project, string[] AllowedRuntimes)[] projects =
        [
            ("KalynaArchiver", ["win-x64"]),
            ("KalynaArchiver.Tests", ["win-x64"]),
            ("KalynaArchiver.Signing", ["win-x64"]),
            ("KeepVaultMac", ["osx-arm64", "osx-x64"]),
            ("KeepVaultMac.Tests", ["osx-arm64"]),
        ];

        var violations = new List<string>();
        foreach ((string project, string[] allowed) in projects)
        {
            string lockFile = Path.Combine(root, project, "packages.lock.json");
            if (!File.Exists(lockFile))
            {
                violations.Add($"{project}/packages.lock.json is missing.");
                continue;
            }

            using JsonDocument document = JsonDocument.Parse(RepositoryLayout.ReadText(lockFile));
            if (!document.RootElement.TryGetProperty("dependencies", out JsonElement dependencies))
            {
                violations.Add($"{project}/packages.lock.json has no dependency targets.");
                continue;
            }

            foreach (JsonProperty target in dependencies.EnumerateObject())
            {
                int separator = target.Name.IndexOf('/', StringComparison.Ordinal);
                if (separator < 0)
                {
                    continue;
                }

                string runtime = target.Name[(separator + 1)..];
                if (!allowed.Contains(runtime, StringComparer.Ordinal))
                {
                    violations.Add(
                        $"{project}/packages.lock.json carries the foreign runtime target \"{target.Name}\"; "
                        + $"the project declares {string.Join(", ", allowed)}, so a locked restore on its own "
                        + "platform fails with NU1004.");
                }
            }
        }

        Require(violations.Count == 0, "Lock files do not match their build platform:\n  " + string.Join("\n  ", violations));
        return Task.CompletedTask;
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

        RequireInReadme(V11MasterKdf.KdfMode, "KDF mode");
        RequireInReadme(V11MasterKdf.KdfInputMode, "KDF input mode");
        RequireInReadme(V11MasterKdf.PasswordMode, "password mode");

        // The v11 factor split, stated the way the specification states it.
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
        RequireInReadme("container format **v11**", "container version");

        Require(missing.Count == 0, "README no longer matches the normative specification:\n  " + string.Join("\n  ", missing));

        // Claims that must never come back, in any documentation file.
        string[] docs = [Path.Combine(root, "README.md"), .. Directory.EnumerateFiles(Path.Combine(root, "docs"), "*.md")];
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
