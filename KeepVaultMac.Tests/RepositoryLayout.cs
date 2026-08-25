using System.Text;

/// <summary>
/// Locates the checkout the test binary was built from.
/// </summary>
internal static class RepositoryLayout
{
    /// <summary>
    /// Walks up from the test binary until it finds the checkout root.
    /// </summary>
    /// <remarks>
    /// The marker has to be accepted as either a directory or a file. In a git
    /// worktree <c>.git</c> is a file pointing at the real git directory, so a
    /// directory-only check walks straight past the worktree and lands on
    /// whatever repository happens to contain it further up. Every test that
    /// reads repository files would then validate a different checkout than the
    /// one it just built and is about to ship, and would keep passing while
    /// doing it.
    /// </remarks>
    public static string FindRepositoryRoot()
    {
        for (string? path = AppContext.BaseDirectory; path is not null; path = Path.GetDirectoryName(path))
        {
            string marker = Path.Combine(path, ".git");
            if (Directory.Exists(marker) || File.Exists(marker))
            {
                return path;
            }
        }

        throw new DirectoryNotFoundException("The Keep Vault repository root could not be located.");
    }

    /// <summary>
    /// Every source file this build actually ships, excluding tests and
    /// vendored third-party trees.
    /// </summary>
    public static IReadOnlyList<string> EnumerateProductionSources(string repositoryRoot)
    {
        string[] roots =
        [
            Path.Combine(repositoryRoot, "KalynaArchiver"),
            Path.Combine(repositoryRoot, "KalynaArchiver.Signing"),
            Path.Combine(repositoryRoot, "KalynaSigningTool"),
            Path.Combine(repositoryRoot, "KalynaReleaseVerifier"),
            Path.Combine(repositoryRoot, "KeepVaultMac"),
            Path.Combine(repositoryRoot, "KeepVaultMac.ReleaseVerifier"),
            Path.Combine(repositoryRoot, "QrCodeScanner", "Sources"),
            Path.Combine(repositoryRoot, "QrCodeScanner", "tools"),
            Path.Combine(repositoryRoot, "QrCodeScannerWindows", "Sources"),
            Path.Combine(repositoryRoot, "QrCodeScannerWindows", "tools"),
            Path.Combine(repositoryRoot, "native"),
            Path.Combine(repositoryRoot, "tools"),
        ];

        string[] extensions =
        [
            ".cs", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
            ".m", ".mm", ".swift", ".xaml", ".axaml", ".ps1", ".fsx", ".sh",
            ".cmd", ".bat", ".props", ".targets", ".csproj",
        ];
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string root in roots)
        {
            if (!Directory.Exists(root))
            {
                continue;
            }

            foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                string relative = Path.GetRelativePath(repositoryRoot, file);
                // build-obj is this repository's intermediate directory, set by
                // Directory.Build.props. Leaving it in made the sweep read
                // generated sources - XAML code-behind, assembly attributes -
                // so the same commit linted a different file set before and
                // after a build.
                string[] generated =
                [
                    $"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}",
                    $"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}",
                    $"{Path.DirectorySeparatorChar}build-obj{Path.DirectorySeparatorChar}",
                    $"{Path.DirectorySeparatorChar}Native{Path.DirectorySeparatorChar}",
                ];
                if (generated.Any(fragment => relative.Contains(fragment, StringComparison.Ordinal)))
                {
                    continue;
                }

                if (extensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase))
                {
                    files.Add(file);
                }
            }
        }

        string[] additionalBuildSources =
        [
            Path.Combine(repositoryRoot, "Directory.Build.props"),
            Path.Combine(repositoryRoot, "QrCodeScannerWindows", "Directory.Build.props"),
            Path.Combine(repositoryRoot, "QrCodeScannerWindows", "QrScanner.csproj"),
        ];
        foreach (string buildSource in additionalBuildSources)
        {
            if (File.Exists(buildSource))
            {
                files.Add(buildSource);
            }
        }

        return [.. files.OrderBy(file => file, StringComparer.Ordinal)];
    }

    public static string ReadText(string path) => File.ReadAllText(path, Encoding.UTF8);
}
