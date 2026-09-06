using KalynaArchiver.Services;

internal static partial class MacComprehensiveTests
{
    private static async Task TestInstallerLockCleanupAsync()
    {
        string root = RepositoryLayout.FindRepositoryRoot();
        ProcessResult result = await RunProcessAsync("/usr/bin/python3",
            ["-I", Path.Combine(root, "tools", "Test-InstallerLockCleanup-macOS.py"),
                "--installer", Path.Combine(root, "tools", "Install-KeepVault-macOS.sh")], root);
        Require(result.Succeeded && result.StandardOutput.Contains(
                "installer_lock_cleanup_pty=pass cases=4", StringComparison.Ordinal),
            "Installer cleanup failed the terminal or object-identity regression: " + result.StandardError);
    }
}
