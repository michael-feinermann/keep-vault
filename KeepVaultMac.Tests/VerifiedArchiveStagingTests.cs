using KalynaArchiver.Services;

internal static partial class MacComprehensiveTests
{
    private static async Task TestVerifiedArchiveStagingAsync()
    {
        string root = RepositoryLayout.FindRepositoryRoot();
        string temporary = CreateTempRoot("keep-vault-v12-vm-test-");
        try
        {
            string binary = Path.Combine(temporary, "verified-staging-test");
            ProcessResult build = await RunProcessAsync("/usr/bin/xcrun",
                ["clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-O2",
                    Path.Combine(root, "KeepVaultMac.Tests", "VerifiedArchiveStagingTests.cpp"), "-o", binary], root);
            Require(build.Succeeded, "The native verified-staging test did not compile: " + build.StandardError);
            ProcessResult run = await RunProcessAsync(binary, [], temporary);
            Require(run.Succeeded && run.StandardOutput.Contains("verified_staging_vm=pass checks=44", StringComparison.Ordinal),
                "The native verified-staging bounds/immutability test failed: " + run.StandardError);
        }
        finally
        {
            Directory.Delete(temporary, recursive: true);
        }
    }
}
