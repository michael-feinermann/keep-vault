using KalynaArchiver.Services;

internal static partial class MacComprehensiveTests
{
    private static async Task TestSkeinWordWipeAsync()
    {
        string root = RepositoryLayout.FindRepositoryRoot();
        string temporary = CreateTempRoot("keep-vault-skein-wipe-test-");
        try
        {
            foreach (string architecture in new[] { "arm64", "x86_64" })
            {
                string binary = Path.Combine(temporary, "skein-wipe-" + architecture);
                ProcessResult build = await RunProcessAsync("/usr/bin/xcrun",
                    ["clang", "-arch", architecture, "-O2", "-DNDEBUG",
                        "-fstack-protector-strong", "-fvisibility=hidden", "-fno-common",
                        "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                        Path.Combine(root, "KeepVaultMac.Tests", "SkeinWordWipeTests.c"),
                        Path.Combine(root, "external", "Skein-reference", "NIST", "CD", "Reference_Implementation", "skein.c"),
                        "-o", binary], root);
                Require(build.Succeeded, "The optimized Skein wipe test did not compile: " + build.StandardError);
                ProcessResult run = await RunProcessAsync("/usr/bin/arch", ["-" + architecture, binary], temporary);
                Require(run.Succeeded && run.StandardOutput.Contains(
                        "skein_word_wipe=complete_and_bounded cases=8", StringComparison.Ordinal),
                    "Skein wiping did not clear every selected word while preserving adjacent guards: " + run.StandardError);
            }
        }
        finally
        {
            Directory.Delete(temporary, recursive: true);
        }
    }
}
