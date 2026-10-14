using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

internal static class GoldenVerifierTests
{
    internal static IReadOnlyList<TestCase> Tests =>
    [
        new("v13-golden-readonly", "independent verifier rejects missing, invalid and on-disk mutated fixtures without writing them", RunAsync, TestResource.Light, "Security"),
    ];
    private static async Task RunAsync()
    {
        string directory = Path.Combine(RepositoryLayout.FindRepositoryRoot(), "KeepVaultMac.Tests", "Fixtures", "V13Reference");
        string fixture = Path.Combine(directory, "pool_shuffle_rev9_public_vectors.json");
        byte[] before = SHA256.HashData(await File.ReadAllBytesAsync(fixture));
        var start = new ProcessStartInfo("/usr/bin/python3") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        start.ArgumentList.Add("-B");
        start.ArgumentList.Add(Path.Combine(directory, "verify_pool_shuffle_rev9.py"));
        start.ArgumentList.Add("--self-test");
        using Process process = Process.Start(start) ?? throw new IOException("Python test process did not start.");
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(), stderr = process.StandardError.ReadToEndAsync();
        using var harnessTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        try { await process.WaitForExitAsync(harnessTimeout.Token); }
        catch { if (!process.HasExited) process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); throw; }
        string output = await stdout, error = await stderr;
        if (process.ExitCode != 0) throw new Exception("Read-only golden verifier failed: " + error);
        using JsonDocument report = JsonDocument.Parse(output);
        if (report.RootElement.GetProperty("rejectedOnDiskFixtures").GetInt32() != 11
            || !report.RootElement.GetProperty("fixtureUnchanged").GetBoolean()
            || !SHA256.HashData(await File.ReadAllBytesAsync(fixture)).AsSpan().SequenceEqual(before))
            throw new Exception("Golden verifier failure paths changed their input or accepted a malformed fixture.");
        start.ArgumentList.Clear();
        start.ArgumentList.Add("-B");
        start.ArgumentList.Add(Path.Combine(directory, "verify_reference_set_rev11.py"));
        using Process referenceSet = Process.Start(start) ?? throw new IOException("Reference-set verifier did not start.");
        Task<string> setOutput = referenceSet.StandardOutput.ReadToEndAsync(), setError = referenceSet.StandardError.ReadToEndAsync();
        try { await referenceSet.WaitForExitAsync(harnessTimeout.Token); }
        catch { if (!referenceSet.HasExited) referenceSet.Kill(entireProcessTree: true); await referenceSet.WaitForExitAsync(); throw; }
        if (referenceSet.ExitCode != 0) throw new Exception("Reference-set verifier failed: " + await setError);
        using JsonDocument setReport = JsonDocument.Parse(await setOutput);
        if (!setReport.RootElement.GetProperty("fixturesUnchanged").GetBoolean()
            || setReport.RootElement.GetProperty("rejectedOnDiskMutations").GetArrayLength() != 14)
            throw new Exception("Reference-set verifier did not enforce all frozen factor, nonce and AAD values.");
    }
}
