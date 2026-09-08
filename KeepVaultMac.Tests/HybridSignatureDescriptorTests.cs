using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using KalynaArchiver.Services;
using KalynaArchiver.Signing;

internal static partial class MacComprehensiveTests
{
    private static void TestHeldHybridSignatureBytes(string signedTarget, HybridSignaturePolicy policy)
    {
        string root = CreateTempRoot("keep-vault-hybrid-held-");
        string sidecarPath = Path.Combine(root, "held.khsig");
        byte[] original = File.ReadAllBytes(IntegrityService.ResolveSidecarBasePath(signedTarget) + ".khsig");
        try
        {
            File.WriteAllBytes(sidecarPath, original);
            File.SetUnixFileMode(sidecarPath, UnixFileMode.None);
            var chmod = new ProcessStartInfo("/bin/chmod") { UseShellExecute = false };
            chmod.ArgumentList.Add("+a");
            chmod.ArgumentList.Add("everyone allow read,readattr,readextattr,readsecurity");
            chmod.ArgumentList.Add(sidecarPath);
            using (Process process = Process.Start(chmod) ?? throw new IOException("Cannot create the private read-only ACL fixture."))
            {
                process.WaitForExit();
                Require(process.ExitCode == 0, "Cannot create the private read-only ACL fixture.");
            }

            using FileDigest digest = HybridSignatureService.ComputeFileDigest(signedTarget);
            using MacBoundFile held = MacBoundFile.Open(sidecarPath, 65_536);
            // fdescfs does not preserve the pathname's ACL access. This fixture
            // reproduces the root-owned-package failure without administrator
            // privileges: ordinary pathname/held-descriptor reads work, while
            // reopening the same descriptor as /dev/fd/N is denied.
            string descriptorPath = "/dev/fd/" + held.Stream.SafeFileHandle.DangerousGetHandle().ToInt64();
            RequireThrows<UnauthorizedAccessException>(() => File.OpenRead(descriptorPath).Dispose(),
                "The mode-000 ACL fixture unexpectedly allowed a /dev/fd reopen.");
            RequireThrows<InvalidDataException>(() => held.ReadAll(original.Length - 1),
                "The held sidecar reader ignored its explicit byte limit.");
            byte[] encoded = held.ReadAll(65_536);
            try
            {
                Require(encoded.AsSpan().SequenceEqual(original), "The held descriptor changed the sidecar bytes.");
                HybridSignatureVerificationResult Verify(ReadOnlySpan<byte> candidate) =>
                    HybridSignatureService.VerifyDigest(digest.Length, digest.Sha512, candidate, policy);
                HybridSignatureVerificationResult intact = Verify(encoded);
                Require(intact.IsTrusted && intact.RsaPssValid && intact.Mldsa87Valid,
                    "A valid ACL-readable held sidecar failed both signature algorithms.");

                const int lengthsOffset = 8 + sizeof(int) + sizeof(long) + 64;
                int rsaOffset = checked(lengthsOffset + 3 * sizeof(int)
                    + BinaryPrimitives.ReadInt32LittleEndian(encoded.AsSpan(lengthsOffset)));
                encoded[rsaOffset] ^= 1;
                HybridSignatureVerificationResult badRsa = Verify(encoded);
                Require(!badRsa.IsTrusted && !badRsa.RsaPssValid && badRsa.Mldsa87Valid,
                    "The byte API did not independently reject a changed RSA-PSS signature.");
                encoded[rsaOffset] ^= 1;
                encoded[^1] ^= 1;
                HybridSignatureVerificationResult badMldsa = Verify(encoded);
                Require(!badMldsa.IsTrusted && badMldsa.RsaPssValid && !badMldsa.Mldsa87Valid,
                    "The byte API did not independently reject a changed ML-DSA signature.");
                encoded[^1] ^= 1;

                Require(!Verify(ReadOnlySpan<byte>.Empty).IsTrusted, "Empty encoded signature was accepted.");
                Require(!Verify(encoded.AsSpan(0, encoded.Length - 1)).IsTrusted, "Truncated encoded signature was accepted.");
                Require(!Verify([.. encoded, 0]).IsTrusted, "Encoded signature trailing data was accepted.");
                Require(!Verify(new byte[65_537]).IsTrusted, "Oversized encoded signature was accepted.");
                Require(!HybridSignatureService.VerifyDigest(digest.Length + 1, digest.Sha512, encoded.AsSpan(), policy).IsTrusted,
                    "Byte verification lost the artifact-length binding.");
                byte[] wrongDigest = digest.Sha512.ToArray();
                try
                {
                    wrongDigest[0] ^= 1;
                    Require(!HybridSignatureService.VerifyDigest(digest.Length, wrongDigest, encoded.AsSpan(), policy).IsTrusted,
                        "Byte verification lost the SHA-512 artifact binding.");
                }
                finally { CryptographicOperations.ZeroMemory(wrongDigest); }

                held.AssertStable();
                Action namespaceCheck = held.CaptureNamespaceCheck();
                File.Move(sidecarPath, sidecarPath + ".original");
                File.WriteAllBytes(sidecarPath, original);
                File.SetUnixFileMode(sidecarPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                RequireThrows<IOException>(() => held.AssertStable(),
                    "A byte-identical pathname replacement escaped the held-descriptor identity check.");
                RequireThrows<IOException>(namespaceCheck,
                    "A byte-identical pathname replacement escaped the deferred namespace check.");
            }
            finally { CryptographicOperations.ZeroMemory(encoded); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(original);
            foreach (string file in Directory.EnumerateFiles(root))
                File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            Directory.Delete(root, recursive: true);
        }
    }
}
