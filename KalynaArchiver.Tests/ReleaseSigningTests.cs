using System.Buffers.Binary;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using KalynaArchiver.Signing;
using Microsoft.Win32.SafeHandles;

internal static class ReleaseSigningTests
{
    public static void Run()
    {
        string root = Path.Combine(Path.GetTempPath(), "keep-vault-release-key-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        byte[] wrapping = RandomNumberGenerator.GetBytes(32);
        (byte[] publicKey, byte[] privateKey) = Mldsa87.GenerateKeyPair();
        try
        {
            string wrappingPath = Path.Combine(root, "synthetic-wrapping.b64");
            string publicPath = Path.Combine(root, "synthetic-public.key");
            string envelopePath = Path.Combine(root, "synthetic-private.enc");
            File.WriteAllText(wrappingPath, Convert.ToBase64String(wrapping) + "\n");
            File.WriteAllBytes(publicPath, publicKey);
            byte[] envelope = Wrap("KVMDSA12"u8, privateKey, wrapping);
            File.WriteAllBytes(envelopePath, envelope);
            using (MldsaPrivateKeyLease loaded = MldsaKeyStore.OpenEncryptedKey(envelopePath, wrappingPath, publicPath))
            {
                if (!loaded.PrivateKey.SequenceEqual(privateKey)) throw new Exception("v12 ML-DSA envelope round trip changed the key.");
            }
            foreach (int offset in new[] { 0, 8, 12, 24, envelope.Length - 1 })
            {
                byte[] corrupted = envelope.ToArray();
                corrupted[offset] ^= 1;
                File.WriteAllBytes(envelopePath, corrupted);
                MustReject(() => MldsaKeyStore.OpenEncryptedKey(envelopePath, wrappingPath, publicPath).Dispose());
            }
            File.WriteAllBytes(envelopePath, envelope.Concat(new byte[] { 0 }).ToArray());
            MustReject(() => MldsaKeyStore.OpenEncryptedKey(envelopePath, wrappingPath, publicPath).Dispose());
            File.WriteAllBytes(envelopePath, Wrap("KVPFXP12"u8, privateKey, wrapping));
            MustReject(() => MldsaKeyStore.OpenEncryptedKey(envelopePath, wrappingPath, publicPath).Dispose());

            using RSA rsa = RSA.Create(4096);
            var request = new CertificateRequest("CN=Keep Vault SYNTHETIC TEST ONLY", rsa,
                HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") }, false));
            using X509Certificate2 generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
            const string syntheticPassword = " synthetic UTF-8 test: ä雪 ";
            string pfxPath = Path.Combine(root, "synthetic.pfx");
            string passwordPath = Path.Combine(root, "synthetic-password.enc");
            File.WriteAllBytes(pfxPath, generated.Export(X509ContentType.Pfx, syntheticPassword));
            File.WriteAllBytes(passwordPath, Wrap("KVPFXP12"u8, Encoding.UTF8.GetBytes(syntheticPassword), wrapping));
            using (X509Certificate2 loaded = ReleaseSigningOperations.LoadCertificate(pfxPath, passwordPath, wrappingPath))
            using (RSA loadedRsa = loaded.GetRSAPrivateKey() ?? throw new Exception("Ephemeral PFX lost its private key."))
            {
                byte[] message = "ephemeral release signing regression"u8.ToArray();
                byte[] signature = loadedRsa.SignData(message, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
                if (!rsa.VerifyData(message, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pss))
                    throw new Exception("Ephemeral RSA certificate did not sign correctly.");

                File.WriteAllBytes(envelopePath, envelope);
                string target = Path.Combine(root, "synthetic-payload.txt");
                File.WriteAllText(target, "Synthetic release-signature regression payload.");
                var rsaPins = HybridSignatureService.Fingerprint(rsa.ExportSubjectPublicKeyInfo());
                var mldsaPins = HybridSignatureService.Fingerprint(publicKey);
                string referencePath = Path.Combine(AppContext.BaseDirectory, "mldsa87_ref.dll");
                if (!File.Exists(referencePath)) referencePath = Path.GetFullPath(Path.Combine("tools", "mldsa87_ref.dll"));
                ReleaseSigningOperations.SignFile(target, loaded, envelopePath, wrappingPath, publicPath,
                    referencePath, false,
                    Convert.ToHexString(rsaPins.Sha256), Convert.ToHexString(rsaPins.Sha3_512), Convert.ToHexString(rsaPins.Skein1024),
                    Convert.ToHexString(mldsaPins.Sha256), Convert.ToHexString(mldsaPins.Sha3_512), Convert.ToHexString(mldsaPins.Skein1024));
                var policy = new HybridSignaturePolicy(
                    Convert.ToHexString(rsaPins.Sha256), Convert.ToHexString(rsaPins.Sha3_512), Convert.ToHexString(rsaPins.Skein1024),
                    Convert.ToHexString(mldsaPins.Sha256), Convert.ToHexString(mldsaPins.Sha3_512), Convert.ToHexString(mldsaPins.Skein1024), publicKey);
                File.AppendAllText(target, "tampered");
                if (HybridSignatureService.VerifyFile(target, target + ".khsig", policy).IsTrusted)
                    throw new Exception("A mutated release artifact was accepted.");

                string packageRoot = Path.Combine(root, "synthetic-package");
                Directory.CreateDirectory(Path.Combine(packageRoot, "QR-Scanner"));
                string[] packageNames = ["Keep Vault.exe", "Keep Vault Release Verifier.exe", "Keep Vault Setup.exe", "QR-Scanner/QR-Scanner.exe", "PORTABLE_README.txt"];
                foreach (string name in packageNames) File.WriteAllText(Path.Combine(packageRoot, name), "Synthetic inert file: " + name);
                var entries = packageNames.Select(name => new ReleaseInventoryEntry(name,
                    new FileInfo(Path.Combine(packageRoot, name)).Length,
                    Convert.ToHexString(SHA512.HashData(File.ReadAllBytes(Path.Combine(packageRoot, name)))))).ToArray();
                string inventoryPath = Path.Combine(packageRoot, VerifiedReleaseInventory.InventoryName);
                File.WriteAllText(inventoryPath, JsonSerializer.Serialize(new ReleaseInventoryDocument("Keep Vault", "5.0.2", "win-x64", entries)));
                ReleaseSigningOperations.SignFile(inventoryPath, loaded, envelopePath, wrappingPath, publicPath,
                    referencePath, false,
                    Convert.ToHexString(rsaPins.Sha256), Convert.ToHexString(rsaPins.Sha3_512), Convert.ToHexString(rsaPins.Skein1024),
                    Convert.ToHexString(mldsaPins.Sha256), Convert.ToHexString(mldsaPins.Sha3_512), Convert.ToHexString(mldsaPins.Skein1024));
                string copiedRoot = Path.Combine(root, "synthetic-installed-copy");
                using (var verified = new VerifiedReleaseInventory(packageRoot, policy))
                {
                    MustRejectIo(() => File.AppendAllText(Path.Combine(packageRoot, packageNames[0]), "must remain blocked while held"));
                    MustRejectIo(() => Directory.Move(packageRoot, packageRoot + ".moved"));
                    using (SafeFileHandle writableParent = OpenWritableDirectory(root))
                        if (writableParent.IsInvalid) throw new Exception("A held package ancestor blocked unrelated file creation rights.");
                    using (SafeFileHandle writablePackage = OpenWritableDirectory(packageRoot))
                        if (!writablePackage.IsInvalid) throw new Exception("A held package directory allowed reparse-changing write access.");
                    verified.CopyToNewDirectory(copiedRoot);
                    // Destination guards survive the copy method, covering the
                    // interval before the installer's independent final verify.
                    MustRejectIo(() => File.AppendAllText(Path.Combine(copiedRoot, packageNames[0]), "mutated after copy"));
                    MustRejectIo(() => File.Move(Path.Combine(copiedRoot, packageNames[0]), Path.Combine(copiedRoot, "replaced.exe")));
                    MustRejectIo(() => Directory.Move(copiedRoot, copiedRoot + ".moved"));
                    using var installed = new VerifiedReleaseInventory(copiedRoot, policy);
                    if (installed.InventoryDigest != verified.InventoryDigest) throw new Exception("Installed inventory changed identity.");
                    MustRejectIo(() => verified.CopyToNewDirectory(copiedRoot));
                }
                using (var verified = new VerifiedReleaseInventory(packageRoot, policy))
                {
                    bool reachedTransition = false;
                    verified.TestHookAfterCopyWriterClosed = path =>
                    {
                        reachedTransition = true;
                        // Identity must stay held while write access changes to
                        // the read-only lease needed by final verification.
                        MustRejectIo(() => File.Move(path, path + ".substituted"));
                        int original = File.ReadAllBytes(path)[0];
                        using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.Read);
                        writer.WriteByte((byte)(original ^ 1));
                        writer.Flush(true);
                    };
                    MustReject(() => verified.CopyToNewDirectory(Path.Combine(root, "mutated-during-copy")));
                    if (!reachedTransition) throw new Exception("The copy guard regression did not reach the writer transition.");
                }
                string extra = Path.Combine(packageRoot, "unexpected.txt");
                File.WriteAllText(extra, "extra");
                MustReject(() => new VerifiedReleaseInventory(packageRoot, policy).Dispose());
                File.Delete(extra);
                File.AppendAllText(Path.Combine(packageRoot, packageNames[0]), "tamper");
                MustReject(() => new VerifiedReleaseInventory(packageRoot, policy).Dispose());
                foreach (string unsafePath in new[] { "../outside", "a\\b", "a:b", "CON", "x/NUL.txt", "trailing.", "a//b", "/rooted" })
                    MustReject(() => VerifiedReleaseInventory.ValidateRelativePath(unsafePath));
            }
            File.WriteAllBytes(passwordPath, Wrap("KVMDSA12"u8, Encoding.UTF8.GetBytes(syntheticPassword), wrapping));
            MustReject(() => ReleaseSigningOperations.LoadCertificate(pfxPath, passwordPath, wrappingPath).Dispose());
            File.WriteAllBytes(passwordPath, Wrap("KVPFXP12"u8, [0xC0, 0x80], wrapping));
            MustReject(() => ReleaseSigningOperations.LoadCertificate(pfxPath, passwordPath, wrappingPath).Dispose());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(wrapping);
            Directory.Delete(root, recursive: true);
        }
    }

    private static byte[] Wrap(ReadOnlySpan<byte> magic, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> key)
    {
        byte[] envelope = new byte[checked(40 + payload.Length)];
        magic.CopyTo(envelope);
        BinaryPrimitives.WriteUInt32LittleEndian(envelope.AsSpan(8, 4), checked((uint)payload.Length));
        RandomNumberGenerator.Fill(envelope.AsSpan(12, 12));
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(envelope.AsSpan(12, 12), payload, envelope.AsSpan(24, payload.Length),
            envelope.AsSpan(24 + payload.Length, 16), envelope.AsSpan(0, 12));
        return envelope;
    }

    private static void MustReject(Action action)
    {
        try { action(); }
        catch (CryptographicException) { return; }
        catch (InvalidDataException) { return; }
        throw new Exception("A malformed or cross-type release secret was accepted.");
    }

    private static void MustRejectIo(Action action)
    {
        try { action(); }
        catch (IOException) { return; }
        throw new Exception("A held release file or an existing install directory was writable.");
    }

    private static SafeFileHandle OpenWritableDirectory(string path) => CreateFileW(path,
        0x40000000, 3, 0, 3, 0x02200000, 0);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, nint attributes,
        uint disposition, uint flags, nint template);
}
