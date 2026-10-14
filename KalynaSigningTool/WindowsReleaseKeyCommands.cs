using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using KalynaArchiver.Signing;
using Microsoft.Win32.SafeHandles;

internal static class WindowsReleaseKeyCommands
{
    private static readonly string[] EncryptedComponents =
    ["hybrid-rsa4096.pfx", "hybrid-rsa4096.pfx.password.v12.usb.enc", "mldsa87-private.key.v12.enc"];
    private static readonly string[] PublicComponents =
    ["hybrid-rsa4096.cer", "mldsa87-public.key", "Directory.Build.props"];

    internal static int Generate(string directory, string publicDirectory)
    {
        string root = NewPrivateDirectory(directory);
        string publicRoot = Path.GetFullPath(publicDirectory);
        RejectAliases(publicRoot);
        Directory.CreateDirectory(publicRoot);
        foreach (string name in PublicComponents)
            if (File.Exists(Path.Combine(publicRoot, name)) || Directory.Exists(Path.Combine(publicRoot, name)))
                throw new IOException("Refusing to overwrite an existing public release identity.");

        byte[] passwordRandom = RandomNumberGenerator.GetBytes(48);
        char[] password = GC.AllocateUninitializedArray<char>(64, pinned: true);
        byte[]? passwordBytes = null;
        byte[]? privateKey = null;
        byte[]? publicKey = null;
        byte[]? pfx = null;
        byte[] pfxWrapping = RandomNumberGenerator.GetBytes(32);
        byte[] mldsaWrapping = RandomNumberGenerator.GetBytes(32);
        try
        {
            if (!Convert.TryToBase64Chars(passwordRandom, password, out int written) || written != password.Length)
                throw new CryptographicException("Could not encode the generated certificate password.");
            passwordBytes = Encoding.UTF8.GetBytes(password);
            (publicKey, privateKey) = Mldsa87.GenerateKeyPair();
            using RSA rsa = RSA.Create(4096);
            var request = new CertificateRequest("CN=Keep Vault Windows Release " + DateTime.UtcNow.ToString("yyyy-MM-dd"),
                rsa, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.3") }, false));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(10));

            // PKCS#12 accepts a mutable password span; no plaintext password
            // string/file, persistent certificate-store import or temporary PFX.
            var contents = new Pkcs12SafeContents();
            var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA512, 200_000);
            Pkcs12ShroudedKeyBag keyBag = contents.AddShroudedKey(rsa, password.AsSpan(), pbe);
            Pkcs12CertBag certificateBag = contents.AddCertificate(certificate);
            byte[] localKeyId = SHA256.HashData(certificate.GetPublicKey());
            keyBag.Attributes.Add(new Pkcs9LocalKeyId(localKeyId));
            certificateBag.Attributes.Add(new Pkcs9LocalKeyId(localKeyId));
            var builder = new Pkcs12Builder();
            builder.AddSafeContentsUnencrypted(contents);
            builder.SealWithMac(password.AsSpan(), HashAlgorithmName.SHA512, 200_000);
            pfx = builder.Encode();

            WriteNew(root, EncryptedComponents[0], pfx);
            WriteWrapped(root, EncryptedComponents[1], "KVPFXP12"u8, passwordBytes, pfxWrapping);
            WriteWrapped(root, EncryptedComponents[2], "KVMDSA12"u8, privateKey, mldsaWrapping);
            WriteProtectedWrapping(root, "pfx-v12-wrapping-key.dpapi", pfxWrapping, "KVPFXP12"u8);
            WriteProtectedWrapping(root, "mldsa-v12-wrapping-key.dpapi", mldsaWrapping, "KVMDSA12"u8);

            byte[] certificateBytes = certificate.Export(X509ContentType.Cert);
            byte[] policy = PublicPolicy(certificate, rsa.ExportSubjectPublicKeyInfo(), publicKey);
            WriteNew(root, PublicComponents[0], certificateBytes);
            WriteNew(root, PublicComponents[1], publicKey);
            WriteNew(root, PublicComponents[2], policy);
            VerifyPair(root, windowsProtected: true);
            WriteNew(publicRoot, PublicComponents[0], certificateBytes);
            WriteNew(publicRoot, PublicComponents[1], publicKey);
            WriteNew(publicRoot, PublicComponents[2], policy);
            Console.WriteLine(JsonSerializer.Serialize(new { status = "created-and-verified", directory = root,
                publicDirectory = publicRoot, certificateThumbprint = certificate.Thumbprint,
                protection = "AES-256-GCM envelopes with CurrentUser DPAPI wrapping keys; encrypted RSA-4096 PKCS12; ML-DSA-87",
                portableExportRequired = true }));
            return 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordRandom);
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(password.AsSpan()));
            CryptographicOperations.ZeroMemory(pfxWrapping);
            CryptographicOperations.ZeroMemory(mldsaWrapping);
            if (passwordBytes is not null) CryptographicOperations.ZeroMemory(passwordBytes);
            if (privateKey is not null) CryptographicOperations.ZeroMemory(privateKey);
            if (publicKey is not null) CryptographicOperations.ZeroMemory(publicKey);
            if (pfx is not null) CryptographicOperations.ZeroMemory(pfx);
        }
    }

    internal static int Export(string directory, string destination)
    {
        string source = Path.GetFullPath(directory);
        RejectAliases(source);
        VerifyPair(source, windowsProtected: true);
        string target = NewPrivateDirectory(destination);
        foreach (string name in EncryptedComponents.Concat(PublicComponents))
        {
            byte[] bytes = ReleaseSigningOperations.ReadBoundedFile(Path.Combine(source, name), 1, 1024 * 1024);
            try { WriteNew(target, name, bytes); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        ExportWrapping(source, target, "pfx-v12-wrapping-key", "KVPFXP12"u8);
        ExportWrapping(source, target, "mldsa-v12-wrapping-key", "KVMDSA12"u8);
        VerifyPair(target, windowsProtected: false);
        Console.WriteLine(JsonSerializer.Serialize(new { status = "portable-export-verified", directory = target,
            privateComponents = "Keep the complete folder private; it contains portable AES wrapping keys." }));
        return 0;
    }

    private static void WriteProtectedWrapping(string root, string name, ReadOnlySpan<byte> key, ReadOnlySpan<byte> purpose)
    {
        byte[] envelope = WindowsWrappingKey.Protect(key, purpose);
        try { WriteNew(root, name, envelope); }
        finally { CryptographicOperations.ZeroMemory(envelope); }
    }

    private static void WriteWrapped(string root, string name, ReadOnlySpan<byte> magic, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> wrapping)
    {
        byte[] envelope = new byte[40 + plaintext.Length];
        try
        {
            magic.CopyTo(envelope);
            BinaryPrimitives.WriteUInt32LittleEndian(envelope.AsSpan(8), (uint)plaintext.Length);
            RandomNumberGenerator.Fill(envelope.AsSpan(12, 12));
            using var aes = new AesGcm(wrapping, 16);
            aes.Encrypt(envelope.AsSpan(12, 12), plaintext, envelope.AsSpan(24, plaintext.Length),
                envelope.AsSpan(24 + plaintext.Length, 16), envelope.AsSpan(0, 12));
            WriteNew(root, name, envelope);
        }
        finally { CryptographicOperations.ZeroMemory(envelope); }
    }

    private static void ExportWrapping(string source, string target, string stem, ReadOnlySpan<byte> purpose)
    {
        byte[] envelope = ReleaseSigningOperations.ReadBoundedFile(Path.Combine(source, stem + ".dpapi"), 21, WindowsWrappingKey.MaximumEnvelopeBytes);
        byte[]? key = null;
        char[] encoded = new char[44];
        byte[] bytes = new byte[44];
        try
        {
            key = WindowsWrappingKey.Unprotect(envelope, purpose);
            if (!Convert.TryToBase64Chars(key, encoded, out int length) || length != 44)
                throw new CryptographicException("Invalid portable wrapping-key encoding.");
            for (int index = 0; index < 44; index++) bytes[index] = checked((byte)encoded[index]);
            WriteNew(target, stem + ".b64", bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(bytes);
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(encoded.AsSpan()));
        }
    }

    private static byte[] PublicPolicy(X509Certificate2 certificate, ReadOnlySpan<byte> spki, ReadOnlySpan<byte> publicKey)
    {
        var rsa = HybridSignatureService.Fingerprint(spki);
        var mldsa = HybridSignatureService.Fingerprint(publicKey);
        var document = new XDocument(new XElement("Project", new XElement("PropertyGroup",
            new XElement("KalynaSigningCertificateThumbprint", certificate.Thumbprint),
            new XElement("KalynaExpectedSignerSha256", Convert.ToHexString(rsa.Sha256)),
            new XElement("KalynaExpectedSignerSha3_512", Convert.ToHexString(rsa.Sha3_512)),
            new XElement("KalynaExpectedSignerSkein1024", Convert.ToHexString(rsa.Skein1024)),
            new XElement("KalynaExpectedMldsa87Sha256", Convert.ToHexString(mldsa.Sha256)),
            new XElement("KalynaExpectedMldsa87Sha3_512", Convert.ToHexString(mldsa.Sha3_512)),
            new XElement("KalynaExpectedMldsa87Skein1024", Convert.ToHexString(mldsa.Skein1024)))));
        return Encoding.UTF8.GetBytes(document.ToString() + Environment.NewLine);
    }

    private static void VerifyPair(string root, bool windowsProtected)
    {
        string extension = windowsProtected ? ".dpapi" : ".b64";
        using X509Certificate2 certificate = ReleaseSigningOperations.LoadCertificate(Path.Combine(root, EncryptedComponents[0]),
            Path.Combine(root, EncryptedComponents[1]), Path.Combine(root, "pfx-v12-wrapping-key" + extension));
        using RSA rsa = certificate.GetRSAPrivateKey() ?? throw new CryptographicException("The generated PFX has no private key.");
        if (rsa.KeySize != 4096) throw new CryptographicException("The release RSA key is not 4096 bits.");
        using X509Certificate2 publicCertificate = X509CertificateLoader.LoadCertificate(
            ReleaseSigningOperations.ReadBoundedFile(Path.Combine(root, PublicComponents[0]), 1, 16384));
        if (!CryptographicOperations.FixedTimeEquals(certificate.RawData, publicCertificate.RawData))
            throw new CryptographicException("The public certificate does not match the encrypted PFX.");
        using MldsaPrivateKeyLease mldsa = MldsaKeyStore.OpenEncryptedKey(Path.Combine(root, EncryptedComponents[2]),
            Path.Combine(root, "mldsa-v12-wrapping-key" + extension), Path.Combine(root, PublicComponents[1]));
        byte[] message = RandomNumberGenerator.GetBytes(64);
        byte[] rsaSignature = rsa.SignData(message, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        byte[] mldsaSignature = Mldsa87.Sign(message, mldsa.PrivateKey);
        if (!rsa.VerifyData(message, rsaSignature, HashAlgorithmName.SHA512, RSASignaturePadding.Pss)
            || !Mldsa87.Verify(message, mldsaSignature, mldsa.PublicKey))
            throw new CryptographicException("Generated release keys failed their signing round trip.");
        byte[] expectedPolicy = PublicPolicy(certificate, rsa.ExportSubjectPublicKeyInfo(), mldsa.PublicKey);
        byte[] actualPolicy = ReleaseSigningOperations.ReadBoundedFile(Path.Combine(root, PublicComponents[2]), 1, 16384);
        if (!CryptographicOperations.FixedTimeEquals(expectedPolicy, actualPolicy))
            throw new CryptographicException("The public release policy does not match the encrypted keys.");
    }

    private static string NewPrivateDirectory(string path)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows release-key storage requires Windows.");
        string full = Path.GetFullPath(path);
        RejectRepositoryOrSyncedStorage(full);
        RejectAliases(full);
        if (Directory.Exists(full) || File.Exists(full)) throw new IOException("Refusing to overwrite an existing key directory.");
        Directory.CreateDirectory(Path.GetDirectoryName(full) ?? throw new IOException("A key directory needs a parent."));
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        SecurityIdentifier user = WindowsIdentity.GetCurrent().User ?? throw new IOException("No Windows user SID.");
        security.SetOwner(user);
        foreach (SecurityIdentifier identity in new[] { user, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
            security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        byte[] descriptor = security.GetSecurityDescriptorBinaryForm();
        GCHandle pinned = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                Descriptor = pinned.AddrOfPinnedObject()
            };
            // CreateDirectoryW fails if any object already occupies the path.
            // DirectoryInfo.Create would silently accept a raced-in directory.
            if (!CreateDirectoryW(full, ref attributes))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not exclusively create the private release-key directory.");
        }
        finally { pinned.Free(); }
        RejectAliases(full);
        RequireCanonicalDirectory(full);
        DirectorySecurity actual = new DirectoryInfo(full).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        var rules = actual.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        if (!actual.AreAccessRulesProtected || !user.Equals(actual.GetOwner(typeof(SecurityIdentifier))) || rules.Length != 2
            || rules.Any(rule => rule.IsInherited || rule.AccessControlType != AccessControlType.Allow
                || rule.FileSystemRights != FileSystemRights.FullControl
                || rule.InheritanceFlags != (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit)
                || rule.PropagationFlags != PropagationFlags.None)
            || rules.Count(rule => user.Equals(rule.IdentityReference)) != 1
            || rules.Count(rule => system.Equals(rule.IdentityReference)) != 1)
            throw new IOException("The release-key directory did not retain the required private Windows ACL.");
        return full;
    }

    private static void RejectRepositoryOrSyncedStorage(string path)
    {
        if (path.StartsWith(@"\\", StringComparison.Ordinal))
            throw new IOException("Release keys require a local Windows filesystem path.");
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
        {
            if (Path.GetFileName(current).StartsWith("OneDrive", StringComparison.OrdinalIgnoreCase)
                || File.Exists(Path.Combine(current, ".git")) || Directory.Exists(Path.Combine(current, ".git")))
                throw new IOException("Private release keys cannot be stored in Git or OneDrive.");
        }
        foreach (string variable in new[] { "OneDrive", "OneDriveConsumer", "OneDriveCommercial" })
        {
            string? configured = Environment.GetEnvironmentVariable(variable);
            if (string.IsNullOrWhiteSpace(configured)) continue;
            string synced = Path.TrimEndingDirectorySeparator(Path.GetFullPath(configured));
            if (path.Equals(synced, StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(synced + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Private release keys cannot be stored in a configured OneDrive directory.");
        }
    }

    private static void RequireCanonicalDirectory(string path)
    {
        // Packaged applications can virtualize LocalAppData without a reparse
        // point. Reject that redirection before generating any secret; the
        // secret reader intentionally requires an exact physical path too.
        using SafeFileHandle handle = CreateFileW(path, 0x80, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot inspect the private directory.");
        var actual = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandleW(handle, actual, (uint)actual.Capacity, 0);
        if (length == 0 || length >= actual.Capacity
            || !string.Equals(actual.ToString(), @"\\?\" + path, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Windows redirects this key directory. Choose a direct local path outside AppData, Git and OneDrive.");
    }

    private static void RejectAliases(string path)
    {
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
        {
            try
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Release keys cannot use a reparse-point path.");
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
    }

    private static void WriteNew(string root, string name, ReadOnlySpan<byte> bytes)
    {
        RejectAliases(root);
        using var stream = new FileStream(Path.Combine(root, name), FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(true);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr Descriptor;
        public int InheritHandle;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string path, ref SecurityAttributes attributes);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint size, uint flags);
}
