# Tests only fresh synthetic key stores below the user's Keep Vault ReleaseKeyTests.
# Never accepts an existing private-key directory or exports a production key.
param(
    [string] $DotnetPath = 'C:\Users\Michael\.codex\tools\dotnet-10.0.401\dotnet.exe',
    [string] $SigningToolAssembly = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $SigningToolAssembly) { $SigningToolAssembly = Join-Path $repository 'KalynaSigningTool\bin\Release\net10.0-windows\KalynaSigningTool.dll' }
$SigningToolAssembly = [IO.Path]::GetFullPath($SigningToolAssembly)
$id = [Guid]::NewGuid().ToString('N')
$evidence = Join-Path $repository ('work\windows-key-storage-' + $id)
$testRoot = Join-Path ([Environment]::GetFolderPath('UserProfile')) ('Keep Vault ReleaseKeyTests\synthetic-' + $id)
if (Test-Path -LiteralPath $testRoot) { throw 'The synthetic test root must be new.' }
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
[IO.Directory]::CreateDirectory($evidence) | Out-Null
[IO.File]::WriteAllText((Join-Path $testRoot 'SYNTHETIC-TEST-KEYS-ONLY.txt'), 'Disposable synthetic regression keys. Never use this identity for a release.')
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class SyntheticKeyPathProbe {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint size, uint flags);
    public static bool IsCanonical(string path) {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var actual = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandleW(file.SafeFileHandle, actual, (uint)actual.Capacity, 0);
        if (length == 0 || length >= actual.Capacity) throw new IOException("The synthetic metadata path probe failed.");
        return string.Equals(actual.ToString(), @"\\?\" + Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase);
    }
    public static void RequireCanonical(string path) {
        if (!IsCanonical(path))
            throw new IOException("Synthetic key storage must not be virtualized or aliased.");
    }
}
'@
[SyntheticKeyPathProbe]::RequireCanonical((Join-Path $testRoot 'SYNTHETIC-TEST-KEYS-ONLY.txt'))
$localKeys = Join-Path $testRoot 'local'
$public = Join-Path $testRoot 'public'
$portable = Join-Path $testRoot 'portable'
$outcomes = [Collections.Generic.List[object]]::new()
$toolHash = (Get-FileHash -LiteralPath $SigningToolAssembly -Algorithm SHA256).Hash
$signingLibrary = Join-Path (Split-Path $SigningToolAssembly) 'KalynaArchiver.Signing.dll'
$libraryHash = (Get-FileHash -LiteralPath $signingLibrary -Algorithm SHA256).Hash
function Invoke-KeyCommand([string] $Name, [bool] $ExpectSuccess, [string[]] $Arguments) {
    $log = Join-Path $evidence ($Name + '.log')
    & $DotnetPath $SigningToolAssembly @Arguments *> $log
    $code = $LASTEXITCODE
    if (($code -eq 0) -ne $ExpectSuccess) { throw "Unexpected command result for $Name; exit=$code. See the synthetic-only log." }
    $outcomes.Add([ordered]@{Name=$Name;Passed=$true;ExitCode=$code;Log=$log})
    Write-Host "PASS $Name"
}
try {
    $redirectProbe = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('Keep Vault\ReleaseKeyTests\redirect-probe-' + $id)
    [IO.Directory]::CreateDirectory($redirectProbe) | Out-Null
    $marker = Join-Path $redirectProbe 'HARMLESS-PATH-PROBE.txt'
    [IO.File]::WriteAllText($marker, 'Metadata path probe only. No key material.')
    if (-not [SyntheticKeyPathProbe]::IsCanonical($marker)) {
        $rejectedRoot = Join-Path $redirectProbe 'must-remain-empty'
        Invoke-KeyCommand 'reject-virtualized-directory-before-secrets' $false @('release-keygen','--directory',$rejectedRoot,'--public-directory',(Join-Path $redirectProbe 'unused-public'))
        if (@(Get-ChildItem -LiteralPath $rejectedRoot -File -Recurse -Force).Count -ne 0 -or
            (Test-Path -LiteralPath (Join-Path $redirectProbe 'unused-public'))) { throw 'The virtualized path rejection happened after creating key contents.' }
        $outcomes.Add([ordered]@{Name='virtualized directory rejection produced no secrets or public directory';Passed=$true})
    }
    else { $outcomes.Add([ordered]@{Name='virtualized directory negative case';Skipped=$true;Reason='This host does not redirect the harmless LocalAppData probe.'}) }
    Invoke-KeyCommand 'generate' $true @('release-keygen','--directory',$localKeys,'--public-directory',$public)
    $generated = Get-Content -LiteralPath (Join-Path $evidence 'generate.log') -Raw | ConvertFrom-Json
    if ($generated.status -cne 'created-and-verified') { throw 'Missing generator success metadata.' }
    $localKeys = $generated.directory
    $public = $generated.publicDirectory
    Invoke-KeyCommand 'reject-existing-key-directory' $false @('release-keygen','--directory',$localKeys,'--public-directory',(Join-Path $testRoot 'unused-public'))
    Invoke-KeyCommand 'reject-git-key-directory' $false @('release-keygen','--directory',(Join-Path $evidence 'must-not-exist'),'--public-directory',(Join-Path $testRoot 'unused-public'))
    if (Test-Path -LiteralPath (Join-Path $evidence 'must-not-exist')) { throw 'A forbidden private Git directory was created.' }
    Invoke-KeyCommand 'reject-onedrive-key-directory' $false @('release-keygen','--directory',(Join-Path $testRoot 'OneDrive-fixture\must-not-exist'),'--public-directory',(Join-Path $testRoot 'unused-public'))
    if (Test-Path -LiteralPath (Join-Path $testRoot 'OneDrive-fixture')) { throw 'A forbidden synchronized directory was created.' }
    Invoke-KeyCommand 'portable-export' $true @('release-key-export','--directory',$localKeys,'--destination',$portable)
    $exported = Get-Content -LiteralPath (Join-Path $evidence 'portable-export.log') -Raw | ConvertFrom-Json
    if ($exported.status -cne 'portable-export-verified') { throw 'Missing export success metadata.' }
    $portable = $exported.directory
    Invoke-KeyCommand 'reject-existing-export-directory' $false @('release-key-export','--directory',$localKeys,'--destination',$portable)
    Invoke-KeyCommand 'reject-export-into-git' $false @('release-key-export','--directory',$localKeys,'--destination',(Join-Path $evidence 'must-not-exist'))

    $managed = Split-Path $SigningToolAssembly
    $escapedManaged = [Security.SecurityElement]::Escape($managed)
    $project = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0-windows</TargetFramework><OutputType>Exe</OutputType>
    <Nullable>enable</Nullable><ImplicitUsings>enable</ImplicitUsings>
    <PublishSingleFile>false</PublishSingleFile><RestorePackagesWithLockFile>false</RestorePackagesWithLockFile><RestoreLockedMode>false</RestoreLockedMode>
  </PropertyGroup>
  <ItemGroup>
    <FrameworkReference Include="Microsoft.WindowsDesktop.App" />
    <Reference Include="KalynaArchiver.Signing"><HintPath>$escapedManaged\KalynaArchiver.Signing.dll</HintPath></Reference>
    <Reference Include="BouncyCastle.Cryptography"><HintPath>$escapedManaged\BouncyCastle.Cryptography.dll</HintPath></Reference>
  </ItemGroup>
</Project>
"@
    [IO.File]::WriteAllText((Join-Path $evidence 'StorageTests.csproj'), $project)
    $source = @'
using System.Buffers.Binary;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using KalynaArchiver.Signing;

var records = new List<object>();
string local = args[0], portable = args[1], publicRoot = args[2], report = args[3];
void Check(string name, Action operation) {
    try { operation(); records.Add(new { Name=name, Passed=true }); Console.WriteLine("PASS " + name); }
    catch (Exception exception) { records.Add(new { Name=name, Passed=false, ErrorType=exception.GetType().FullName }); throw; }
}
void Require(bool value) { if (!value) throw new InvalidOperationException("Synthetic storage assertion failed."); }
void Reject(Action operation) {
    bool rejected=false;
    try { operation(); } catch (CryptographicException) { rejected=true; } catch (IOException) { rejected=true; }
    Require(rejected);
}
byte[] Fingerprint(string path) => SHA256.HashData(File.ReadAllBytes(path));
X509Certificate2 Load(string root, string extension) => ReleaseSigningOperations.LoadCertificate(
    Path.Combine(root,"hybrid-rsa4096.pfx"), Path.Combine(root,"hybrid-rsa4096.pfx.password.v12.usb.enc"), Path.Combine(root,"pfx-v12-wrapping-key"+extension));
void MutateFile(string path, Func<byte[],byte[]> mutate, Action mustReject) {
    byte[] original=File.ReadAllBytes(path);
    try { File.WriteAllBytes(path,mutate(original.ToArray())); Reject(mustReject); }
    finally { File.WriteAllBytes(path,original); CryptographicOperations.ZeroMemory(original); }
}
void VerifyAcl(string root) {
    var acl=new DirectoryInfo(root).GetAccessControl(AccessControlSections.Access|AccessControlSections.Owner);
    var user=WindowsIdentity.GetCurrent().User!;
    var system=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
    var rules=acl.GetAccessRules(true,true,typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
    Require(acl.AreAccessRulesProtected && user.Equals(acl.GetOwner(typeof(SecurityIdentifier))) && rules.Length==2);
    Require(rules.Count(r=>user.Equals(r.IdentityReference))==1 && rules.Count(r=>system.Equals(r.IdentityReference))==1);
    Require(rules.All(r=>!r.IsInherited && r.AccessControlType==AccessControlType.Allow && r.FileSystemRights==FileSystemRights.FullControl
        && r.InheritanceFlags==(InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit) && r.PropagationFlags==PropagationFlags.None));
}
try {
    Check("local and export have exact protected owner/SYSTEM ACLs",()=>{VerifyAcl(local);VerifyAcl(portable);});
    Check("only public three-component identity is published",()=>Require(Directory.GetFiles(publicRoot).Select(Path.GetFileName).Order().SequenceEqual(new[]{"Directory.Build.props","hybrid-rsa4096.cer","mldsa87-public.key"})));
    Check("local DPAPI and portable base64 variants are disjoint",()=>{
        Require(Directory.GetFiles(local).Length==8 && Directory.GetFiles(portable).Length==8);
        foreach(string stem in new[]{"pfx-v12-wrapping-key","mldsa-v12-wrapping-key"}) {
            Require(File.Exists(Path.Combine(local,stem+".dpapi")) && !File.Exists(Path.Combine(local,stem+".b64")));
            Require(File.Exists(Path.Combine(portable,stem+".b64")) && !File.Exists(Path.Combine(portable,stem+".dpapi")));
        }
    });
    foreach(string name in new[]{"hybrid-rsa4096.pfx","hybrid-rsa4096.pfx.password.v12.usb.enc","mldsa87-private.key.v12.enc","hybrid-rsa4096.cer","mldsa87-public.key","Directory.Build.props"})
        Check("export preserves "+name,()=>Require(CryptographicOperations.FixedTimeEquals(Fingerprint(Path.Combine(local,name)),Fingerprint(Path.Combine(portable,name)))));
    using var certificate=Load(local,".dpapi");
    using var exported=Load(portable,".b64");
    using var publicCertificate=X509CertificateLoader.LoadCertificateFromFile(Path.Combine(publicRoot,"hybrid-rsa4096.cer"));
    using var rsa=certificate.GetRSAPrivateKey()!;
    Check("PFX imports ephemerally and matches public/export certificate",()=>Require(certificate.HasPrivateKey && exported.HasPrivateKey && !publicCertificate.HasPrivateKey
        && certificate.RawData.AsSpan().SequenceEqual(exported.RawData) && certificate.RawData.AsSpan().SequenceEqual(publicCertificate.RawData)));
    Check("RSA4096 SHA512 code-signing certificate constraints",()=>Require(rsa.KeySize==4096 && certificate.SignatureAlgorithm.Value=="1.2.840.113549.1.1.13"
        && !certificate.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority
        && certificate.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages==X509KeyUsageFlags.DigitalSignature
        && certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages.Cast<Oid>().Single().Value=="1.3.6.1.5.5.7.3.3"));
    using var mldsa=MldsaKeyStore.OpenEncryptedKey(Path.Combine(local,"mldsa87-private.key.v12.enc"),Path.Combine(local,"mldsa-v12-wrapping-key.dpapi"),Path.Combine(local,"mldsa87-public.key"));
    using var exportedMldsa=MldsaKeyStore.OpenEncryptedKey(Path.Combine(portable,"mldsa87-private.key.v12.enc"),Path.Combine(portable,"mldsa-v12-wrapping-key.b64"),Path.Combine(portable,"mldsa87-public.key"));
    Check("portable MLDSA plaintext matches local protected key",()=>Require(mldsa.PrivateKey.SequenceEqual(exportedMldsa.PrivateKey) && mldsa.PublicKey.SequenceEqual(exportedMldsa.PublicKey)));
    Check("RSA-PSS/SHA512 and MLDSA87 signing roundtrip",()=>{
        byte[] message=RandomNumberGenerator.GetBytes(57);
        Require(rsa.VerifyData(message,rsa.SignData(message,HashAlgorithmName.SHA512,RSASignaturePadding.Pss),HashAlgorithmName.SHA512,RSASignaturePadding.Pss));
        byte[] signature=Mldsa87.Sign(message,mldsa.PrivateKey);
        Require(Mldsa87.Verify(message,signature,mldsa.PublicKey)); message[0]^=1; Require(!Mldsa87.Verify(message,signature,mldsa.PublicKey));
    });
    Check("all six public policy fingerprints and selector match",()=>{
        var policy=XDocument.Load(Path.Combine(publicRoot,"Directory.Build.props")).Root!.Element("PropertyGroup")!;
        var first=HybridSignatureService.Fingerprint(rsa.ExportSubjectPublicKeyInfo());
        var second=HybridSignatureService.Fingerprint(mldsa.PublicKey);
        Require(policy.Element("KalynaSigningCertificateThumbprint")!.Value==certificate.Thumbprint);
        foreach(var pair in new[]{("KalynaExpectedSigner",first),("KalynaExpectedMldsa87",second)}) {
            Require(policy.Element(pair.Item1+"Sha256")!.Value==Convert.ToHexString(pair.Item2.Sha256));
            Require(policy.Element(pair.Item1+"Sha3_512")!.Value==Convert.ToHexString(pair.Item2.Sha3_512));
            Require(policy.Element(pair.Item1+"Skein1024")!.Value==Convert.ToHexString(pair.Item2.Skein1024));
        }
    });
    foreach(string purposeText in new[]{"KVPFXP12","KVMDSA12"}) {
        byte[] purpose=Encoding.ASCII.GetBytes(purposeText), key=RandomNumberGenerator.GetBytes(32), envelope=WindowsWrappingKey.Protect(key,purpose);
        try {
            Check(purposeText+" DPAPI roundtrip",()=>{byte[] actual=WindowsWrappingKey.Unprotect(envelope,purpose);try{Require(CryptographicOperations.FixedTimeEquals(key,actual));}finally{CryptographicOperations.ZeroMemory(actual);}});
            foreach(int length in new[]{0,19,20,envelope.Length-1,envelope.Length+1,4097})
                Check(purposeText+" rejects envelope length "+length,()=>{byte[] malformed=new byte[length];envelope.AsSpan(0,Math.Min(length,envelope.Length)).CopyTo(malformed);Reject(()=>WindowsWrappingKey.Unprotect(malformed,purpose));});
            foreach(int offset in new[]{0,8,16,20,envelope.Length-1})
                Check(purposeText+" rejects tampered byte "+offset,()=>{byte[] malformed=envelope.ToArray();malformed[offset]^=1;Reject(()=>WindowsWrappingKey.Unprotect(malformed,purpose));});
            byte[] other=Encoding.ASCII.GetBytes(purposeText=="KVPFXP12"?"KVMDSA12":"KVPFXP12");
            Check(purposeText+" rejects other purpose",()=>Reject(()=>WindowsWrappingKey.Unprotect(envelope,other)));
            Check(purposeText+" changing header cannot change entropy binding",()=>{byte[] changed=envelope.ToArray();other.CopyTo(changed,8);Reject(()=>WindowsWrappingKey.Unprotect(changed,other));});
            foreach(int length in new[]{0,31,33}) Check(purposeText+" rejects key length "+length,()=>Reject(()=>WindowsWrappingKey.Protect(new byte[length],purpose)));
        } finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(envelope); }
    }
    Check("unknown purpose rejected",()=>Reject(()=>WindowsWrappingKey.Protect(new byte[32],"UNKNOWN!"u8)));
    string passwordPath=Path.Combine(local,"hybrid-rsa4096.pfx.password.v12.usb.enc");
    foreach(int offset in new[]{0,8,12,24,new FileInfo(passwordPath).Length-1})
        Check("PFX password envelope tamper "+offset,()=>MutateFile(passwordPath,bytes=>{bytes[offset]^=1;return bytes;},()=>{using var ignored=Load(local,".dpapi");}));
    Check("PFX password trailing byte rejected",()=>MutateFile(passwordPath,bytes=>bytes.Concat(new byte[]{0}).ToArray(),()=>{using var ignored=Load(local,".dpapi");}));
    string mldsaPath=Path.Combine(local,"mldsa87-private.key.v12.enc");
    foreach(int offset in new[]{0,8,12,24,4935})
        Check("MLDSA envelope tamper "+offset,()=>MutateFile(mldsaPath,bytes=>{bytes[offset]^=1;return bytes;},()=>{using var ignored=MldsaKeyStore.OpenEncryptedKey(mldsaPath,Path.Combine(local,"mldsa-v12-wrapping-key.dpapi"),Path.Combine(local,"mldsa87-public.key"));}));
    Check("swapped DPAPI wrapping purposes rejected",()=>Reject(()=>{using var ignored=ReleaseSigningOperations.LoadCertificate(Path.Combine(local,"hybrid-rsa4096.pfx"),passwordPath,Path.Combine(local,"mldsa-v12-wrapping-key.dpapi"));}));
    Check("wrong portable AES key rejected",()=>MutateFile(Path.Combine(portable,"pfx-v12-wrapping-key.b64"),_=>Encoding.ASCII.GetBytes(Convert.ToBase64String(new byte[32])),()=>{using var ignored=Load(portable,".b64");}));
    Check("wrong MLDSA public key rejected",()=>MutateFile(Path.Combine(local,"mldsa87-public.key"),bytes=>{bytes[0]^=1;return bytes;},()=>{using var ignored=MldsaKeyStore.OpenEncryptedKey(mldsaPath,Path.Combine(local,"mldsa-v12-wrapping-key.dpapi"),Path.Combine(local,"mldsa87-public.key"));}));
    Check("PFX bytes tamper rejected",()=>MutateFile(Path.Combine(local,"hybrid-rsa4096.pfx"),bytes=>{bytes[^1]^=1;return bytes;},()=>{using var ignored=Load(local,".dpapi");}));
    Check("all synthetic components restored after negative tests",()=>{using var ignored=Load(local,".dpapi");using var other=Load(portable,".b64");});
} finally { File.WriteAllText(report,JsonSerializer.Serialize(records,new JsonSerializerOptions{WriteIndented=true})); }
'@
    [IO.File]::WriteAllText((Join-Path $evidence 'Program.cs'), $source)
    & $DotnetPath build (Join-Path $evidence 'StorageTests.csproj') --nologo -c Release *> (Join-Path $evidence 'build.log')
    if ($LASTEXITCODE -ne 0) { throw 'The isolated managed storage-test build failed.' }
    & $DotnetPath (Join-Path $evidence 'bin\Release\net10.0-windows\StorageTests.dll') $localKeys $portable $public (Join-Path $evidence 'crypto-results.json') *> (Join-Path $evidence 'crypto-tests.log')
    if ($LASTEXITCODE -ne 0) { throw 'The synthetic managed storage tests failed.' }
    if ((Get-FileHash -LiteralPath $SigningToolAssembly -Algorithm SHA256).Hash -cne $toolHash -or
        (Get-FileHash -LiteralPath $signingLibrary -Algorithm SHA256).Hash -cne $libraryHash) { throw 'The tested generator or signing library changed.' }
    $outcomes.Add([ordered]@{Name='synthetic managed crypto/storage checks';Passed=$true;Details=(Join-Path $evidence 'crypto-results.json')})
}
finally {
    [ordered]@{Scope='Fresh disposable synthetic key-store tests only; no production keys, native products or trust-store changes.';
        SyntheticRoot=$testRoot;Tool=$SigningToolAssembly;ToolSha256=$toolHash;SigningLibrarySha256=$libraryHash;
        Outcomes=$outcomes;CompletedAt=(Get-Date -Format o)} |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $evidence 'results.json') -Encoding utf8NoBOM
    Write-Host "Synthetic storage evidence: $evidence"
}
