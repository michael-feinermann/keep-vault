# This regression uses a freshly generated, short-lived test certificate only.
# It never imports a certificate into a Windows certificate store and never
# opens release-key files. The copied test executable is never launched.
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Import-SigningRuntime.ps1')
Import-SigningRuntime -NoBuild
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$testRoot = Join-Path $repoRoot ('build-analysis\ephemeral-authenticode-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
$target = Join-Path $testRoot 'synthetic-test.exe'
Copy-Item -LiteralPath (Join-Path $repoRoot 'tools\argon2.exe') -Destination $target
$rsa = [Security.Cryptography.RSA]::Create(4096)
$certificate = $null
$loaded = $null
$pfx = $null
try {
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Keep Vault SYNTHETIC TEST ONLY', $rsa,
        [Security.Cryptography.HashAlgorithmName]::SHA512, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))
    $oids = [Security.Cryptography.OidCollection]::new()
    $oids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3')) | Out-Null
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $false))
    $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddHours(1))
    $pfx = $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx, 'synthetic test only')
    $loaded = [Security.Cryptography.X509Certificates.X509CertificateLoader]::LoadPkcs12(
        $pfx, 'synthetic test only', [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    [KalynaArchiver.Signing.ReleaseAuthenticodeSigner]::SignSha512($target, $loaded)
    $result = Get-AuthenticodeSignature -LiteralPath $target
    if (-not $result.SignerCertificate -or $result.Status -in @('NotSigned', 'HashMismatch')) {
        throw "Ephemeral Authenticode test failed: $($result.Status) $($result.StatusMessage)"
    }
    $trustStatus = [KalynaArchiver.Signing.ReleaseAuthenticode]::Verify($target)
    if ($trustStatus -ne 0x800B0109u) { throw 'Synthetic signer must verify with only CERT_E_UNTRUSTEDROOT.' }
    [KalynaArchiver.Signing.ReleaseAuthenticodePolicy]::RequireSha512($target)
    $algorithms = [KalynaArchiver.Signing.ReleaseAuthenticodePolicy]::ReadDigestAlgorithms($target)
    if ($algorithms.PeDigest -ne '2.16.840.1.101.3.4.2.3' -or $algorithms.PrimarySignerDigest -ne '2.16.840.1.101.3.4.2.3' -or $algorithms.PeDigestLength -ne 64) {
        throw 'The actual PE and primary CMS digests are not both SHA-512.'
    }
    $weakTarget = Join-Path $testRoot 'synthetic-sha256-policy-rejection.exe'
    Copy-Item -LiteralPath $target -Destination $weakTarget
    $null = Set-AuthenticodeSignature -LiteralPath $weakTarget -Certificate $loaded -HashAlgorithm SHA256
    $rejected = $false
    try { [KalynaArchiver.Signing.ReleaseAuthenticodePolicy]::RequireSha512($weakTarget) }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'A SHA-256 Authenticode signature passed the strict SHA-512 policy.' }
    $bytes = [IO.File]::ReadAllBytes($target)
    $bytes[4096] = $bytes[4096] -bxor 1
    [IO.File]::WriteAllBytes($target, $bytes)
    $changedStatus = [KalynaArchiver.Signing.ReleaseAuthenticode]::Verify($target)
    if ($changedStatus -ne 0x80096010u) { throw 'A tampered signed image was not rejected with TRUST_E_BAD_DIGEST.' }
    Write-Output "ephemeral_authenticode=$($result.Status); pe_sha512=true; primary_cms_sha512=true; sha256_rejected=true; tamper_rejected=true"
}
finally {
    if ($pfx) { [Array]::Clear($pfx) }
    if ($loaded) { $loaded.Dispose() }
    if ($certificate) { $certificate.Dispose() }
    $rsa.Dispose()
    # Leave the inert, synthetically signed copy as an inspectable test artifact.
}
