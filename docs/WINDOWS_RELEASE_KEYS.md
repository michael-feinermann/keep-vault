# Windows release keys

Windows has its own RSA-4096 and ML-DSA-87 release identity. Its public
certificate, ML-DSA public key and seven fingerprint/selector values are in
`WindowsRelease/Signing`. The macOS identity and existing release assets retain
their original keys. Development identities are unchanged.

The Windows identity created on 2026-09-21 has certificate thumbprint
`7BA65B5130F34AB9F15C0D074699D46D9BCCD21C`. Its private store is the direct
`Keep Vault ReleaseKeys v12\Windows-20260921` folder beneath Michael's Windows
user profile. Only its three public components are committed to this repository.

`tools/New-WindowsReleaseKeys.ps1 -ReleaseKeyDirectory <new-local-directory>`
creates and verifies a new pair. It refuses an existing private directory or
existing public identity. Use PowerShell 7 and the SDK pinned in `global.json`;
`-DotnetPath` can select the installed `dotnet.exe`. Generate only when creating
an identity, not for each build.

The private directory is outside Git and OneDrive. Its protected Windows ACL
allows only the current user and SYSTEM. The RSA PFX has a random password;
the password and ML-DSA private key are in separate AES-256-GCM v12 envelopes.
Their independent wrapping keys are protected by Windows DPAPI for the current
user. No plaintext password or private key is printed, passed to a process,
imported into a persistent certificate store, or written to an intermediate
file. A key generation must pass both signature round trips and public-policy
matching before writing the repository's public identity.
Windows package virtualization can redirect `AppData` without a filesystem
junction. Such a destination is rejected before generating secrets; use a
direct private folder beneath the Windows user profile instead.

Build with `tools/Build-Portable.ps1 -ReleaseKeyDirectory <local-directory>`.
The pipeline requires the committed Windows identity and exactly one complete
wrapping-key pair: two `.dpapi` files or two portable `.b64` files. It rejects
mixed, incomplete and ambiguous pairs, mismatching public keys and policy
overrides. A self-signed release certificate supplies the pinned publisher
identity; it does not by itself provide public-CA trust or SmartScreen reputation.

## Later transfer

Simply copying the local `.dpapi` files is not a portable backup: decryption
depends on the original Windows account's DPAPI credentials. While signed into
that account, run `tools/Export-WindowsReleaseKeys.ps1 -ReleaseKeyDirectory
<local-directory> -Destination <new-private-directory-on-target>` to create and
verify a portable folder. The target must support Windows ACLs, such as NTFS;
the tool rejects Git, OneDrive, network paths and any existing destination.

The export contains portable AES wrapping keys alongside the encrypted private
components, so possession of the complete exported folder permits signing.
Keep it private and on a protected storage device. It is never exported
automatically during generation or a build. The local DPAPI copy remains usable.
All key files in this document are distinct from archive passwords and do not
decrypt user archives.
