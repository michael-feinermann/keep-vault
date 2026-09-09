# Keep Vault macOS release

[Deutsch](README.md) · [English](README.en.md) · [Documentation index](../../docs/README.en.md)

This infrastructure does not produce an insecure substitute release. A build is
published only if every link in the following trust chain exists and has passed
verification:

1. The NativeAOT core and all native tools are universal Mach-O files or, for
   an explicitly local build, arm64 Mach-O files.
2. Every Mach-O is signed with Hardened Runtime and an Apple identity belonging
   to the pinned team `2T6K9PGS55`.
3. Mach-O components are exhaustively discovered from the bundle and have
   SHA3-512 and Skein-1024 manifests. The artifact and both manifests are each
   signed with RSA-PSS/SHA-512 and ML-DSA-87.
4. The small Swift launcher contains the exact SHA-256 pin of the hybrid RSA
   certificate and the ML-DSA-87 public key. Before the first `exec`, it checks
   the complete Apple bundle signature, the signed core identifier, the SHA-512
   artifact binding and both hybrid signatures of the core.
5. A separately Apple-signed supervisor starts suspended. The launcher checks
   its team, identifier and build-specific embedded CDHash. The launcher then
   replaces its own PID with the core using
   `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED`. The supervisor checks
   the actually mapped process through Security.framework against the previously
   embedded core CDHash and resumes it only on an exact match. A path swap between
   verification and launch therefore cannot execute an unchecked core.
6. Only then is the entire `.app` bundle sealed from the inside out.
   The distribution ZIP additionally receives its own hybrid signatures.

This creates no self-reference cycle. The actual core is hybrid-signed.
Its Apple CDHash is embedded in the supervisor, whose Apple CDHash is in turn
embedded in the launcher. Launcher and supervisor are part of the outer Apple signature.

## Entitlements

Core and launcher use no App Sandbox and declare no entitlements. Both run
with Hardened Runtime and active library validation. File selection and printing
use the regular macOS dialogs. The source fixes empty entitlement files for
core, launcher and native helpers. The separate QR scanner has its own camera sandbox.

There are no exceptions for network, camera, microphone, USB, Bluetooth,
Apple Events, debugging, JIT, unsigned memory or library validation. ZPAQ and
the Argon2 command-line tool receive no additional sandbox or inherit entitlements.
ZPAQ is additionally subject to restrictive operation-specific Seatbelt profiles
and the root-owned v12 execution anchor.

## Private release keys

Private keys must not be in the repository. The build expects:

- by default,
  `~/Library/Application Support/Keep Vault/ReleaseKeys/hybrid-rsa4096.pfx`
  as an external RSA-4096 code-signing PFX with a SHA-512 certificate signature,
  Digital Signature key usage and Code Signing EKU,
- by default,
  `~/Library/Application Support/Keep Vault/ReleaseKeys/mldsa87-private.key.v12.enc`
  as the role-specific v12 envelope for the ML-DSA-87 private key,
- by default,
  `~/Library/Application Support/Keep Vault/ReleaseKeys/hybrid-rsa4096.pfx.password.v12.enc`
  as the independent v12 envelope for the PFX password,
- the matching public key at
  `KeepVaultMac/Packaging/Keys/mldsa87-public.key`.

The variables `KEEPVAULT_HYBRID_PFX`,
`KEEPVAULT_MLDSA_PRIVATE_KEY_ENCRYPTED`,
`KEEPVAULT_PFX_PASSWORD_ENCRYPTED` and `KEEPVAULT_MLDSA_PUBLIC_KEY` may replace
these paths for a controlled release environment. The PFX and the two separate
v12 envelopes must belong to the current user, must be neither symlinks nor inside
the repository, and must reside in a private directory without group or other
access. The two wrapping keys remain in separate Keychain entries requiring
confirmation. `tools/Protect-HybridKeys-macOS.sh --verify-only` checks this
separation without reading keys or passwords.

Alternatively, both wrapping keys may explicitly reside on a protected local
volume. This requires setting `KEEPVAULT_MLDSA_WRAPPING_KEY_FILE` and
`KEEPVAULT_PFX_WRAPPING_KEY_FILE` together. Each file contains one canonical
Base64 value for 32 bytes, is role-separated, single-link and mode 0600.
Parent directories are private (0700). Symlinks, equal key values, non-local
volumes and disabled ownership enforcement are rejected. There is no silent
switch between file and Keychain access. The v12 envelopes must exactly match
the chosen wrapping keys; existing different envelopes are not overwritten.

`KEEPVAULT_APPLE_KEYCHAIN` additionally selects a private Apple keychain, for
example on the same encrypted USB volume. Identity discovery and
`codesign --keychain` then use only this keychain for the private signing identity.
macOS may still obtain certificates for the public trust chain from its normal
certificate stores. OS authorization and unlocking happen locally; passwords
are not passed as command-line arguments or environment values.

If the installed root-owned ZPAQ anchor does not match the new signed build,
`--install-for-tests` may explicitly request installation of this exact candidate
before testing. The regular installer requires local macOS administrator
approval. The same build then continues and checks byte identity again.
A new build after separate installation would not be a substitute: even the CMS
signing time changes signed bytes. This option skips no test and is not public
release approval.

Because macOS cannot load private PFX keys purely ephemerally in
`X509Certificate2`, the signer uses .NET's designated temporary keychain path.
The build script restricts it to its own `0700` TMPDIR, starts the already built
signer without MSBuild through the same process path, and compares both this TMPDIR
and the user's keychain inventory before and after every signing operation.
Any residual artifact fails the release closed. The signer deterministically
releases all certificate and RSA handles before this check.

The local arm64 release build can then start without additional key-path variables:

```sh
tools/Build-KeepVault-macOS.sh --architecture arm64
```

Use `--architecture universal` instead for a distribution artifact containing
both architectures. Both NativeAOT publishes and every native component must
successfully be produced as `arm64` and `x86_64`.

The release path runs no ambient installed .NET SDK. If needed, it downloads
Microsoft's official macOS-arm64 archive for SDK 10.0.400, checks it against the
fixed pinned SHA-512 before and after extraction, and uses a fresh private SDK
tree for every entry point. The host must additionally carry Microsoft's
Developer ID signature.

Before every release, the main project, HybridSigner, tests and release verifier
are restored with `--locked-mode`, `--force`, `-p:RestoreForceEvaluate=false` and
HTTP caching disabled into a fresh private NuGet cache. `--force` forces a fresh
restore check; `--force-evaluate` is not used because it would override locked mode. All .NET invocations receive only a fixed allowlist through `env -i`;
publish and signer build then run with `--no-restore` and no persistent build servers.
`obj`, `bin` and publish outputs of all projects and ProjectReferences reside
exclusively in separate per-project subtrees of the fresh private artifact path.
Repository intermediate outputs are neither read nor executed. Release and
verification scripts additionally pin the SHA-256 values of the audited lockfiles
and abort on any deviation before accessing private signing keys.

The signer rejects keys that do not match the compiled triple RSA and ML-DSA pins.
A new macOS key set therefore requires an explicit, jointly audited update of the
public keys and build pins. The build script never changes these trust anchors
automatically.

## Local Apple signature and publication

An Apple Development identity suffices for a locally verified build, but not
for public Gatekeeper distribution. For such builds, verification explicitly
reports the expected Gatekeeper rejection and claims no notarization.

Apple's documented route for an already signed, unchanged ZIP is direct submission
with Xcode's `notarytool`. The build path uses `--notary-profile NAME` for this;
only this profile route requires a Keychain profile validated against Apple's
service and successfully stored. Alternatively, `notarytool submit` and
`notarytool log` support a protected terminal prompt without storing a profile:
provide `--apple-id` and `--team-id`, omit `--password`, `--keychain-profile` and
`--keychain`. Both local subcommand help pages and `man notarytool` document this;
Apple refers to those help pages in
[TN3147](https://developer.apple.com/documentation/technotes/tn3147-migrating-to-the-latest-notarization-tool).
Re-signing the apps before submission is unnecessary.
[Apple: notarizing existing software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)

On 06.09.2026, the protected user prompt successfully validated the credentials.
Only subsequent storage in the explicitly selected USB keychain failed with
`UNIX[Invalid argument]`. This is not evidence of another 401 rejection.
The storage error's cause remains open; a connection to Unicode in the path
has not been established.

The Organizer preflight on 06.09.2026 instead showed that the Xcode used here
re-signs its export copy even with the matching Developer ID certificate:
it extends the Designated Requirement with the App Store clause containing
OID `1.2.840.113635.100.6.1.9`. All 30 checked Mach-O CDHashes in the main app
then differ from the original. Apple describes this shared code identity for
App Store and Developer ID output in
[TN3127](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements).
Notarizing this exported copy does not approve the unchanged originals.
Their stricter signature requirement remains in place.

The existing `--notarize-in-xcode` option creates separate standard archives for
Keep Vault, QR-Scanner and Keep Vault Installer and preserves the signed candidate in a private directory. It excludes
`--notary-profile` and waits for `NOTARIZED` in the terminal. This input and an
Organizer success message do not constitute approval. The script requires
unchanged original files and independently valid tickets on all three original apps,
otherwise it aborts. On this Xcode, the Organizer route is therefore not a
proven successful notarization path for the unchanged candidate.

After successful submission, Keep Vault, QR-Scanner and Keep Vault Installer
must each be treated
separately, on the original, with `stapler staple` and `stapler validate`.
All three original apps must then pass Apple and hybrid signature checks, the required
CDHash comparisons and final verification with `--require-notarization` and
Gatekeeper. An Xcode export replaces none of the three originals. Afterwards the ZIP is
recreated with tickets and signed; `--install-for-tests` installs exactly this
candidate, including the root-owned ZPAQ anchor, before the tests.

Public publication additionally requires:

- a valid `Developer ID Application` certificate of the same team,
- successful notarization through the chosen procedure,
- valid stapled tickets for all three apps,
- final checks with `--require-notarization` and `spctl`,
- every prescribed functional, GUI and performance gate, and the exact mapping
  between commit, tag and distribution artifacts.

A GitHub draft is not a public release.

## Installation and Finder shortcut

After a successful release build, this command installs the already verified
bundle to `/Applications` and creates a real Finder alias named `Keep Vault`
on the desktop:

```sh
tools/Install-KeepVault-macOS.sh
```

An existing Keep Vault bundle is atomically replaced with
`NSFileManager.replaceItemAtURL` only if its bundle ID matches. After successful
reverification, the previous version is moved to the Trash so it remains
recoverable. An existing desktop object is replaced only if it is actually
a Finder alias.
