# Explanations of distributed license notices

[Deutsch](package-notices.de.md) · [English](package-notices.en.md) · [Documentation index](README.en.md)

This page reproduces the first-party explanatory text accompanying the package's license notices. Complete license terms and copyright declarations remain unchanged in the linked originals and the distributed package. The translation changes no terms of use. The [package installation guide](../KeepVaultMac/Packaging/INSTALLATION.txt) is already complete in German and English.

## Third-party software in the v12 package

Original: [ThirdPartyNoticesHeader.txt](../KeepVaultMac/Packaging/ThirdPartyNoticesHeader.txt).

This distribution contains third-party software. The complete notices form part of the distribution and must accompany every binary copy. The release build appends the verbatim license and third-party-notice files from exactly the locked packages and vendored source revisions used to create the application. A pinned SHA-256 check is performed before and after each append operation.

The following components are covered by the common included MIT license text:

- Avalonia 12.1.1 and its runtime components. Copyright 2013-2026 The AvaloniaUI Project.
- PDFsharp 6.2.4. Copyright 2005-2026 empira Software GmbH, Troisdorf, Germany.
- MicroCom.Runtime 0.11.6. Copyright 2021 Nikita Tsukanov.
- Tmds.DBus.Protocol 0.94.1. Copyright Tom Deseyn.
- Microsoft.Extensions.DependencyInjection.Abstractions 8.0.2.
- Microsoft.Extensions.Logging.Abstractions 8.0.3.
- System.Security.Cryptography.Pkcs 8.0.1. Copyright .NET Foundation and Contributors.

The Inter font carries Copyright 2016 The Inter Project Authors ([project](https://github.com/rsms/inter)) and is distributed under the SIL Open Font License, Version 1.1. The complete English OFL text dated 26 February 2007 is in the original.

The authors release the Skein hash function, Threefish block cipher and their source code to the public domain. Included portability headers carry separate Brian Gladman notices from 1998-2006 and 2003. Their complete terms, alternative GPL provision and disclaimers remain in the original.

The Argon2 reference implementation is used under its CC0 1.0 option. The ML-DSA reference implementation in release tooling uses its CC0 option. The authors waive copyright and related rights to the extent legally permitted. Their source distributions remain available with the tagged source release.

## Bundled offline password-analysis data

Original: [PasswordModelNoticesHeader.txt](../KeepVaultMac/Packaging/PasswordModelNoticesHeader.txt).

The signed application includes public wordlists, ranked word data, names and a bounded password blocklist. These data are used only when choosing credentials for new archives. No network lookup or runtime data download is required.

The included manifest records original authors and projects, immutable source revisions where available, hashes of original and derived files, transformations, entry counts and licenses. It is followed by the complete required license and attribution notices. Model interpretation and limits are described in full in [German](password-model/README.de.md) and [English](password-model/README.en.md); the embedded original is at `KalynaArchiver/Resources/PasswordModel/README.md`.

Attribution:

- Electronic Frontier Foundation: EFF Long Wordlist, CC BY 4.0.
- dys2p: German wordlist de-7776-v1, CC0 1.0.
- Bitcoin BIPs and Trezor python-mnemonic: byte-identical English BIP39 list, distributed with the Trezor MIT license.
- zxcvbn-ts and OPUS: English and German ranked common-word data, ODC-BY 1.0; German first names under the zxcvbn-ts MIT license.
- Dropbox zxcvbn: selected public password candidates and English name lists, MIT license.
- Keep Vault: small authored enumerations of public example phrases and blocklist entries, MIT license as in the source distribution.

Any transformations are identified separately for each file. These finite data sets are not a complete database of compromised passwords. Their inclusion implies neither endorsement by their authors nor an empirical guarantee of password entropy.
