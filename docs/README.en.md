# Keep Vault documentation index

[Deutsch](README.md) · [English](README.en.md) · [Main guide](../README.md)

The paired guides and historical reports below have complete German and English editions. New 5.0.3/v13 implementation and review reports are currently available in German and are marked accordingly; no complete English translation is claimed for them. Commands, hashes, test data and original log quotations are preserved as technical evidence.

Published reference pending completion of the new release: [Keep Vault 5.0.2 for macOS](https://github.com/michael-feinermann/keep-vault/releases/tag/v5.0.2), build 13, container v12 and KPAR2 v4. The working source targets 5.0.3, build 14 and container v13 under REV9. Its [release report](KEEP_VAULT_5_0_3_RELEASE_REPORT.md) records the actual validation, installation and publication status. This run covers macOS only; Windows requires separate evidence. Historical reports retain their dated results and do not approve 5.0.3.

## 5.0.3 / v13 / REV9: current source and evidence

All documents in this table are currently in German. A link is a document index, not a PASS claim; the report itself distinguishes completed checks, pending gates and limits. Real test data is limited by the user to 256 MiB, with an explicit 512 MiB Paranoia structural exception. No physical multi-TiB run is implied.

| Document | Available edition |
|---|---|
| Implementation, baseline and toolchain | [German](KEEP_VAULT_5_0_3_V13_IMPLEMENTATION.md) |
| Container format v13 | [German](KEEP_VAULT_V13_FORMAT.md) |
| Cryptographic primitive usage | [German](KEEP_VAULT_V13_CRYPTO_USAGE.md) |
| REV9 core review | [German](KEEP_VAULT_5_0_3_CORE_REV9_REVIEW.md) |
| Nonce and pool review | [German](KEEP_VAULT_5_0_3_NONCE_POOLS_REVIEW.md) |
| REV6 nonce derivation, retained in REV9 | [German](KEEP_VAULT_5_0_3_NONCE_REV6_REVIEW.md) |
| REV7 pool routing, retained in REV9 | [German](KEEP_VAULT_5_0_3_POOL_ROUTING_REV7_REVIEW.md) |
| REV9 pool shuffle and lifetime | [German](KEEP_VAULT_5_0_3_POOL_SHUFFLE_REV9_REVIEW.md) |
| REV9 entropy measurements | [German](KEEP_VAULT_5_0_3_ENTROPY_REV9_PERFORMANCE.md) |
| Cipher references and oracles | [German](KEEP_VAULT_5_0_3_CIPHER_REFERENCE_REPORT.md) |
| Optimization review | [German](KEEP_VAULT_5_0_3_OPTIMIZATION_REPORT.md) |
| Parallelism and scaling boundaries | [German](KEEP_VAULT_5_0_3_SCALABILITY_REPORT.md) |
| Bounded input, KPAR2 and resources | [German](KEEP_VAULT_5_0_3_MULTITB_DESIGN.md) |
| IO and resource tests | [German](KEEP_VAULT_5_0_3_MULTITB_TEST_REPORT.md) |
| Security review | [German](KEEP_VAULT_5_0_3_SECURITY_REVIEW.md) |
| Overall test status | [German](KEEP_VAULT_5_0_3_TEST_REPORT.md) |
| GUI test status | [German](KEEP_VAULT_5_0_3_GUI_REPORT.md) |
| Release and installation status | [German](KEEP_VAULT_5_0_3_RELEASE_REPORT.md) |

## Guides and specifications

| Document | Deutsch | English |
|---|---|---|
| User guide and security boundaries | [Deutsch](../README.de.md) | [English](../README.md) |
| macOS packaging, signing and installation | [Deutsch](../KeepVaultMac/Packaging/README.md) | [English](../KeepVaultMac/Packaging/README.en.md) |
| QR scanner for macOS | [Deutsch](../QrCodeScanner/README.md) | [English](../QrCodeScanner/README.en.md) |
| QR scanner for Windows | [Deutsch](../QrCodeScannerWindows/README.de.md) | [English](../QrCodeScannerWindows/README.md) |
| Synthetic credential compatibility fixtures | [Deutsch](../KeepVaultMac.Tests/Fixtures/CredentialCompatibility/README.de.md) | [English](../KeepVaultMac.Tests/Fixtures/CredentialCompatibility/README.md) |
| v12 credential policy and Windows contract (historical) | [Deutsch](KEEP_VAULT_V12_CREDENTIAL_POLICY.md) | [English](KEEP_VAULT_V12_CREDENTIAL_POLICY.en.md) |
| v12 macOS release specification (historical) | [Deutsch](KEEP_VAULT_V12_MACOS_RELEASE.md) | [English](KEEP_VAULT_V12_MACOS_RELEASE.en.md) |
| v12 Windows port requirements (historical) | [Deutsch](KEEP_VAULT_V12_WINDOWS_UPDATE.md) | [English](KEEP_VAULT_V12_WINDOWS_UPDATE.en.md) |
| Additional local password model | [Deutsch](password-model/README.de.md) | [English](password-model/README.en.md) |

## Audit reports and historical evidence

| Document | Deutsch | English |
|---|---|---|
| 5.0.2 macOS audit | [Deutsch](KEEP_VAULT_5_0_2_MACOS_AUDIT.md) | [English](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md) |
| 5.0.2 PIN and password-model audit | [Deutsch](KEEP_VAULT_5_0_2_PIN_MODEL_AUDIT.md) | [English](KEEP_VAULT_5_0_2_PIN_MODEL_AUDIT.en.md) |
| v12 GPT-5.6-Sol recheck | [Deutsch](KEEP_VAULT_V12_GPT56SOL_RECHECK.md) | [English](KEEP_VAULT_V12_GPT56SOL_RECHECK.en.md) |
| 5.0.1 historical audit progress | [Deutsch](KEEP_VAULT_5_0_1_MACOS_AUDIT_PROGRESS.md) | [English](KEEP_VAULT_5_0_1_MACOS_AUDIT_PROGRESS.en.md) |
| v11 historical macOS audit | [Deutsch](KEEP_VAULT_V11_MACOS_CODEX_AUDIT.md) | [English](KEEP_VAULT_V11_MACOS_CODEX_AUDIT.en.md) |
| v11 historical open review questions | [Deutsch](v11-open-questions.de.md) | [English](v11-open-questions.md) |

## Sources, data and notices

| Document | Deutsch | English |
|---|---|---|
| Vendored-source provenance | [Deutsch](../external/VENDOR-PROVENANCE.de.md) | [English](../external/VENDOR-PROVENANCE.md) |
| Third-party original documents | [Deutsch](third-party-documents.de.md) | [English](third-party-documents.en.md) |
| Package license-notice explanations | [Deutsch](package-notices.de.md) | [English](package-notices.en.md) |

The [bundled installation file](../KeepVaultMac/Packaging/INSTALLATION.txt) already contains both languages in full. Unchanged OPUS notices are also available in [German](../KalynaArchiver/Resources/PasswordModel/NOTICE-OPUS-de.md) and [English](../KalynaArchiver/Resources/PasswordModel/NOTICE-OPUS-en.md). The complete translation of the embedded model text is maintained outside the signed resources. Original third-party licenses and reference publications remain in their original language; the bilingual source guide explains their mapping.

## Release notes

Each file below contains the complete German and English text. Published versions have corresponding GitHub release descriptions. The 5.0.3 draft has not been published; historical drafts remain drafts.

- [v5.0.3: unpublished draft, Deutsch · English](releases/v5.0.3.md)
- [v5.0.2: Deutsch · English](releases/v5.0.2.md)
- [v5.0.1: Deutsch · English](releases/v5.0.1.md)
- [v5.0.0: Deutsch · English](releases/v5.0.0.md)
- [v4.0.2: Deutsch · English](releases/v4.0.2.md)
- [v4.0.0: Deutsch · English](releases/v4.0.0.md)
- [v3.0.0: Deutsch · English](releases/v3.0.0.md)
- [v2.0.0: Deutsch · English](releases/v2.0.0.md)
- [v1.0.0: Deutsch · English](releases/v1.0.0.md)

## Maintaining language editions

Substantive changes to paired guides are made to both language editions together. New first-party documents receive an entry in this index identifying the editions actually available. The new 5.0.3 review reports may remain German-only; a future translation must be complete before it is marked as an English edition. Translations are checked against the source for sections, tables, numbers, formulas, commands, hashes and evidence limits; a summary does not replace a complete edition. Links lead to the chosen language wherever available. Historical source paths in logs remain as evidence.

The documentation change of 9 September 2026 changes neither the published `v5.0.2` tag nor its notarized executables. The release tag is authoritative for their source version; the default branch contains language editions added afterwards.
