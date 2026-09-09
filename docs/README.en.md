# Keep Vault documentation index

[Deutsch](README.md) · [English](README.en.md) · [Main guide](../README.md)

All first-party project guides, specifications, audit reports and release notes are available in complete German and English editions. Each language edition links to its counterpart. Commands, hashes, test data and original log quotations are preserved as technical evidence.

Current published release: [Keep Vault 5.0.2 for macOS](https://github.com/michael-feinermann/keep-vault/releases/tag/v5.0.2), build 13, container v12 and KPAR2 v4. The Windows port is verified and released separately. Historical reports below record their respective dated state, including failures and open steps at that time; translation does not turn them into current release approval.

## Guides and specifications

| Document | Deutsch | English |
|---|---|---|
| User guide and security boundaries | [Deutsch](../README.de.md) | [English](../README.md) |
| macOS packaging, signing and installation | [Deutsch](../KeepVaultMac/Packaging/README.md) | [English](../KeepVaultMac/Packaging/README.en.md) |
| QR scanner for macOS | [Deutsch](../QrCodeScanner/README.md) | [English](../QrCodeScanner/README.en.md) |
| QR scanner for Windows | [Deutsch](../QrCodeScannerWindows/README.de.md) | [English](../QrCodeScannerWindows/README.md) |
| Synthetic credential compatibility fixtures | [Deutsch](../KeepVaultMac.Tests/Fixtures/CredentialCompatibility/README.de.md) | [English](../KeepVaultMac.Tests/Fixtures/CredentialCompatibility/README.md) |
| v12 credential policy and Windows contract | [Deutsch](KEEP_VAULT_V12_CREDENTIAL_POLICY.md) | [English](KEEP_VAULT_V12_CREDENTIAL_POLICY.en.md) |
| v12 macOS release specification | [Deutsch](KEEP_VAULT_V12_MACOS_RELEASE.md) | [English](KEEP_VAULT_V12_MACOS_RELEASE.en.md) |
| v12 Windows port requirements | [Deutsch](KEEP_VAULT_V12_WINDOWS_UPDATE.md) | [English](KEEP_VAULT_V12_WINDOWS_UPDATE.en.md) |
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

Each file below contains the complete German and English text. The same editions appear in the GitHub release descriptions. Historical drafts remain drafts.

- [v5.0.2: Deutsch · English](releases/v5.0.2.md)
- [v5.0.1: Deutsch · English](releases/v5.0.1.md)
- [v5.0.0: Deutsch · English](releases/v5.0.0.md)
- [v4.0.2: Deutsch · English](releases/v4.0.2.md)
- [v4.0.0: Deutsch · English](releases/v4.0.0.md)
- [v3.0.0: Deutsch · English](releases/v3.0.0.md)
- [v2.0.0: Deutsch · English](releases/v2.0.0.md)
- [v1.0.0: Deutsch · English](releases/v1.0.0.md)

## Maintaining language editions

Substantive changes are made to both language editions together. New first-party documents receive both editions and an entry in this index. Translations are checked against the source for sections, tables, numbers, formulas, commands, hashes and evidence limits; a summary does not replace a complete edition. Links lead to the chosen language wherever available. Historical source paths in logs remain as evidence.

The documentation change of 9 September 2026 changes neither the published `v5.0.2` tag nor its notarized executables. The release tag is authoritative for their source version; the default branch contains language editions added afterwards.
