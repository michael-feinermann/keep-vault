# Keep Vault: Dokumentationsverzeichnis

[Deutsch](README.md) · [English](README.en.md) · [Hauptanleitung](../README.de.md)

Alle eigenen Projektanleitungen, Spezifikationen, Prüfberichte und Release-Texte sind vollständig auf Deutsch und Englisch verfügbar. Jede Sprachfassung verlinkt ihr Gegenstück. Befehle, Hashes, Testdaten und originale Protokollzitate bleiben als technische Belege erhalten.

Aktuell veröffentlicht: [Keep Vault 5.0.2 für macOS](https://github.com/michael-feinermann/keep-vault/releases/tag/v5.0.2), Build 13, Container v12 und KPAR2 v4. Die Windows-Portierung wird gesondert geprüft und freigegeben. Die nachfolgenden historischen Berichte dokumentieren den jeweils datierten Stand einschließlich damaliger Fehler und offener Schritte; eine Übersetzung wandelt diese nicht in aktuelle Freigaben um.

## Anleitungen und Spezifikationen

| Dokument | Deutsch | English |
|---|---|---|
| Anleitung und Sicherheitsgrenzen | [Deutsch](../README.de.md) | [English](../README.md) |
| macOS-Paket, Signierung und Installation | [Deutsch](../KeepVaultMac/Packaging/README.md) | [English](../KeepVaultMac/Packaging/README.en.md) |
| QR-Scanner für macOS | [Deutsch](../QrCodeScanner/README.md) | [English](../QrCodeScanner/README.en.md) |
| QR-Scanner für Windows | [Deutsch](../QrCodeScannerWindows/README.de.md) | [English](../QrCodeScannerWindows/README.md) |
| Synthetische Zugangsdaten-Kompatibilitätstests | [Deutsch](../KeepVaultMac.Tests/Fixtures/CredentialCompatibility/README.de.md) | [English](../KeepVaultMac.Tests/Fixtures/CredentialCompatibility/README.md) |
| v12-Zugangsdatenregeln und Windows-Vertrag | [Deutsch](KEEP_VAULT_V12_CREDENTIAL_POLICY.md) | [English](KEEP_VAULT_V12_CREDENTIAL_POLICY.en.md) |
| v12-macOS-Release-Spezifikation | [Deutsch](KEEP_VAULT_V12_MACOS_RELEASE.md) | [English](KEEP_VAULT_V12_MACOS_RELEASE.en.md) |
| v12-Windows-Portierungsauftrag | [Deutsch](KEEP_VAULT_V12_WINDOWS_UPDATE.md) | [English](KEEP_VAULT_V12_WINDOWS_UPDATE.en.md) |
| Zusätzliches lokales Passwortmodell | [Deutsch](password-model/README.de.md) | [English](password-model/README.en.md) |

## Prüfberichte und historische Nachweise

| Dokument | Deutsch | English |
|---|---|---|
| 5.0.2-macOS-Prüfbericht | [Deutsch](KEEP_VAULT_5_0_2_MACOS_AUDIT.md) | [English](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md) |
| 5.0.2-PIN- und Passwortmodell-Prüfbericht | [Deutsch](KEEP_VAULT_5_0_2_PIN_MODEL_AUDIT.md) | [English](KEEP_VAULT_5_0_2_PIN_MODEL_AUDIT.en.md) |
| v12-Nachprüfung mit GPT-5.6-Sol | [Deutsch](KEEP_VAULT_V12_GPT56SOL_RECHECK.md) | [English](KEEP_VAULT_V12_GPT56SOL_RECHECK.en.md) |
| 5.0.1-historischer Prüfverlauf | [Deutsch](KEEP_VAULT_5_0_1_MACOS_AUDIT_PROGRESS.md) | [English](KEEP_VAULT_5_0_1_MACOS_AUDIT_PROGRESS.en.md) |
| v11-historisches macOS-Audit | [Deutsch](KEEP_VAULT_V11_MACOS_CODEX_AUDIT.md) | [English](KEEP_VAULT_V11_MACOS_CODEX_AUDIT.en.md) |
| v11-historische offene Prüffragen | [Deutsch](v11-open-questions.de.md) | [English](v11-open-questions.md) |

## Quellen, Daten und Hinweise

| Dokument | Deutsch | English |
|---|---|---|
| Herkunft eingebundener Quellen | [Deutsch](../external/VENDOR-PROVENANCE.de.md) | [English](../external/VENDOR-PROVENANCE.md) |
| Originaldokumente von Drittanbietern | [Deutsch](third-party-documents.de.md) | [English](third-party-documents.en.md) |
| Erläuterungen zu den Paket-Lizenzhinweisen | [Deutsch](package-notices.de.md) | [English](package-notices.en.md) |

Die [mitgelieferte Installationsdatei](../KeepVaultMac/Packaging/INSTALLATION.txt) enthält beide Sprachen bereits vollständig. Die unveränderten OPUS-Hinweise liegen ebenfalls auf [Deutsch](../KalynaArchiver/Resources/PasswordModel/NOTICE-OPUS-de.md) und [Englisch](../KalynaArchiver/Resources/PasswordModel/NOTICE-OPUS-en.md) vor. Die vollständige Übersetzung des eingebetteten Modelltextes wird außerhalb der signierten Ressourcen gepflegt. Originale Drittanbieter-Lizenzen und Referenzpublikationen bleiben in ihrer Originalsprache; die zweisprachige Quellenübersicht erklärt ihre Zuordnung.

## Release-Texte

Jede der folgenden Dateien enthält den vollständigen deutschen und englischen Text. Dieselben Fassungen stehen in den GitHub-Release-Beschreibungen. Historische Entwürfe bleiben Entwürfe.

- [v5.0.2: Deutsch · English](releases/v5.0.2.md)
- [v5.0.1: Deutsch · English](releases/v5.0.1.md)
- [v5.0.0: Deutsch · English](releases/v5.0.0.md)
- [v4.0.2: Deutsch · English](releases/v4.0.2.md)
- [v4.0.0: Deutsch · English](releases/v4.0.0.md)
- [v3.0.0: Deutsch · English](releases/v3.0.0.md)
- [v2.0.0: Deutsch · English](releases/v2.0.0.md)
- [v1.0.0: Deutsch · English](releases/v1.0.0.md)

## Pflege der Sprachfassungen

Inhaltliche Änderungen werden in beiden Sprachfassungen gemeinsam vorgenommen. Neue eigene Dokumente erhalten beide Sprachfassungen und einen Eintrag in diesem Verzeichnis. Bei Übersetzungen werden Abschnitte, Tabellen, Zahlen, Formeln, Befehle, Hashes und Nachweisgrenzen mit der Quelle abgeglichen; eine Zusammenfassung ersetzt keine vollständige Fassung. Verweise führen soweit vorhanden zur gewählten Sprache. Historische Quellenpfade in Protokollen bleiben als Belege erhalten.

Die Dokumentationsänderung vom 9. September 2026 verändert weder den veröffentlichten Tag `v5.0.2` noch dessen notarisierte Programmdateien. Für den Quellstand dieser Programme ist der Release-Tag maßgeblich; der Standardbranch enthält die anschließend ergänzten Sprachfassungen.
