# Keep Vault: Dokumentationsverzeichnis

[Deutsch](README.md) · [English](README.en.md) · [Hauptanleitung](../README.de.md)

Die unten paarweise verlinkten Anleitungen und historischen Berichte liegen vollständig auf Deutsch und Englisch vor. Neue Umsetzungs- und Prüfberichte zu 5.0.3/v13 nennen ihre verfügbare Sprache im Verzeichnis; für sie wird keine vollständige zweisprachige Übersetzung behauptet. Befehle, Hashes, Testdaten und originale Protokollzitate bleiben als technische Belege erhalten.

Veröffentlichte Referenz bis zum Abschluss des neuen Releases: [Keep Vault 5.0.2 für macOS](https://github.com/michael-feinermann/keep-vault/releases/tag/v5.0.2), Build 13, Container v12 und KPAR2 v4. Der Arbeitsstand zielt auf 5.0.3 und Container v13 gemäß REV11. Der [Releasebericht](KEEP_VAULT_5_0_3_RELEASE_REPORT.md) hält den tatsächlichen Prüf-, Installations- und Veröffentlichungsstatus fest. Dieser Durchgang betrifft ausschließlich macOS; Windows benötigt eigene Nachweise. Historische Berichte behalten ihren datierten Befund und geben 5.0.3 nicht frei.

## 5.0.3 / v13 / REV11: aktueller Quell- und Prüfstand

Die jeweilige Dokumentsprache ist ausdrücklich angegeben. Ein Link ist ein Verzeichniseintrag, keine PASS-Aussage; der jeweilige Bericht trennt bestandene Prüfungen, offene Gates und Nachweisgrenzen. Reale Testdaten sind auf Benutzerwunsch auf 256 MiB begrenzt, mit einer ausdrücklichen 512-MiB-Ausnahme für die Paranoia-Strukturrunde. Daraus folgt kein physischer Mehr-TiB-Lauf.

| Dokument | Verfügbare Fassung |
|---|---|
| Automatische Ressourcen nach REV11 | [English](KEEP_VAULT_5_0_3_AUTO_RESOURCES_REV10_REVIEW.md) |
| Originaleingaben und Recovery nach REV11 | [Deutsch](KEEP_VAULT_5_0_3_ORIGINAL_INPUT_REVIEW.md) |
| Nativer ZPAQ-Kontrollkanal und Lebensdauer nach REV11 | [Deutsch](KEEP_VAULT_5_0_3_ZPAQ_REV11_REVIEW.md) |
| Fortschritt und entfallene Laufzeitgrenzen nach REV11 | [English](KEEP_VAULT_5_0_3_PROGRESS_ETA_REV11_REVIEW.md) |
| Schreibgeschützte Golden-Prüfung | [English](KEEP_VAULT_5_0_3_GOLDEN_VERIFIER_REVIEW.md) |
| Umsetzung, Ausgangsstand und Toolchain | [Deutsch](KEEP_VAULT_5_0_3_V13_IMPLEMENTATION.md) |
| Containerformat v13 | [Deutsch](KEEP_VAULT_V13_FORMAT.md) |
| Verwendung der kryptografischen Primitive | [Deutsch](KEEP_VAULT_V13_CRYPTO_USAGE.md) |
| REV9-Kernprüfung | [Deutsch](KEEP_VAULT_5_0_3_CORE_REV9_REVIEW.md) |
| Nonce- und Poolprüfung | [Deutsch](KEEP_VAULT_5_0_3_NONCE_POOLS_REVIEW.md) |
| REV6-Nonceableitung, in REV9 beibehalten | [Deutsch](KEEP_VAULT_5_0_3_NONCE_REV6_REVIEW.md) |
| REV7-Poolrouting, in REV9 beibehalten | [Deutsch](KEEP_VAULT_5_0_3_POOL_ROUTING_REV7_REVIEW.md) |
| REV9-Poolshuffle und Lebensdauer | [Deutsch](KEEP_VAULT_5_0_3_POOL_SHUFFLE_REV9_REVIEW.md) |
| REV9-Entropiemessungen | [Deutsch](KEEP_VAULT_5_0_3_ENTROPY_REV9_PERFORMANCE.md) |
| Cipherreferenzen und Orakel | [Deutsch](KEEP_VAULT_5_0_3_CIPHER_REFERENCE_REPORT.md) |
| Optimierungsprüfung | [Deutsch](KEEP_VAULT_5_0_3_OPTIMIZATION_REPORT.md) |
| Parallelität und Skalierungsgrenzen | [Deutsch](KEEP_VAULT_5_0_3_SCALABILITY_REPORT.md) |
| Begrenzter Input, KPAR2 und Ressourcen | [Deutsch](KEEP_VAULT_5_0_3_MULTITB_DESIGN.md) |
| IO- und Ressourcenprüfungen | [Deutsch](KEEP_VAULT_5_0_3_MULTITB_TEST_REPORT.md) |
| Sicherheitsprüfung | [Deutsch](KEEP_VAULT_5_0_3_SECURITY_REVIEW.md) |
| Gesamtprüfstand | [Deutsch](KEEP_VAULT_5_0_3_TEST_REPORT.md) |
| GUI-Prüfstand | [Deutsch](KEEP_VAULT_5_0_3_GUI_REPORT.md) |
| Release- und Installationsstatus | [Deutsch](KEEP_VAULT_5_0_3_RELEASE_REPORT.md) |

## Anleitungen und Spezifikationen

| Dokument | Deutsch | English |
|---|---|---|
| Anleitung und Sicherheitsgrenzen | [Deutsch](../README.de.md) | [English](../README.md) |
| macOS-Paket, Signierung und Installation | [Deutsch](../KeepVaultMac/Packaging/README.md) | [English](../KeepVaultMac/Packaging/README.en.md) |
| QR-Scanner für macOS | [Deutsch](../QrCodeScanner/README.md) | [English](../QrCodeScanner/README.en.md) |
| QR-Scanner für Windows | [Deutsch](../QrCodeScannerWindows/README.de.md) | [English](../QrCodeScannerWindows/README.md) |
| Synthetische Zugangsdaten-Kompatibilitätstests | [Deutsch](../KeepVaultMac.Tests/Fixtures/CredentialCompatibility/README.de.md) | [English](../KeepVaultMac.Tests/Fixtures/CredentialCompatibility/README.md) |
| v12-Zugangsdatenregeln und Windows-Vertrag (historisch) | [Deutsch](KEEP_VAULT_V12_CREDENTIAL_POLICY.md) | [English](KEEP_VAULT_V12_CREDENTIAL_POLICY.en.md) |
| v12-macOS-Release-Spezifikation (historisch) | [Deutsch](KEEP_VAULT_V12_MACOS_RELEASE.md) | [English](KEEP_VAULT_V12_MACOS_RELEASE.en.md) |
| v12-Windows-Portierungsauftrag (historisch) | [Deutsch](KEEP_VAULT_V12_WINDOWS_UPDATE.md) | [English](KEEP_VAULT_V12_WINDOWS_UPDATE.en.md) |
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

Jede der folgenden Dateien enthält den vollständigen deutschen und englischen Text. Veröffentlichte Fassungen besitzen entsprechende GitHub-Release-Beschreibungen. Der 5.0.3-Entwurf ist noch nicht veröffentlicht; historische Entwürfe bleiben Entwürfe.

- [v5.0.3: unveröffentlichter Entwurf, Deutsch · English](releases/v5.0.3.md)
- [v5.0.2: Deutsch · English](releases/v5.0.2.md)
- [v5.0.1: Deutsch · English](releases/v5.0.1.md)
- [v5.0.0: Deutsch · English](releases/v5.0.0.md)
- [v4.0.2: Deutsch · English](releases/v4.0.2.md)
- [v4.0.0: Deutsch · English](releases/v4.0.0.md)
- [v3.0.0: Deutsch · English](releases/v3.0.0.md)
- [v2.0.0: Deutsch · English](releases/v2.0.0.md)
- [v1.0.0: Deutsch · English](releases/v1.0.0.md)

## Pflege der Sprachfassungen

Inhaltliche Änderungen an paarweise gepflegten Anleitungen werden in beiden Sprachfassungen gemeinsam vorgenommen. Neue eigene Dokumente erhalten einen Eintrag mit den tatsächlich verfügbaren Sprachfassungen. Die neuen 5.0.3-Prüfberichte dürfen zunächst nur auf Deutsch vorliegen; eine spätere Übersetzung muss vollständig sein, bevor sie als englische Fassung ausgewiesen wird. Bei Übersetzungen werden Abschnitte, Tabellen, Zahlen, Formeln, Befehle, Hashes und Nachweisgrenzen mit der Quelle abgeglichen; eine Zusammenfassung ersetzt keine vollständige Fassung. Verweise führen soweit vorhanden zur gewählten Sprache. Historische Quellenpfade in Protokollen bleiben als Belege erhalten.

Die Dokumentationsänderung vom 9. September 2026 verändert weder den veröffentlichten Tag `v5.0.2` noch dessen notarisierte Programmdateien. Für den Quellstand dieser Programme ist der Release-Tag maßgeblich; der Standardbranch enthält die anschließend ergänzten Sprachfassungen.
