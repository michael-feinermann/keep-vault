# Keep Vault 5.0.3/v13: veröffentlichte macOS-Vorabversion, Build 21

## Veröffentlichungsupdate, 12. Oktober 2026, 16:47 MESZ

[v5.0.3 ist jetzt regulär veröffentlicht und Latest](https://github.com/michael-feinermann/keep-vault/releases/tag/v5.0.3), auf ausdrücklichen Wunsch vor den verschobenen restlichen Tests. Verwendet werden exakt dieselben sechs geprüften Build-21-Dateien; der kompilierte Quellstand und beide Tags bleiben an `8c68571695ae9072555ffb462b3c0b9c500811ea` gebunden. Die technische Gesamtfreigabe bleibt ausstehend. Der [aktuelle Veröffentlichungsstand](KEEP_VAULT_5_0_3_PUBLICATION_STATUS.md) und die neuen Veröffentlichungsbelege trennen diese Entscheidung von den nachfolgenden historischen Vorabversionsnachweisen. Aussagen zur damaligen Latest-Auswahl beziehen sich auf die frühere Build-21-Veröffentlichung. Neue Funktions-, Leistungs- oder reale GUI-Prüfungen werden nicht behauptet.

Stand: 12. Oktober 2026. [Build 21 ist öffentlich als Vorabversion verfügbar](https://github.com/michael-feinermann/keep-vault/releases/tag/v5.0.3-rc.build21). Die reguläre vollständige macOS-Funktionssuite besteht mit 319 PASS, 0 FAIL und 0 BLOCKED. Die Veröffentlichung ist keine Gesamtfreigabe: Der normative Freigabelauf mit 49 Phasen, die verschobenen Langläufe und verbleibende reale GUI-Abnahmen sind weiterhin offen.

## Version und Herkunft

| Bindung | Tatsächlicher Wert |
|---|---|
| Produkt | Keep Vault 5.0.3/v13, macOS Universal, Build 21 |
| GitHub-Release | `410608510`, öffentlich, `prerelease=true` |
| Veröffentlichung | 12. Oktober 2026, 13:09:13 UTC |
| Tag | `v5.0.3-rc.build21` |
| Kompilierter Quellstand | `8c68571695ae9072555ffb462b3c0b9c500811ea` |
| Öffentliches ZIP | `Keep.Vault-macOS-universal.zip`, 46.565.158 Bytes |
| ZIP-SHA-256 | `8c2864a4d156a821e07a6c4328401aed0c47137d31f3202ce9adb4125ff990ac` |
| Universal-AOT-Produkt-SHA-256 | `bd5a5fbcc1c0b768386a63b7644368bff6cdaa87ddd61c7e504ded91569b078d` |

Der tatsächliche dritte Builder endet mit Exit 0; Quellstand und erfasste Eingabedateien bleiben während seines Laufs unverändert. Die anschließende Dokumentation und Belegkurierung verändern diesen kompilierten Quellstand oder das Release-Tag nicht. 566 Build-Eingaben sind an den Git-Baum gebunden: 565 stimmen byteweise mit ihren Git-Blobs überein. Bei `native/threefish_ref_export.c` ist die durch `.gitattributes` erklärte LF-zu-CRLF-Transformation separat mit beiden Hashes dokumentiert.

Die vollständige Funktionssuite verwendet die verwalteten Assemblies `Keep Vault.dll` und `KeepVaultMac.Tests.dll`. Diese Testassembly ist nicht das ausgelieferte AOT-Programm. Der Builder bindet die final gestagten nativen Komponenten und Signaturdateien sowie das Universal-AOT-Programm separat an die veröffentlichten Produktbytes. Die spätere Downloadprüfung bestätigt diese Bindungen erneut.

## Fehlerkorrekturen und gezielte Sicherheitsprüfung

Die Änderungen schließen den Zugriff auf Schlüsselbesitzer ab Beginn ihrer Entsorgung, auch wenn ein erster Cleanup fehlschlägt. Ein echter Cleanup kann erneut versucht werden; ausgegebene Arrayreferenzen werden gelöscht. Fehlende Arrays und falsche Breiten werden vor nativen Schlüsselübergaben abgefangen. Die zweite Master-KDF-Runde verlangt ihren vollständigen Vorgänger; der zulässige optionale Zusatzinput der ersten Runde bleibt erhalten.

Der Übergabevertrag prüft abgeleitetes Anwendungsschlüsselmaterial auf vollständige `00`-, `01`- und `FF`-Folgen und löscht abgewiesene Puffer. Er umfasst Master-, Rollen- und Stufenableitung sowie Besitzer-, Cipher-, MAC- und Recovery-Verbraucher. Die AEAD-Nonce-Fehlerbereinigung räumt bereits angelegtes Schlüsselmaterial auf. Der [detaillierte KDF-Bericht](KEEP_VAULT_5_0_3_KDF_HANDOFF_REVIEW.md) beschreibt Grenzen und Korrekturen.

| Tatsächlich ausgeführte Prüfung | Ergebnis |
|---|---|
| Reguläre vollständige macOS-Suite | 319 PASS, 0 FAIL, 0 BLOCKED; Wandzeit 1.456,1 s, Summe der Testzeiten 1.432,4 s |
| KDF-/Rollen-/Besitzer-Fehlermatrix | 12 Suites, 626 benannte Grenzen × 4 Fehlerbilder = 2.504 Fälle, PASS |
| Cipher-, MAC- und Recovery-Verbraucher | 336 + 80 + 24 = 440 Fehlerfälle, PASS |
| Caller-Output-Cleanup | 48 zusätzliche Fälle, PASS |
| Finale native NULL-/Breitenprüfung ARM64 | 161 PASS auf den finalen signierten Produktbibliotheken und einer separaten Testreferenz |
| Finale native NULL-/Breitenprüfung x86_64 | 161 PASS unter Rosetta, gleicher nachgewiesener Umfang |

Die Fehlermatrix verwendet ausschließlich intern begrenzte 8-MiB-Testparameter. Das ist ein Fault-Injection-Profil, keine Messung produktiver KDF-Geschwindigkeit und keine Absenkung der Produktparameter. Die nativen Prüfläufe verwenden echte Nullpointer und prüfen ABI-Breiten. Je Architektur sind neun Bibliotheken bytegleich an die final ausgelieferten Produktdateien gebunden; eine zehnte SHA3-Referenzbibliothek wird ausschließlich geprüft und nicht ausgeliefert.

Konstante Schlüssel bleiben für legitime Primitive-Referenztests zulässig und haben eigene Positivprüfungen. Nonces, Zähler, Tweaks und Nutzdaten unterliegen keinem pauschalen Konstantenverbot. Die Wächter erkennen die geprüften Sentinelwerte, fehlende Eingaben und Breitenfehler. Sie beweisen keine Entropie und erkennen nicht jede beliebige Speicherbeschädigung. Die vier isolierten GUI-Audit-Prüfungen sind automatisierte Prüfungen und ersetzen keine reale Bedienabnahme.

## Paranoia-Struktur- und Recovery-Lauf

Dieser Funktionslauf verarbeitet 512 MiB Quelldaten: den vereinbarten Baum mit insgesamt 256 MiB sowie eine zusätzliche große 256-MiB-Datei. Der Baum umfasst 149 Dateien und 32 Verzeichnisse, einschließlich leerer, verschachtelter, versteckter und Unicode-Pfade. Nach der KPAR2-Beschädigung wurde ein Shard repariert und der anschließende Struktur- und Hashvergleich bestanden.

Gemessen wurden ARM64, macOS 27.0.1, zehn logische Prozessoren, Kompressionsstufe 3 und produktive Paranoia-KDF-Parameter mit vier Argon2-Iterationen und Parallelität vier. Das entstandene Archiv hat 382.969.950 Bytes, die Recovery-Datei 63.053.824 Bytes. Grundlage der Durchsatzwerte sind jeweils 512 MiB Quelldaten, einschließlich KDF- und Workflow-Anteilen der betreffenden Phase.

| Phase | Zeit | Quelldaten-Durchsatz |
|---|---:|---:|
| Vorbereitung und initiales Manifest | 0,556 s | |
| Archivierung und Verschlüsselung | 151,716 s | 3,37 MiB/s |
| Recovery-Erstellung | 18,688 s | |
| Recovery-Prüfung | 8,270 s | |
| Recovery-Reparatur | 18,384 s | |
| Entschlüsselung und Extraktion | 118,032 s | 4,34 MiB/s |
| Abschließendes Manifest | 0,261 s | |
| Separat gemessener gesamter Workflow | 315,812 s | |

Die Phasen und die Gesamtzeit stammen aus eigenen Zeitmessungen; ihre gerundete Summe ist nicht die Gesamtzeit. Dies ist eine einzelne Funktionsmessung. Sie liefert keinen vergleichbaren 1-GiB-Benchmark aller Suites oder einen isolierten Camellia-/Cipher-Durchsatz. Wiederholte vergleichbare Messungen am Netzteil bleiben verschoben.

## Signaturen, öffentliche Downloads und Installation

Das Kit wurde mit Developer ID signiert und von Apple akzeptiert. Der separate Scanner-Antrag lautet `70e39545-bd3e-4e35-b44d-6e9a91a61761`; der Kit-Antrag lautet `0cba08fd-06ab-46f3-8dda-c0b48733fd87`. Die Annahme ist an den tatsächlichen Builder und seinen vor dem Stapling eingereichten ZIP-Stand gebunden. Das später gestapelte Veröffentlichungs-ZIP wird nicht als bytegleich mit dem eingereichten ZIP bezeichnet.

Nach lokaler Prüfung und einem Download des neuen Draft-Releases wurden alle sechs veröffentlichten Assets erneut authentifiziert und anonym heruntergeladen. Der öffentliche Lauf vom 12. Oktober 2026, 13:09:26 bis 13:09:59 UTC, besteht mit 261 protokollierten Kommandos. Beide Downloadwege liefern bytegleiche ZIP-, SHA3-, Skein- und Hybrid-Signaturdateien gegenüber dem gebundenen lokalen Asset-Satz. ZIP-Struktur, Extraktion und jeweils 161 Kit-Einträge werden geprüft.

RSA-PSS und ML-DSA-87 werden für die individuellen Hybrid-Payloads auf beiden Architekturen geprüft. Die explizite Abdeckung erfasst alle 21 Mach-O-Dateien: 20 haben individuelle Hybrid-Signaturen; der Apple-signierte Installer-Einstieg ist zusätzlich über das hybride Kit-Inventar gebunden. Dies ist keine Behauptung, ein älterer pauschaler Kit-Verifier habe jeden Pfad eigenständig akzeptiert. Alle drei App-Bundles bestehen außerdem die frischen Apple-Signatur-, Entitlement-, Stapler- und Gatekeeper-Prüfungen.

Der abschließende Installationsabgleich besteht mit 19 protokollierten Kommandos. `/Applications/Keep Vault.app` und `/Applications/QR-Scanner.app` sind in Dateibytes und Namensraum mit dem veröffentlichten Dist-Stand identisch; Version 5.0.3 und Build 21 sind bestätigt. Der reguläre CLI-Installer installiert diese Bundles benutzereigen, beobachtet UID 501 und Bundle-Modus 0700; kein Eintrag ist für Gruppe oder andere Benutzer schreibbar. Die geschützte ZPAQ-Komponente gehört root, hat Modus 0555, schreibgeschützte Begleitdateien und besteht die Hybrid-Prüfung auf beiden Architekturen. Die installierten Apps bestehen erneut Apple-, Ticket- und Gatekeeper-Prüfungen. Dieser Abgleich startet keine reale GUI-Bedienprüfung.

## Erhaltene Fehlernachweise und Veröffentlichungsgrenzen

Der [erste vollständige Durchgang](evidence/v13-build21-complete-suite-failure-20261012/README.md) bleibt als 317 PASS und 2 FAIL erhalten. Seine veraltete Before-Unlock-Fixture und die archivierte `.csproj`-Fixture wurden korrigiert; die [gezielten Korrekturprüfungen](evidence/v13-build21-fixture-corrections-20261012/README.md) bestehen. Der geschlossene Produkt-Getter und die strenge Projektprüfung bleiben erhalten. Der zweite Builder endet wegen `NU1301` bei der DNS-Auflösung von NuGet vor dem Start der vollständigen Suite. Dieser Infrastrukturfehler wird ebenfalls erhalten. Erst der tatsächliche dritte vollständige Builder mit 319 PASS trägt die veröffentlichte Vorabversion.

`v5.0.2` bleibt GitHubs stabile Latest-Version. Identität, Beschreibung, Datums- und Modusfelder sowie Asset-IDs, Namen, Größen und Digests dieser Version und des älteren Build-20-Drafts wurden nach der Veröffentlichung als unverändert geprüft; volatile Downloadzähler sind ausdrücklich ausgenommen. [PR 3](https://github.com/michael-feinermann/keep-vault/pull/3) bleibt Draft. Es wurde keine stabile 5.0.3-Version oder Gesamtfreigabe erteilt.

Noch offen sind der normative `--release`-Lauf mit 49 Phasen, finale Langläufe einschließlich der vergleichbaren 1-GiB-Messungen und verbleibende reale Bedienabnahmen des aktuellen installierten Builds. Windows, reale Mehr-TiB-Läufe und eine externe Sicherheitsprüfung sind nicht Bestandteil dieses Nachweises. Historische GUI- oder Build-20-Belege werden nicht in aktuelle Build-21-Belege umbenannt. v13-Container sind nicht mit dem v12-Format austauschbar.

## Öffentliche Belege

Das [Belegpaket](evidence/v13-build21-published-20261012/README.md) enthält die ausgewählten Original-Receipts, Hash-Manifeste, Kommandoprotokolle und ausdrücklich bezeichneten Ableitungen. Die Kurierung kopiert die dafür aufgeführten Dateien bytegenau; Produkt-/SDK-Binaries, private Signierschlüssel, Wrapping-Schlüssel und Zugangsdaten gehören nicht zum öffentlichen Dokumentationspaket.

| Verzeichnis | Belegumfang |
|---|---|
| `builder/` | Tatsächlicher dritter Builder, Quellbindung, vollständige Resultate, getrennte zweite Netzwerkfehlklassifikation |
| `native/` | Frische ARM64-/x86_64-ABI-Läufe und Bindung an finale signierte Bibliotheken |
| `local/` und `draft/` | Lokale Kit-Prüfung und tatsächlicher Download des neu angelegten Build-21-Drafts |
| `public/` | Authentifizierte und anonyme öffentliche Downloads, vollständige Abdeckung und Apple-Prüfungen |
| `installed/` | Finaler Installationsabgleich einschließlich Eigentum und geschützter ZPAQ-Komponente |
| `administration/` | Veröffentlichung, Asset-Bindungen und Erhalt älterer Releases |

`overallReleaseApproval=false` und `fullReleaseGate=NOT_RUN` bleiben die verbindlichen Grenzen dieses Berichts.
