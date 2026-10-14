# Keep Vault 5.0.3: Vorabprüfung, Entwurfsbindung und Einmalverbrauch (REV12)

Stand: 3. Oktober 2026. Grundlage: Abschnitt 9.7 und Gates 8.12 aus `KEEPVAULT_5.0.3_V13_CODEX_GESAMTUEBERARBEITUNG_REV12.md`. Dieser Bericht dokumentiert Quelländerungen und den vorgesehenen Nachweisumfang; er ist keine Freigabe des macOS-Pakets und kein Windows-Ausführungsnachweis.

## Befunde und Korrekturen

1. Der macOS-Erstellungshandler löschte im `finally` sämtliche Passwort-, PIN- und Faktorwerte sowie das vorbereitete Entropieobjekt. Das galt auch für fehlende Eingaben, fehlende Schlüsselzettelfreigabe, vorhandene Ziele und einen abgebrochenen Zugriffsdialog. Erstellung, Extract, List und Recovery führen nun eine eigene `ArchiveOperationLifetime`. Erwartete Vorabverweigerungen haben einen typisierten `ArchivePreflightReason`; sie bleiben korrigierbar. Ein UI-Gate gilt ausdrücklich nicht als Verbrauchsbeweis. Die Freigabe des Gates und das Dispose tatsächlich erworbener temporärer Ressourcen bleiben in `finally`.
2. `GeneratedArchiveEntropy.HasPendingEncryptionParameters` verlangte auch bei einem `SingleRound`-Ergebnis die zweite Salt-/Nonce-Paarung. Damit konnte ein gültig vorbereiteter Standard-Satz nach bereits erfolgtem Poolcleanup als nicht verfügbar erscheinen. Der Status bildet jetzt unverbrauchten Besitz der ersten Paarung ab. Eine getrennte, lesende `ValidateForEncryption` prüft die tatsächliche Suite, gegebenenfalls die zweite Paarung und die beiden Faktorbytes, ohne Pools erneut zu mischen oder Parameter zu entnehmen.
3. Das vorbereitete Entropieobjekt speichert `ConsumptionStarted` unter demselben Lock, der die Parameter überträgt. Das irreversibel gesetzte Bit verhindert jeden erneuten Consume, einschließlich eines Fehlers beim Bereinigen der nicht benötigten zweiten Paarung. Die Operationslebensdauer wird an derselben Grenze benachrichtigt. Es gibt kein Zurücksetzen auf Pending, keinen Rücktransfer und keine UI-Sicherheitskopie. Bei direkter Generierung ohne vorbereitetes Objekt markiert der Dienst den möglichen Verbrauch vor dem destruktiven Mixer-Aufruf konservativ als begonnen.
4. Der Dienst reserviert die private `BoundFileTransaction.CreateNew` jetzt vor der Parameterentnahme. Ein fehlgeschlagenes exklusives Öffnen kann deshalb nachweislich vor Verbrauch verweigern. Nach Reservierung wird der finale Name erneut geprüft. Ein dort entstandenes Fremdobjekt bleibt unangetastet; der eigene Part wird über seine gebundene Identität entfernt. Die spätere Veröffentlichung nutzt weiterhin `RenameTo(..., overwrite: false)`. Eine erst beim Commit sichtbare Kollision bleibt ein Fehler nach Verbrauch.
5. Pfad-/Suite-Ereignisse setzten den Schlüsselzettelstatus pauschal zurück. Die Bindung wird nun anhand des bestehenden Pfad-/Suite-/Faktor-Fingerprints geprüft. Ein identischer kanonischer Pfad, reine Faktorformatierung und eine unveränderte Auswahl nach DE/EN-Neubefüllung erhalten die gültige Freigabe. Echte Pfad-, Suite- oder Faktoränderungen invalidieren die Freigabe, ohne Passwort, PIN oder Faktoren zu leeren. Während des kontrollierten Leerens wird kein neuer Fingerprint aus den gerade zu löschenden Feldern aufgebaut.
6. Print und Save erhalten einen Operationsbesitzer. Eine monotone Entwurfsrevision und der semantische Fingerprint werden vor Ausgabe und vor Freigabe geprüft. Ein alter asynchroner Druck-/Speicherdialog kann keinen inzwischen geänderten Entwurf bestätigen. Das gilt auch für eine Rückkehr zu früheren Werten nach einer zwischenzeitlichen Änderung. Abbruch und fehlender Drucker löschen keinen Entwurf.
7. Ein vorhandenes Verzeichnis mit einem unterstützten Archivsuffix wird bei der Zielnormalisierung nicht mehr still als Zielordner mit einem neuen Unterpfad behandelt. Die gewöhnliche Auswahl eines Zielordners ohne Archivsuffix bleibt möglich; der vorhandene tatsächliche Archivzielname wird als Kollision geprüft.

## Besitz- und Cleanupentscheidungen

| Grenze | Verhalten |
|---|---|
| Fehlende Quelle, Ziel, Bestätigung, Ressourcenentscheidung oder Schlüsselzettel | Typisierte Vorabwarnung, editierbare Werte und unverbrauchte Vorbereitung bleiben erhalten. |
| Abgebrochener Pfad-/Berechtigungs-/Schlüsselzetteldialog | Temporäre Dialog-/Zugriffsressourcen freigeben, Gate beenden, unverbrauchten Entwurf erhalten. |
| Reservierung oder früh erkennbare Kollision vor Consume | Eigenen Part gebunden bereinigen; fremdes Objekt erhalten; denselben Satz weiter nutzen können. |
| Tatsächliche Entnahme, auch wenn der aufrufende Dienst später wirft | Irreversibel verbraucht; vorgesehene Geheimwertbereinigung nach den letzten Lesern; bewusste neue Vorbereitung erforderlich. |
| Erfolgreiche Erstellung | Credentialcleanup bleibt nach Recovery und gegebenenfalls Originalvergleich und Veröffentlichung. |
| Extract/List/Recovery haben kryptografische Arbeit begonnen | Bestehendes Cleanup bei Erfolg, echtem Fehler und Cancel bleibt aktiv. Automatische Reparaturpfade melden ihren Arbeitsbeginn an denselben Besitzer. |
| Unbekannter Fehler, Trust-/Integritäts-/Kryptofehler oder unklare Fehlerlage | Fail-closed; nicht als gewöhnliche Warnung ausgeben; bestehende Geheimwertbereinigung und Originalschutz erhalten. |
| Explizites Leeren, neue bestätigte Vorbereitung, kontrolliertes Beenden | Eigentümergezieltes Dispose und Nullung; keine Rekonstruktion verbrauchter Pools und kein Löschen einer fremden Liveepoche. |

Temporäre Factor-Validierungen verwenden den gemeinsamen Parser mit gesperrten Puffern und bestehendem `ZeroAndDisposeAllPreservingFailure`. Vorabwarnungen loggen keine Credentialwerte. Der produktive Code erzeugt keine dauerhaften Sicherungskopien des Entwurfs. UI-Strings und Kopien im Framework/GC können weiterhin nicht nachträglich garantiert physisch gelöscht werden. Gegen Prozessabsturz, Kernelkompromittierung oder Speicherabgriff entsteht keine neue Garantie.

## Geprüfte Aufrufer und Plattformgrenzen

- macOS: Create, Extract, List, EmergencyRecovery, automatische Verify/Repair- und Retrypfade, Generate, Print, Test-PDF-Save, explizites Leeren und Dispose. Der bestehende doppelte Gateversuch besitzt keine Cleanupbefugnis über den ersten Vorgang.
- Windows: dieselben konkreten Erstellung-, Extract-, List-, Recovery-, Print-/Save- und automatischen Reparaturpfade im WPF-Code wurden passend korrigiert. Die vorhandene pauschale Großschreibung des Pfades für die Druckbindung wurde entfernt; semantische Vergleiche erfinden keine neue allgemeine Fallnormalisierung für möglicherweise case-sensitive Verzeichnisse.
- Gemeinsamer Kern: ausschließlich Besitz-/Lebensdauer- und Outputreservierungsreihenfolge. KDF-Inputs, Argon2id-Parameter, Suite-/Nonce-/MAC-/Framingverträge, Cipherstufen, Faktor-/QR-Nutzdaten und Sicherheitsprüfungen bleiben unverändert.
- Windows wird in diesem Durchgang auf ausdrücklichen Nutzerwunsch nicht ausgeführt. Ein Quellreview oder macOS-Headlesslauf ersetzt keinen tatsächlichen WPF-Dialog-, Paste- und Layoutnachweis.

## Tests und Status

Neue Tests in `KeepVaultMac.Tests/PreflightLifetimeRev12Tests.cs`:

| Harness-ID | Nachweis |
|---|---|
| `gui.rev12-preflight-state` | Echter Avalonia-Buttonpfad für fehlenden Schlüsselzettel und bestehendes Dateiziel, unveränderter vollständiger synthetischer Entwurf, identischer vorbereiteter Besitzer, kein Consume/KDF, DE/EN und identische Pfadbindung, echte Pfadänderung, verzögerte Warnung und Zweitklick mit neuerer Eingabe, freigegebene Controls, Original-/Fremddateierhalt, Log-Privacy. |
| `gui.rev12-extract-preflight` | Extract-/List-/Recovery-Buttonpfade mit fehlender Eingabe erhalten die vier Credentialfelder und geben den Gatebesitz frei. |
| `entropy.rev12-consume-boundary` | Single-/DualRound read-only Prüfung, Faktorenverwechslung ohne Verbrauch, Fehler unmittelbar nach atomarem Handoff, irreversibler Verbrauch vor Rückkehr, kein weiterer Consume, freigegebene gesperrte Speicherallokationen. |
| `container.rev12-preflight-race` | Ziel entsteht nach Partreservierung vor Consume: unverbraucht, eigenes Partcleanup, Fremdobjekt erhalten. Ziel entsteht beim ersten Payload-Read nach KDF: spätere Commitkollision, nachweislich verbraucht, kein Wiederverwenden und unverändertes Fremdobjekt. Produktionseinstellungen für die KDF werden nicht abgeschwächt. |

Die bisherigen Tests für unbekannte adversarielle Handlerfehler bleiben bestehen und verlangen weiterhin sicheres Leeren. Sie unterscheiden sich von den neuen erwarteten Vorabwarnungen. Die Logbelege berücksichtigen die neue gebündelte Konsolenanzeige durch expliziten Flush im Test.

Status bei Übergabe an die Integration: Quelländerungen und Tests implementiert; `git diff --check` ohne Befund. Noch kein neuer Build oder Testlauf durch diesen Teilauftrag, da die laufende Leistungsreferenz keine konkurrierende CPU-/Speicherlast erhalten soll. Die Integration muss die vier neuen Tests und relevante bestehende Cleanup-/KAT-/GUI-Gates ausführen und Ergebnisse hier ergänzen. Der echte macOS-Bedienablauf mit Drucken/Test-PDF-Picker, Warnungsbestätigung, Berechtigungsdialog, Pfadkorrektur und einmaliger erfolgreicher Erstellung ist weiterhin eine eigene Pflichtprüfung der final installierten Bytes.
