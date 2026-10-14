# Keep Vault 5.0.3: Originalreader und Recovery nach REV11

Stand: 1. Oktober 2026. Entwicklungsnachweis für macOS arm64, noch keine Freigabe eines neuen signierten Pakets. Die vorliegenden Tests verwenden reale Einzelquellen bis 32 MiB; die autorisierte Grenze von 256 MiB wird eingehalten. Logische Größenprüfungen sind keine realen TiB-Läufe.

## Eingabevertrag

`VerifiedArchiveInput.BindEncryptedAsync` bindet das Original einmal mit einem sicheren Lesehandle, kanonischem Namen, Objektidentität und erwarteter Länge. Dabei entstehen weder eine Payloadkopie noch eine Indexdatei. Der begrenzte Preflight hält ausschließlich das Header-/Tagabbild. Der vorhandene Containerparser und die unveränderte KDF laufen, bevor der erste vollständige Quellenpass beginnt.

`BeginFusedAuthentication` verbindet den bestehenden globalen MAC-Assembler mit dem neuen physischen Reader. Je physischem 1-MiB-Bereich liest dieser in einen exklusiven gesperrten Puffer und erzeugt genau einen lokalen 204-Byte-Nachweis. Der globale SHA3-/Skein-Transcript erhält dieselben unveränderten Bytes. Header und gespeicherte Globaltags werden gegen das vor der KDF gehaltene Abbild geprüft. Die bisherigen logischen MAC-Blätter, Domainstrings, Headerpräfixe und das Auslassen der gespeicherten Globaltags bleiben unverändert.

Erst nach vollständiger Erfassung, Join, Index-Seal, Längen-/EOF-/Objektprüfung und beiden erfolgreichen globalen Tagvergleichen wird `Verified` veröffentlicht. Parser, Entschlüsselung und ZPAQ erhalten vorher keine normale Leseberechtigung. Der zusätzliche Poly1305-Vertrag der betreffenden Suites bleibt im Containerconsumer bestehen.

Der zweite Pass liest vom selben Original. Vollständige physische Bereiche werden lokal doppelt authentifiziert, bevor ein Slice dieses Puffers ausgegeben wird. Kurze aufeinanderfolgende Reads nutzen eine bereits geprüfte eigene unveränderliche Pufferlease, damit etwa 64-KiB-Teilreads denselben 1-MiB-Bereich nicht mehrfach physisch lesen. Auch solche Cachezugriffe prüfen Quellenbindung, Länge und gespeicherten Record. Ein neuer Bereich ersetzt den Puffer erst während exklusiver Ausleihe. Fehler löschen die gesamte angeforderte Ausgabespanne und sperren den Reader. Dispose widerruft neue Leser, joint bereits aktive Reads und löscht die vollständigen Pufferkapazitäten sowie alle lokalen Schlüssel.

Der konservative kopiefreie Dreipassweg bleibt ausschließlich als Vergleich und lokale Plain-/Repair-Erfassung vorhanden. Normales verschlüsseltes Öffnen und authentifizierte KPAR2-Erstellung verwenden den kombinierten ersten Pass.

## Identischer RAM-/Dateiindex

`AuthenticatedRangeIndex` speichert bereits erstellte Records unverändert. Die temporären lokalen Schlüssel und die Operations-ID gehören zum gesperrten Readerkontext, nicht zum Index. Segmentierte RAM-Ablage wächst nach tatsächlichem Bedarf. Sämtliche verschachtelten Recovery- und Range-Tabellen teilen über den Operationkontext das anfängliche 16-MiB-Fenster. Verwaltungsbedarf wird zusätzlich in der Schwellenberechnung berücksichtigt.

Bei bekanntem Indexbedarf wird einschließlich Segmentverwaltung vorab entschieden, ob RAM ausreicht. Eine spätere Migration kopiert ausschließlich die vorhandenen Records, niemals neue Quellenbytes. Erst nach vollständigem Schreiben und Längenprüfung wird der Dateibesitzer übernommen; anschließend werden die alten RAM-Segmente gelöscht und ihre Leases freigegeben. Ein fehlerhafter Wechsel sperrt die Operation. Die private Datei wird objektgebunden erstellt, früh entlinkt und nach dem Join auf den vorbereiteten echten Nur-Lesehandle umgestellt. Ein vom Angreifer zuvor geöffneter Schreibhandle bleibt durch die MAC-Prüfung abgedeckt.

Solange RAM genügt, wird das konfigurierte Arbeitsverzeichnis weder angelegt noch geöffnet oder auf freien Platz geprüft. Beim Spill bindet `ReserveWorkingWrite` das tatsächliche Arbeitsvolume. Ein explizit fehlendes oder ungeeignetes Volume führt zum Fehler, ohne Ersatzpfad. `ReserveOutputWrite` ist hierfür ausdrücklich nicht geeignet, da Ausgabe- und Arbeitsvolume verschieden sein dürfen.

## Recovery und Berechtigungen

`CaptureForRepairAsync` erzeugt eine ausschließlich lokale Ciphertextbefugnis. Ein kaputter Containerheader und ungültige globale Container-MACs verhindern diesen streng begrenzten Erfassungspfad nicht. `RepairCiphertextRead` kann den Besitzer weder zum Plainconsumer noch zum global verifizierten Reader befördern. Bootstrap, Locator, kanonisches Manifest, Credential-KDF und Zertifizierung behalten ihre bisherigen Prüfungen.

Für tatsächlich unlesbare Quellblöcke hält der Repairpfad die bereits beim ersten Lesen festgestellten 4096-Byte-Erasures in einer gesonderten doppelt authentifizierten Tabelle fest. Nur diese eingefrorenen Positionen werden beim geschützten Wiederlesen durch dieselben Nullbytes ersetzt. Spätere Lesefehler erweitern die Maske nicht und erzeugen keine neuen erwarteten Tags. Diese lokale Erasurebefugnis ist keine Authentizitätsaussage. Der separate reparierte Kandidat wird neu gebunden und vollständig durch beide globalen Container-MACs sowie die zertifizierten Gesamtdigests geprüft, bevor er veröffentlicht werden kann.

`RecoveryRecordTable` und `RecoveryMetadataStream` verwenden RAM-first-Ablage. Die bestehenden festen Recordformate und kanonischen KPAR2-v4-Bytes bleiben erhalten. Shardfenster, Kandidaten-Kopierpuffer, Pending-/Cachepuffer und temporäre Metadatenkopien erhalten konkrete RAM-Leases vor der Allokation. Cleanup löscht Puffer vor Freigabe; fehlgeschlagene Recordtabellen-Konstruktionen behalten ihren Besitzer für einen späteren Cleanupversuch. Primär- und Cleanupfehler bleiben gemeinsam sichtbar.

Ausgabeschritte reservieren die tatsächlich bevorstehenden Schreibbytes im gemeinsamen Volume-Ledger. Sequentielle Recoverywrites verwenden explizite Dateioffsets, damit die Reservierung nicht endet, während die Daten nur im verwalteten FileStream-Puffer liegen. Copyjobs werden nach I/O-Bedarf begrenzt und halten beim Warten keine CPU-Leases. Auch ausgelagerte Metadatennachweise werden vor dem Start eines CPU-Hashteams gelesen. Die vorhandenen RS(20,3)-Breiten, Schutzquote und Zertifizierungsregeln werden nicht reduziert.

## Aktive Aufrufer

- Containerentschlüsselung und authentifizierte KPAR2-Erstellung binden den Originalreader und nutzen die kombinierte globale Verifizierung.
- Plain-Archive verwenden denselben Bereichsschutz, veröffentlichen aber den getrennten Status `PlainIntegrityVerified`. Die `.sha3`-/`.skein`-Dateien bleiben Fehlererkennung ohne Absenderauthentizität.
- `ArchiveIntegrityLease.ServeVerifiedReadAtAsync` ist auf beiden Plattformen verfügbar. Native ZPAQ-Consumer erhalten nur den geschützten Parent-Read-at-Vertrag.
- Die Erstellungs-Readiness wird erst nach KDF-Abschluss signalisiert; die Entpack-Readiness erst nach beiden globalen MACs. Die verzögerten Childstreams liegen im ZPAQ-Implementierungsbereich.
- Produktionsreferenzen auf `MacPrivateFileSnapshot.Capture` und `MacRecoveryReadLease` sind entfernt. Die alten Mac-/WindowsInputSnapshot-Erzeuger verbleiben ausschließlich als historische Testseams; die normalen ZPAQ-Aufrufer verwenden den neuen gebundenen Quellenkatalog.

Beim Abschlussreview wurde eine zusätzliche Grenze im automatischen Original-Löschen gefunden: Die GUI erfasste die Originalidentität bisher erst beim späteren Vergleich. Ein bytegleich ausgetauschtes Objekt nach erfolgreicher Erstellung hätte damit eine neue Löschfreigabe erhalten können. Der gesonderte GUI-/Deletion-Arbeitsbereich hat einen vor Erstellung gebundenen `CreationSnapshot` ergänzt. Sein enger Test `deletion.rev11-creation-binding` und vier bestehende Löschgruppen bestanden laut `work/v13-evidence/rev11-resources/deletion-all-results.json`. Auch der abschließende Build6-Lauf bestand alle fünf Löschgruppen, einschließlich Rename-/Unlink-Austausch und Änderung desselben Quarantäne-Inodes bei wiederhergestellter mtime. Seine gesonderten Nachweise stehen in `work/v13-evidence/rev11-resources/deletion-final-results.json` und `deletion-final-hashes.json`.

## Nachweise und Grenzen

Die Builds verwenden den separat verifizierten Microsoft-SDK 10.0.400 und unveränderte gepinnte Restore-Locks. Tests laufen aus privaten Kopien der Managed-Artefakte. Native Kryptokomponenten stammen unverändert aus dem vorhandenen signierten installierten Paket und wurden mit dem bestehenden `Stage-TestNatives-macOS.sh`-Vertrag übernommen. Diese Readernachweise sind deshalb kein Nachweis der parallel geänderten nativen ZPAQ-Control-Implementierung, keines neuen Installers und keines neuen notarisierten Pakets. Windows ist hier quellenintegriert, nicht ausgeführt.

Primärer Evidenzordner: `work/v13-evidence/rev11-development/`. Jede Gruppe verwendet `--full --no-smoke --only <exakte ID> --parallel 1 --seed 0x5EED0313`. Logs und originale Ergebnis-/Zeit-JSONs wurden direkt nach jeder Gruppe gesichert. Die `binaries.json` in den jeweiligen Unterordnern hält die konkreten SHA-256-Werte aller 127 Stage-Dateien fest. `io-sixth-build/source-files.json` bindet die betroffenen Reader-/Recoveryquellen, relevanten gemeinsamen Policies und Tests per SHA-256. Sein HEAD ist ausdrücklich der Basiscommit des noch nicht eingecheckten Entwicklungsstands, kein vorgetäuschter Releasecommit.

| Stand | Beleg | Ergebnis |
|---|---|---|
| Erster Readerbuild | `io-first-build/` | Neue 5 Readergruppen PASS; 3 überholte Legacy-Fixtures sichtbar erhalten |
| Build3 | `build-io-third.log`, `io-third-build/` | Build ohne Warnungen/Fehler; 21/22 Gruppen PASS, 5 Fuzzgruppen mit jeweils 10.000 Fällen PASS |
| Build4 | `build-io-fourth.log`, `io-fourth-build/` | Build ohne Warnungen/Fehler; 38/39 Gruppen PASS; alle 20 Readergruppen und alle 5 Fuzzgruppen PASS |
| Build5: Recovery-Abschluss | `build-io-fifth-final.log`, `io-fifth-build/` | Build ohne Warnungen/Fehler; alle 32 Gruppen PASS, einschließlich 12 suitebezogener Recoverygruppen, KPAR2-Angriffsmatrix und Container-Workervergleich aller 12 Suites |
| Build6: eingefrorener Produktstand | `build-io-sixth-final.log`, `io-sixth-build/` | Build ohne Warnungen/Fehler; alle 35 gezielten Reader-/Recovery-/Containergruppen PASS; zusätzlich Companion-Build15-Smoke im korrigierten Einzelaufruf PASS |

Der einzelne Fehler im Build4 betraf `ComputeParityForWorkerEquivalenceTests`: Ein neuer Scratchowner löschte die zurückgegebene Testarray-Referenz beim Scopeende. Der Testhelper gibt jetzt eine explizite Ergebnis-Kopie zurück. Die Produktionsfenster verlassen ihren Owner nicht. Ablehnungs- oder Gleichheitsassertions wurden nicht gelockert; der konkrete Rerun bestand in Build5. Die erweiterte Cleanupgruppe bestätigt außerdem, dass ein fehlschlagender Recordtabellen-Unlock weder die Freigabe bereits gelöschter Stream-Pending-/Cachepuffer verhindert noch eine erneute Verwendung nach fehlgeschlagenem Schreiben/Seal erlaubt.

Die Readernachweise umfassen feste öffentliche Schlüssel/Operations-IDs mit exakt gleichen 204-Byte-Records in RAM und Datei bei einem und zwei zugelassenen Workern, die reale 16-MiB-Cachegrenze einschließlich Verwaltung ±1 Byte, Header-/Globaltagwechsel zwischen Preflight und Vollpass, zwei vollständig verschiedene globale MAC-Ablehnungen, fremde Writer, Index-/Quellenmutation, Private-Buffer-Slices, Range-/Längenüberläufe, Cancel, Cleanup-Retry und getrennte Repair-Erasures. Fragmentierte sequentielle Ausgabe weist über instrumentierte tatsächliche Range-Reads exakt einmal die Quellenlänge als zweiten physischen Pass nach; der kleine begrenzte Preflight und EOF-Probes werden separat behandelt.

Die fünf Fuzztargets sind `fuzz.rev11-original-reader-10000`, `fuzz.rev11-range-index-10000`, `fuzz.verified-input-10000`, `fuzz.recovery-streaming-10000` und `fuzz.verified-read-at-server-10000`. Ihre Seeds sind deterministisch aus dem protokollierten Hauptseed und einer Targetspezifik abgeleitet. Die Fälle variieren Daten, Längen, Positionen, Modi und Mutationen; eine weltweite Einzigartigkeit sämtlicher kurzen Framingbytes wird nicht behauptet. Es handelt sich um verwaltete Entwicklungsprüfungen, nicht um einen neuen nativen Sanitizerlauf oder einen großen Datenträgerbenchmark.

Build5 bewahrt jede der 32 Einzelgruppen samt Original-JSON und Laufzeit. Die Summe der Harnesslaufzeiten beträgt 206,636 Sekunden; dies ist keine Leistungsbenchmarktabelle. Die 12 Recovery-Suitefälle verwenden jeweils 64 KiB Payload und die unveränderten Produktions-KDF-Profile, einschließlich beider Paranoia-Runden. Der deterministische 12-Suite-Containerworker-Vergleich verwendet ausdrücklich den bestehenden 8-MiB-Test-KDF-Override; er vergleicht einen Einworker-Testoverride mit der tatsächlich aufgelösten Produktplanung und belegt Bytegleichheit sowie Ablehnung ohne Klartextausgabe, nicht Produktions-KDF-Performance oder eine Mindestzahl gleichzeitig rechnender Worker. Alle Gruppen liefen mit dem protokollierten Seed `0x5EED0313`.

Der letzte Produkt-Hunk vor Build6 legt die Kapazität der Reader-Leasebesitzerliste vor dem ersten RAM-Erwerb an. So kann ein Listwachstumsfehler keinen bereits zugelassenen Charge ohne erreichbaren Cleanupbesitzer hinterlassen. Danach wurden alle 20 Readergruppen, 14 Recovery-Metadaten-/I/O-Gruppen und der 12-Suite-Containervergleich erneut ausgeführt und bestanden. Die fünf Fuzzgruppen bleiben mit jeweils 10.000 PASS-Fällen aus Build4, der Recovery-Streamingfuzz zusätzlich aus Build5, erhalten.

Der zusätzliche `smoke.release-companion-version` wurde zunächst versehentlich mit `--no-smoke` ausgeschlossen: Exit64 ohne Testausführung. Log, Selektionsdiagnose und irrtümlich kopierte vorherige Resultate sind ausdrücklich als `stale-previous-group` erhalten. Der korrekte Aufruf ohne `--no-smoke`, weiterhin mit exakt derselben ID und Seed, bestand unter `io-sixth-build/smoke-rerun/`. Kein Testfilter und keine Produktprüfung wurden abgeschwächt.

Zum Abschluss dieses Arbeitsbereichs sind die Reader-/Recovery-Produktquellen eingefroren. Es gibt keinen offenen Fehler aus diesen gezielten Tests. Der vollständige neue signierte Release-, native ZPAQ-, installierte GUI- und Paketnachweis bleibt Aufgabe des anschließenden Gesamtlaufs.
