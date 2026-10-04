# REV12: tatsächliche DragOver-/Acquire-Abschlussprüfung

Finaler fokussierter Managed Build082228: PASS, Exit 0, Quellen vor/nach Build bytegleich. Beide tatsächlichen GUI-Gruppen bestehen frisch. Basis-HEAD: 6bfd2e4d31c3493987083379e898a0b84338a102 mit drei geänderten Code-/Testdateien außerhalb dieses Basiscommits; finale vollständige Sourcekarte SHA-256 `57533b7d826d3950ec03716b86419a9575721d92124fd0cd31afff71b79a576f`.

| Finale Gruppe | Ergebnis | genaue Gruppenzeit (s) | Spitzen-RSS (MiB) | Seed |
|---|---|---:|---:|---|
| gui.rev12-drop-storage-ownership | PASS | 5.0230465 | 372 | 0x58550FAF |
| gui.rev12-storage-transitions | PASS | 0.7468022 | 137 | 0x22301413 |

Die synchronen neun tatsächlichen Hoverhandler verweigern Transfer-/Provider-Path-Fehler mit None/Handled und begrenztem Log ohne Modalitätsflut und ohne Übernahme/Dispose geliehener Items. Tests umfassen wiederholte Fehler, vollständigen Credential-/Preparedentropy-/Fingerprint-/Pfad-/Tab-/Ownererhalt, normale Routen und echten ExtractPanel-/OutputFolder-Hover→Drop. Der Acquire-InFlight-Refguard verhindert die zweite Lease derselben Rawreferenz im nativen Pathcallback; reale Datei-/Ordner-Retain-Calls, Owns/Has, Rawcleanup, Alias, Failure und Close werden geprüft.

Alle sechs Builds mit Metadaten und drei Logs je Build sowie NEUN Runs bleiben bytegleich erhalten: fünf historische Hover-/Fixture-FAILs, zwei frühere Storage-PASSs und zwei finale PASSs. Keine Failureoriginale umgeschrieben. Source-/Fixturediffs und SHA-Karten bleiben getrennt erhalten. Echte Diagnosemarker grenzen fehlendes Show, Dummyfingerprint mit ausstehendem TextChanged und einen doppelten Separator im Prefixoracle ein. Das finale Orakel bewahrt die reale Druckbindung und prüft den strikten kanonischen direkten Parent; ein vorhandenes extract(1) erzwingt ein neues nicht existierendes extract(2).

[Summary](summary.json) bindet Auswahl, Exit, Logmarker, Log-/Result-/Timing-/Sourcehashes und neun Statuswerte. Bei historischen FAILs ist der ursprüngliche Timingkatalog leer; ausschließlich die originalen Resultsekunden werden dort getrennt genannt. [Original Copy Receipt](ORIGINAL_COPY_RECEIPT.json) benennt jede bytegleiche Originalkopie mit SHA-256. SHA256SUMS bindet alle Paketnutzdateien ohne sich selbst. SDK-/Packageinventurhashes und Eintragszahlen stehen in originalen Toolchainkarten. Keine SDK-, DLL- oder privaten Schlüsselkopien. Zusätzliche DLL-Hashkarten in Summary sind ausdrücklich erst bei Publikation NACH allen Läufen aufgenommen; kein ursprünglicher Vor-Lauf-Binarynachweis.

Scope: macOS ARM64, Managed Avalonia-Headless, unveränderte signierte Build15-Natives. PlainURL-Tests zählen tatsächliche native Dispose-Aufrufe, keine echte Security-Scoped-YES-Grant/Stop-Abnahme. Kein neuer Full-PASS und keine finale Build16 Universal-/AOT-/installierte GUI-/Signatur-/Notarisierungs-/Releasefreigabe. Der Paketautor führte keine Builds oder Tests aus.
