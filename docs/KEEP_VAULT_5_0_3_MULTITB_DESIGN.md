# Keep Vault 5.0.3: Originalzugriff und bedarfsgerechte Ressourcen

Stand: 1. Oktober 2026, Umsetzung nach Revision 11. Diese aktuelle Designbeschreibung ersetzt die früheren REV9-Beschreibungen von Vollspools, pauschalen Maximalreservierungen und Archivdeadlines. Frühere Laufprotokolle und Paketnachweise bleiben historische Belege ihres jeweiligen Quellstands. Der aktuelle Auftrag betrifft macOS; reale Tests sind auf Einzelquellen bis 256 MiB begrenzt. Eine ältere ausdrücklich autorisierte 512-MiB-Paranoia-Prüfung ist kein allgemeiner neuer Größenauftrag. Weder Rechenwerte noch kleine reale Tests belegen praktisch verarbeitete TiB-Datenmengen.

## Gebundenes Original, zwei vollständige Quellenpässe

`VerifiedArchiveInput` öffnet einmal das Original, hält einen sicheren Lesehandle und bindet kanonischen Namen, Objektidentität sowie erwartete Länge. Der begrenzte Containerpreflight prüft Magic, Headerlänge, Suite und Struktur. Aus dem eingefrorenen Header werden die unveränderten KDF-Rollen abgeleitet, bevor ein vollständiger Quellenpass startet.

Der erste vollständige Pass liest physische Bereiche von 1.048.576 Byte in exklusive gesperrte Puffer. Diese Bytes speisen sowohl die lokalen Bereichsnachweise als auch den unveränderten logischen SHA3-/Skein-MAC-Transcript. Header und gespeicherte Globaltags werden dabei erneut gegen das vor der KDF gehaltene Abbild geprüft. Physische Rangegrenzen werden nicht mit logischen globalen MAC-Blattgrenzen gleichgesetzt. Beide globalen Tags, vollständige Rangezahl, Länge, EOF und Quellenbindung müssen bestehen, bevor normale Konsumenten lesen dürfen.

Der zweite Quellenpass liest wieder vom selben Objekt, prüft beide lokalen Tags des vollständigen Bereichs und gibt ausschließlich Slices genau dieser privaten Pufferinstanz frei. Ein Cachetreffer benötigt eine eigene unveränderliche verifizierte Pufferlease. Quellenbindung, Indexposition und gespeicherter Record bleiben auch dann geprüft. Fragmentierte sequentielle Reads müssen dadurch nicht denselben Range immer neu vom Datenträger lesen. AEAD-Chunktags bleiben zusätzlich vor der jeweiligen Klartextfreigabe verbindlich.

```text
BOUND_UNTRUSTED
  -> PREFLIGHT_BOUNDED_HEADER + unveränderte KDF
  -> INDEXING_AND_GLOBAL_VERIFY
  -> VERIFIED
  -> CONSUMING_VERIFIED_BYTES
  -> JOIN / WIPE / CLOSED

separat: lokale Erfassung -> LOCAL_CAPTURE_SEALED
  -> REPAIR_CIPHERTEXT_ONLY -> eigener Kandidat -> neue Vollverifizierung
```

Fehler sperren den Kontext. Cancel/Dispose widerruft neue Arbeit, joint bereits gestartete Leser und löscht sämtliche sensitiven Pufferkapazitäten und Schlüssel vor Freigabe. Ein Cleanupfehler erhält seinen Besitzer für Retry. Eine geänderte, ausgetauschte, verkürzte oder verschwundene Quelle führt zum sicheren Fehler; der Vertrag verspricht keine universelle Momentaufnahme weiterlaufender Dateien.

## Unveränderte Bereichsnachweise

Für jeden erwarteten Index `i` und seine aus der geschützten Gesamtlänge berechnete Nutzlänge `n_i` gilt:

```text
M_i = OperationId[32] || BE64(i) || BE32(n_i) || capturedBytes_i
T_H = HMAC-SHA3-512(K_H, LP_LE32(D_H) || M_i)            // 64 Byte
T_S = Skein-MAC-1024-1024(K_S, pers=D_S, msg=M_i)        // 128 Byte
Record_i = BE64(i) || BE32(n_i) || T_H || T_S            // 204 Byte
D_H = Kalyna-ZPAQ/v13/VerifiedArchiveInput/HMAC-SHA3-512
D_S = Kalyna-ZPAQ/v13/VerifiedArchiveInput/Skein-MAC-1024-1024
```

Operations-ID und beide lokalen Schlüssel entstehen je Kontext frisch aus dem OS-CSPRNG. Sie liegen ausschließlich im vorgesehenen gesperrten RAM. Jeder Record bindet genau eine erfasste Byteversion. Retry mit einer anderen Quellenversion benötigt einen neuen Kontext. Erwartete Offsets, Längen und Allokationen stammen nicht aus untrusted Indexfeldern.

## RAM-first-Index und bedarfsabhängiges Arbeitsvolume

`AuthenticatedRangeIndex` hat segmentierte RAM-Ablage und eine private Datei als zwei Speicherbackends desselben Recordvertrags. Sämtliche verschachtelten Range-/Recoverytabellen teilen das anfängliche 16-MiB-Cacheziel. Es werden nur tatsächlich benötigte Segmente allokiert; Verwaltungsbedarf zählt zusätzlich. Bekannte Indexlänge und aktuelle Ressourcen bestimmen den Weg vor dem Vollpass. Ein notwendiger Wechsel kopiert bereits vorhandene Records in begrenzten Fenstern, ohne die Quelle erneut zu lesen oder Tags neu auszustellen. Erst die vollständig geschriebene und geprüfte Datei wird übernommen.

Die reine Indexarithmetik lautet `q = length / RangeBytes + (length % RangeBytes != 0 ? 1 : 0)` und `checked(q * 204)`:

| Physische Datei | Recordbytes ohne Verwaltung |
|---|---:|
| 10 MiB | 2.040 |
| 1 GiB | 208.896 |
| 100 GiB | 20.889.600 |
| 1 TiB | 213.909.504 |
| 4 TiB | 855.638.016, genau 816 MiB |
| 64 TiB | 13.690.208.256, genau 12,75 GiB |

Das sind Rechenwerte. Ein Container mit 64 TiB Payload ist wegen Header und Tags physisch größer. Die unabhängige kryptographische Nutzungsgrenze wird durch Auto, RAM- oder Volumefreigaben nicht erhöht.

Wenn RAM genügt, wird das gespeicherte Arbeitsverzeichnis nicht geöffnet, erstellt oder nach Freiplatz gefragt. Ein derzeit nicht benötigter fehlender Pfad blockiert keine kleine Operation. Wird Spill nötig, gilt das ausdrücklich autorisierte Arbeitsvolume. `ReserveWorkingWrite` prüft dessen tatsächlich gebundenen Descriptor und die konkreten zusätzlichen Bytes. Ein fehlendes oder ungeeignetes Volume bewirkt eine sichere Absage, keinen stillen Ersatzpfad.

macOS bindet für einen Dateiindex bereits vor dem frühen Unlink einen echten `O_RDONLY`-Handle am gehaltenen Elternverzeichnis. No-Symlink-, Regular-/Single-Link- und Identitätsprüfungen sichern die Bindung. Nach Join und Flush schließt `SealReadOnly` den eigenen Schreibhandle und übernimmt den vorbereiteten Lesehandle. Bereits vorhandene fremde Writer erhalten dadurch keine gültigen MACs für neue Records. Bei Ende erfolgt die objektgebundene Bereinigung. Das Windows-Gegenstück reduziert die Handleberechtigung; der aktuelle Laufnachweis ist macOS.

## Plain-ZPAQ und native Verbraucher

`ArchiveIntegrityService` verarbeitet Plain-Archive über den gleichen Original-/Rangevertrag und vergleicht beide vorhandenen unkeyed Sidecars. Der Status heißt getrennt `PlainIntegrityVerified`; dies ist Fehlererkennung ohne Absenderauthentizität. Normales `.zpaq` bleibt unterstützt.

Der native Parser erhält ausschließlich begrenzte Antworten des Duplex-Read-at-Protokolls `KV13RA`, mit geprüften 64-Bit-Offsets und höchstens 1 MiB pro Anfrage. Der Parent gibt nur bereits geprüfte private Slices zurück. Weder ein ungeprüfter Archivpfad noch ein Raw-FD oder eine gesamte Klartext-/SHM-Kopie ersetzt diesen Vertrag. Der verschlüsselte Pipepfad behält `KVP13ZP1` und seine bisherigen Framegrenzen.

Normale Erstellung bindet Quelldateien und Metadaten über `ZpaqBoundSources`. Die historischen vollständigen Mac-/WindowsInputSnapshot-Erzeuger bleiben nur in Testseams erreichbar. `MacPrivateFileSnapshot.Capture` und `MacRecoveryReadLease` haben keine aktiven normalen Produktionscaller. Die Erstellungs-KDF endet vor Zulassung schwerer nativer Kompressionsmodelle. Beim Entpacken startet der native Verbraucher erst nach beiden globalen MACs. Der neue native Quellen-/Controlvertrag und dessen Nachweise werden gesondert im ZPAQ-Arbeitsbereich dokumentiert.

## KPAR2-v4

RS(20,3), Shardbreiten, Metadatenblocklayout, Locator-Konsens, kanonische JSON-Reihenfolge und doppelte Zertifizierung bleiben erhalten. `RecoveryManifestCodec` verarbeitet bounded Tokenfenster und vergleicht die kanonische Darstellung inkrementell, ohne eine vollständige JSON-Allokation. `RecoveryRecordTable` und `RecoveryMetadataStream` verwenden nun denselben RAM-first-Speicherweg. Kleine Sidecars benötigen keine Arbeitsdatei.

Typisierte feste Records authentifizieren Operations-ID, Index, Typ, Nutzlänge und vollständigen Inhalt mit eigenen flüchtigen gesperrten Schlüsseln. Digesttexte bleiben exakt `Base64(SHA3[64]) + ":" + Base64(Skein[128])`. Metadatenströme enthalten höchstens 64 KiB Nutzdaten pro Record; alle gleichzeitig lebenden Tabellen und Bereiche zählen im gemeinsamen Metadatenbudget. Die vorgesehene öffentliche KPAR2-Metadatenstruktur wird dadurch nicht zu einem neuen Format.

Eine beschädigte Quelle benötigt zunächst nur die getrennte lokale Repairbefugnis. Bereits bei Capture tatsächlich unlesbare 4096-Byte-Blöcke werden als eingefrorene, doppelt authentifizierte Erasures geführt. Spätere Fehler dürfen diese Maske nicht erweitern. Bootstrap/Locator/Manifest, Credentials und Sidecar-Zertifizierung behalten ihren bisherigen strengen Vertrag. Ein reparierter eigener Kandidat erhält anschließend einen neuen Originalreader und muss beide globalen Container-MACs sowie die zertifizierten Archivdigests bestehen. Die suiteabhängige KDF bleibt eine beziehungsweise zwei vollständige Masterrunden.

Die Sidecarschätzung folgt der tatsächlichen Archiv-/Headerlänge, den Teilstripes, Locatorblöcken und Metadaten. Der endgültige Umfang wird beim Schreiben begrenzt. Ein tatsächlich benötigter Reparaturkandidat kann annähernd Archivgröße haben und wird als solcher geplant. Das beschädigte Original bleibt bis zum erfolgreichen Abschluss unverändert.

## Ressourcen ohne Phantomreservierungen oder Archivdeadline

`ResourcePreferences`, aufgelöster Phasenplan und tatsächliche Belegung sind getrennt. CPU-/RAM-/I/O-/Queue-Auto bleibt über Policykopie und Persistenz erhalten. Ein manuelles Rechenlimit von eins ist zulässig. Es besteht keine pauschale Gesamtgrenze von 64 Workern; aktuelle Topologie, Arbeit, Druck und explizite Benutzerlimits begrenzen die konkreten Grants.

Ein kleiner Auftrag startet mit einem kleinen tatsächlichen Pufferfenster. Chunkbuffer wachsen erst bei wirklicher Eingabe; EOF und kurze Reads bleiben korrekt. Größenmaxima reservieren weder diesen RAM noch diesen Plattenplatz. Container-/Recovery-Lesegrenzen leiten sich aus dem unabhängigen v13-Nutzungsbudget ab. Das konservative aktuelle Default-Extraktionsmaximum beträgt 256 MiB und bleibt eine vom Benutzer änderbare Ausgabeautorisierung, keine Formatgrenze. Eintrags- und Metadatenobergrenzen bleiben endliche Prüflimits.

`OperationMemoryBudget` zählt konkrete Working-/Heavy-Leases sowie Entropiesegmente gemeinsam. Verschachtelte Dienste teilen denselben Besitzer. Zulassung erfolgt vor realer Allokation und berücksichtigt verlässliche OS-/Prozessbeobachtungen, aktive Besitzer und noch ausstehende Erwerbe. Nach Allokation wird die Belegung bestätigt. Ein Vorgang wartet nicht auf seine eigene unmögliche Restzulassung. Argon2-Matrizen passen vor Erwerb in den realen Rahmen; ihre kryptographischen Kosten werden bei Mangel nicht reduziert.

Readerpuffer, RAM-Indexsegmente, Recoveryshards, Kandidaten-Kopierbuffer und Metadaten-Pending-/Caches besitzen konkrete Leases. CPU-Permits liegen um Rechenarbeit, nicht um wartende I/O-Slots. Copyjobs halten kein ganzes Rechenteam über ihre Datei-I/O. Ausgelagerte Recovery-Metadaten werden vor dem CPU-Hashteam gelesen. Die vorbereitende KDF und die schweren ZPAQ-Modelle werden nacheinander zugelassen; alte Beschreibungen eines vorsorglichen maximalen KDF-Abzugs bei bereits laufendem Kompressor sind überholt.

Arbeits- und Ausgabevolumes werden unabhängig gebunden. Tatsächlich ausstehende eigene Writes teilen einen gemeinsamen Volume-Ledger. Vorhandene Quellen, genehmigte Maxima und eine spätere Umbenennung desselben Outputobjekts sind keine zusätzlichen freien Bytes. Native Ausgabe darf ihr bewilligtes Expansionsbudget nicht überschreiten. Laufende Freiplatz-/I/O-/Flush-/Renamefehler bleiben harte Fehler; eine Buchhaltung eigener Jobs reserviert keinen exklusiven Platz gegen andere Prozesse.

Die macOS-Prüfung bindet Dateisystem, Mountflags und 64-Bit-Freiplatz am Descriptor. Es gelten lokale schreibbare APFS-/HFS+-Volumes mit aktiver Eigentümersemantik. Unbekannte Dateisysteme, Netzwerk-/Read-only-/Ignore-Ownership-Mounts erhalten keine stille Freigabe. Bekannte Synchronisationspfade werden abgewiesen; verdeckte Drittanbietersynchronisation kann nicht universell erkannt werden. Benutzerfreigabe und tatsächliche lokale Schutzsemantik bleiben erforderlich.

Normale Archivoperationen haben keine Wandzeit-, CPU-Zeit-, Stillstands-, ETA- oder Fortschrittsdeadline. `OperationExecutionBudget` hält Lebensdauer, Nutzerabbruch und Beobachtungen. `OperationProgressTracker` ist reine Telemetrie mit getrennten Phasen-/Passzählern; Messfehler oder ausbleibende Rate verändern keine Sicherheits- oder Ressourcenentscheidung. Manueller Abbruch, Shutdown und echte Fehler joint gestartete Arbeit und löschen geschützte Zustände weiterhin.

## Nachweisgrenzen

Konkrete Reader-/Recovery-Belege, Stagehashes und offene finale Paketprüfungen stehen im [REV11-Readerbericht](KEEP_VAULT_5_0_3_ORIGINAL_INPUT_REVIEW.md). Die Auto-/Phasenbuchhaltung wird im [Ressourcenreview](KEEP_VAULT_5_0_3_AUTO_RESOURCES_REV10_REVIEW.md) behandelt; dessen Dateiname stammt noch aus Revision10. Alte REV9-Logs sind keine Nachweise des kopiefreien Readers oder der deadlinefreien Ausführung.

Realer Windowslauf, neue native Sanitizer-/ZPAQ-Integration, finale installierte GUI, physisches Volumeabziehen, echte Quoten-/ENOSPC-Ereignisse und großskalige RSS-/Swap-/Datenträgermessungen sind jeweils gesondert nachzuweisen. Ein einzelner synchron blockierender Betriebssystemread wird nicht durch einen Abbruchcheck zwischen Ranges sofort unterbrechbar. Kein aktueller kleiner Test wird als TiB-Lauf oder externe kryptographische Begutachtung dargestellt.
