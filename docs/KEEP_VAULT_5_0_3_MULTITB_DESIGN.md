# Keep Vault 5.0.3: Eingabezugriff und Ressourcen

Stand: 28.09.2026, Abgleich mit Revision 9. Die aktuelle Ausführung betrifft macOS. Michael hat die praktischen Tests auf höchstens 256 MiB begrenzt. Zusätzlich ist ein Paranoia-Lauf mit insgesamt 512 MiB ausdrücklich erlaubt: 256 MiB unterschiedliche Datei- und Verzeichnisstrukturen sowie eine einzelne 256-MiB-Datei. Daraus folgt kein Nachweis praktisch verarbeiteter TiB-Datenmengen.

## Implementierter verschlüsselter Eingabepfad

`KalynaArchiver/Services/VerifiedArchiveInput.cs` ersetzt den vollständigen macOS-SHM-Snapshot beim Öffnen verschlüsselter Container. Auch die Erzeugung dual authentifizierter KPAR2-Dateien verarbeitet diesen geschützten Eingabestand. Der normale Entschlüsselungspfad und die KPAR2-Erzeugung erhalten keinen Dateideskriptor des Spools.

Die Quelle wird mit dem vorhandenen No-Symlink-/No-Reparse-Regular-File-Vertrag geöffnet. Vor dem Capture wird die Containerkennung geprüft. Diese Vorprüfung gibt keine Daten für die Entschlüsselung frei. Der tatsächliche Header, die gespeicherten Tags und der gesamte verschlüsselte Inhalt durchlaufen anschließend den lokalen Bereichsschutz. Auf macOS werden Quellobjekt, Metadaten und die Zuordnung des ursprünglichen Pfads am Ende des Capture erneut geprüft.

Das Arbeitsvolume wird aus der unveränderlichen `ArchiveOperationPolicy` übernommen. Zwei Dateien werden exklusiv über `BoundFileTransaction` angelegt: der Ciphertext-Spool und der Index. Auf macOS erhalten sie Besitzerrechte 0600. Namen werden vor dem Kopieren objektgebunden entfernt. Auf Windows erfolgt eine objektgebundene Löschmarkierung. Entfernte Namen sind eine Cleanup-Eigenschaft; sie bilden ausdrücklich nicht den Manipulationsschutz. Die tatsächlich geöffneten Arbeitsdateien müssen auf dem zuvor gebundenen Volume liegen. Es erfolgt kein stiller Wechsel des Arbeitsvolumes.

Pro Captureversuch entstehen unabhängig voneinander 32 zufällige Bytes Operations-ID, 64 Bytes HMAC-Schlüssel und 128 Bytes Skein-Schlüssel. Die vorhandene `LockedSensitiveBuffer`-Implementierung hält diese Werte gesperrt. Sie werden weder aus Archivschlüsseln abgeleitet noch persistiert. Eine Instanz kann keinen zweiten Captureversuch ausführen.

Die physische Quelle einschließlich Header und gespeicherter Globaltags wird in 1-MiB-Bereichen erfasst. Ein fest begrenztes Team aus den tatsächlich gewährten CPU-Permits nimmt unabhängige Bereiche auf. Ein eigener gesperrter Puffer je Worker hält den vollständigen Bereich. Die lokale Versiegelung und der disjunkte Spool-Write verwenden exakt diesen unveränderten Puffer. Ein gesondertes Semaphore begrenzt gleichzeitig laufende I/O-Anfragen. Der Index wird unmittelbar auf Datenträger geschrieben; die Archivlänge erhöht weder Taskzahl noch Pufferzahl. Der letzte Bereich darf kürzer sein.

Die Dateistreams besitzen ihre Handles bis zum Ende aller Worker und Leser. Die Handleobjekte werden einmal vor der parallelen Arbeit gebunden. Schon Magic-, Längen- und EOF-Prüfung erfolgen über `RandomAccess`; parallele Pfade greifen nicht auf den gepufferten FileStream-Cursor oder dessen mutierenden `SafeFileHandle`-Getter zu.

```text
M_i = OperationId[32] || BE64(i) || BE32(n_i) || capturedBytes_i
T_H = HMAC-SHA3-512(K_H, LE32(len(D_H)) || D_H || M_i)
T_S = Skein-MAC-1024-1024(K_S, personalization=D_S, message=M_i)
Record_i = BE64(i) || BE32(n_i) || T_H[64] || T_S[128]
D_H = "Kalyna-ZPAQ/v13/VerifiedArchiveInput/HMAC-SHA3-512"
D_S = "Kalyna-ZPAQ/v13/VerifiedArchiveInput/Skein-MAC-1024-1024"
RecordBytes = 204
```

Operations-ID, Schlüssel, erfasste Länge und Recordanzahl bleiben im Prozesskontext. Die Recordanzahl wird über Division und Rest berechnet, ohne `length + rangeSize - 1` zu addieren. Indexpositionen sind geprüfte 64-Bit-Produkte. Aus Indexdaten werden weder Allokationen noch erwartete Offsets abgeleitet.

Nach Capture werden beide Dateien mit `Flush(true)` abgeschlossen und ihre genauen Längen geprüft. Es existiert ein interner Schreibhandle je Objekt, weil die vorhandene plattformübergreifende Transaktionsklasse keinen atomaren Descriptor-Downgrade anbietet. Diese Handles sind nicht an Verbraucher zugänglich. Der Schutz bleibt bei einem bereits vorhandenen fremden Schreibhandle durch die lokalen MACs erhalten. Das Schließen beziehungsweise Abstufen nicht mehr benötigter Schreibrechte ist ein zusätzlicher noch offener Härtungspunkt.

## Zustände und Weitergabe

```text
Created -> Capturing -> CapturedUnverified -> VerifyingGlobal
        -> Verified -> Consuming -> Closed -> Disposed
Fehler oder Abbruch -> Failed -> Closed -> Disposed
```

Die normale Stream- und Read-at-Schnittstelle liefert vor der globalen Prüfung keine Bytes. Nur der eng begrenzte Callback von `VerifyGloballyAsync` erhält eine temporäre Prüfansicht. Der Containerverifizierer liest darüber den strikten v13-Header, führt die unveränderte produktive KDF aus und berechnet beide globalen Container-MACs. `VerifiedArchiveInput` prüft zusätzlich selbst die exakten Taglängen und beide vollständigen Tagvergleiche. Erst dann entsteht der Zustand `Verified`. Die Prüfansicht wird nach dem Callback entzogen; ihre Aufbewahrung verlängert die Leseberechtigung nicht. Es gibt keinen allgemein setzbaren Verified-Schalter.

Jeder spätere Read-at lädt vollständige betroffene Capturebereiche und ihre Records in denselben begrenzten privaten Arbeitsbereich. Die vertrauenswürdig gehaltene Capturelänge bestimmt Bereichsindex, erwartete Länge und Indexoffset. Beide lokalen MACs werden neu berechnet und vollständig verglichen. Nur der angeforderte Ausschnitt des gerade geprüften privaten Puffers gelangt in den Caller-Puffer. Eine nachfolgende Dateimutation ändert diesen bereits kopierten Puffer nicht; der nächste Read-at muss die Datei erneut prüfen. Fehler innerhalb eines mehrteiligen Reads nullen den gesamten angeforderten Rückgabebereich und vergiften die Eingabeinstanz.

Für Non-AEAD-Suites gilt derselbe lokale Schutz. XChaCha-Suites prüfen darüber hinaus wie im Containervertrag vorgeschrieben den vollständigen AEAD-Tag des jeweiligen Chunks vor der Klartextweitergabe. Der lokale 1-MiB-Bereich ist unabhängig vom 16-MiB-Verschlüsselungschunk und vom logisch versetzten globalen MAC-Blatt.

Read-at-Verbraucher erhalten voneinander unabhängige gesperrte Bereichspuffer aus einem festen Pool. Ein CPU-Permit wird nur dann neu erworben, wenn der Aufrufer noch keinen markierten CPU-Kontext hält. Der Streamcursor bleibt separat serialisiert. Dispose entzieht neue Reads, bricht wartende Reads ab und wartet auf alle bereits aktiven Leser, bevor Schlüssel oder Puffer freigegeben werden. Alle vollständigen Pufferkapazitäten und Schlüssel werden vor dem ersten Unlock genullt. Die RAM-Reservation bleibt bis zum erfolgreichen Cleanup erhalten, auch nachdem Capture zurückgekehrt ist. Vor der ersten geschützten Allokation wird die Instanz in einem Besitzerregister gehalten; fehlgeschlagener Cleanup bleibt deshalb auch nach einer Capture-Ausnahme wiederholbar. Ein weiterer Capture versucht zuerst den Cleanup geschlossener Besitzer und scheitert bei fortbestehendem Fehler. Der Prozess kann den Zustand nach einem Neustart nicht wiederherstellen.

## Reguläre ZPAQ-Eingabe

`CaptureOriginalAsync` erzeugt nur den authentifizierten Bereichsindex und hält das sicher geöffnete Original. Es entsteht keine temporäre Klartext-Archivkopie. `ArchiveIntegrityService` vergleicht beide vorhandenen unkeyed Sidecars über denselben lokal geschützten Stream. Dies ist Fehlererkennung, keine Ursprungsauthentifizierung.

Der native Parser erhält ausschließlich Antworten des begrenzten Duplex-Read-at-Protokolls `KV13RA`. Der verwaltete Server akzeptiert positive Anfragen von höchstens 1 MiB mit geprüften 64-Bit-Offsets. Er liest zunächst in einen privaten gesperrten Puffer, dessen zugrunde liegende Bereiche vollständig lokal geprüft wurden, und schreibt erst dann die Antwort. Der native Reader erhält weder Archivpfad noch Raw-FD noch eine gesamte VM-Kopie. Der bestehende verschlüsselte Framepfad verwendet `KVP13ZP1`; seine begrenzten Frames bleiben erhalten.

## KPAR2-v4 ohne gesamtes Manifest im RAM

RS(20,3), 4-MiB-Bodyshards, Headerprofil, Metadatenblocklayout, Locator-Konsens und Zertifizierung bleiben erhalten. Die Envelope-Länge ist durchgängig Int64; auf Datenträger war dieses Feld bereits 64 Bit breit. Die früheren 1-TiB-/128-MiB-Grenzen wurden durch explizite Policybudgets ersetzt.

`RecoveryManifestCodec` schreibt die bestehenden kanonischen JSON-Eigenschaften und deren Reihenfolge inkrementell. Beim Lesen arbeitet ein 8-KiB-Tokenpuffer mit Tiefe 8, höchstens 64 Byte Propertynamen, 32 Byte Zahlentokens und 4096 Byte Stringtokens. Das Archivmaß begrenzt die Zahl der Digest-/Paritätseinträge. Nach dem Lesen wird die kanonische Darstellung erneut in einen geschützten Metadatenstream geschrieben und fensterweise bytegenau verglichen. Es gibt keine vollständige JSON-Allokation.

`RecoveryRecordTable<T>` hält Digests und Paritätskoordinaten in typisierten Records einer exklusiven, unbenannten Arbeitsdatei. Eigene flüchtige gesperrte Schlüssel, Operations-ID, Index, Typ und feste Recordbreite sind durch beide lokalen MACs gebunden. Digesttexte behalten exakt `Base64(SHA3[64]) + ":" + Base64(Skein[128])`. `RecoveryMetadataStream` verwendet 64-KiB-Records sowie jeweils einen begrenzten Schreib-/Lesecache. Metadatenserialisierung, Zertifizierung und RS-Codierung verarbeiten diese Streams inkrementell. Ein gemeinsames Metadatenbudget zählt gleichzeitig lebende Tabellen, Metadatenstreams und Eingabe-Bereichsindizes.

Sidecarbytes bleiben bis zur Zertifizierung untrusted. Locator und RS-Metadaten werden nur mit festen, geprüften Grenzen gelesen; dekodierte Metadaten werden lokal auf Datenträger versiegelt. Erst beide Zertifizierungen geben den normalen authentifizierten Manifestpfad frei. Paritätsbytes werden bei Verwendung erneut gegen beide zertifizierten Digests geprüft. Der explizite Emergency-Modus bleibt als solcher gekennzeichnet.

Eine beschädigte Quelle ist ausschließlich ein interner objektgebundener Recovery-Read-at-Stand. Sie erhält keine Decrypt- oder ZPAQ-Freigabe. Physische EIO-Bereiche können im getrennten Kandidaten ersetzt werden. Der Kandidat entsteht unter einem zufälligen privaten `.partial`-Namen. Jede verschlüsselte Reparatur erhält danach einen neuen geschützten Eingabekontext und muss beide vollständigen Container-MACs sowie beide zertifizierten Archivdigests bestehen, bevor die objektgebundene exklusive Umbenennung ins Recovery-Ziel erfolgt. Die KDF bleibt suiteabhängig vollständig: eine Master-Runde bei Einrundensuites und zwei bei Paranoia.

## Ressourcenrichtlinie und gemeinsames RAM-Budget

`ArchiveOperationPolicy` hält getrennte Bytebudgets für Container, Extraktion, Einzeldatei, Recovery und Metadaten; Eintragszahl; Arbeits-/Ausgabevolume; RAM, Entropiespeicher, CPU-Worker, I/O und Warteschlangen; Wandzeit, CPU-Zeit und Stillstandsfrist. Die GUI kann diese öffentlichen Ressourcenentscheidungen für die Sitzung ändern. Das tatsächliche Ausgabevolume wird vor dem Vorgang aus dem ausgewählten Ziel gebunden. Der lokale Arbeitsdatenträger ist separat auswählbar.

Defaults bleiben konservativ: 512 GiB Container, 500 GiB Extraktion/Einzeldatei, 1 TiB Recovery, 2 GiB Metadaten, vier Stunden Wandzeit. Diese Werte sind keine Formatgrenzen und können in der GUI erhöht werden. Mehr-TiB-Recovery benötigt ein ausreichend großes explizites Metadatenbudget für gleichzeitig vorhandene serialisierte und geparste Tabellen. Aus dem Header werden keine Ressourcenfreigaben übernommen.

CPU-Worker sind von den Chunk-Slots getrennt: pro Slot werden zwei 16-MiB-Puffer, je Worker Kontext-/Stackreserve und je I/O-Anfrage ein begrenztes Fenster budgetiert. Eine feste 64-Worker-Grenze besteht in dieser Policy und den Recovery-/ZPAQ-Aufrufern nicht. Die zulässige Prozess-CPU-Zahl und das RAM begrenzen die freigegebene Zahl. Die native Pipe benötigt mindestens zwei CPU-Permits einschließlich des authentifizierenden Elternprozesses; die GUI weist darauf hin.

`OperationMemoryBudget` reserviert pro äußerem API-Vorgang `MemoryBudgetBytes - EntropyCaptureBudgetBytes`. Verschachtelte Container-, Recovery- und ZPAQ-Aufrufe verwenden dieselbe Reservation, deren Lebensdauer referenzgezählt ist. Gleichzeitige unabhängige Vorgänge warten abbruchfähig, wenn ihr gemeinsamer Bedarf die stabile Prozessgrenze überschreiten würde. Diese Grenze beträgt 75 Prozent des von .NET gemeldeten OS-/Prozess-Memorylimits; ein Viertel bleibt für OS, GUI, Runtime und Caches. Das ist eine konservative Ressourcenentscheidung, keine Messung des realen Peak-RSS.

Live- und verbrauchte Mausrecords werden separat in derselben globalen Rechnung geführt. Jedes Segment reserviert vor dem Routing die maximale Seitenabdeckung beider gesperrter Arrays und eine Metadatenreserve. Das kleinste aktive Entropiebudget und die verbleibende Hostkapazität begrenzen neue Segmente. Argon2-Matrizen müssen vor Allokation in das nach Entropie- und Pufferreserven verbleibende Budget passen; die KDF-Kosten werden nicht reduziert. Ein zusätzlich referenzgezähltes Heavy-Lease zählt gleichzeitig lebende Matrizen und native Child-Reservierungen additiv. Bei der verschlüsselten Pipe erhält ZPAQ das Heavy-Budget abzüglich einer vollständigen maximalen v13-Argon2-Matrix. Damit darf der bereits gestartete Kompressor seine Modelle füllen, während der Elternprozess die KDF ausführt. Child-CPU- und Heavy-Permits werden erst nach bestätigtem Prozessende, dann aber vor dem noch laufenden Consumer-Finaljoin freigegeben. Die äußere Reservation bleibt bis zum Ende aller Consumer erhalten.

Der native Parameter `-kv-memory-budget` bezeichnet das gesamte Child-RSS-Budget. Vor Modellen und Warteschlangen werden Runtime-/Stackreserven abgezogen. Ein globaler Allokator zählt C++-Allokationen einschließlich überausgerichteter Objekte sowie die expliziten libzpaq-Array-, StringBuffer- und BWT-Allokationen vor dem Erwerb. Realloc zählt den alten und neuen Besitzer während der Überlappung; fehlgeschlagener Erwerb erhält den alten Puffer. Freigabe löscht die vollständige Nutzkapazität. Metadaten, komprimierte Queues und Worker-Modelle konkurrieren innerhalb dieser endlichen Grenze. Eine zusätzliche Child-RSS-Messung beendet Überschreitungen; die Reserve ist keine mathematische Garantie gegen sämtliche OS-/Allocator-Fragmentierung.

Ein gemeinsamer `OperationExecutionBudget` überwacht Wandzeit, kumulierte Eltern-/Child-CPU-Zeit und Stillstand. Nur erfolgreich verarbeitete Bytes, Frames, Stripes oder tatsächliches Ausgabewachstum erneuern die Fortschrittsfrist. Stderr-/Statuszeilen erneuern sie nicht. Ein bereits abgelaufener Zeitraum kann durch verspätete Fortschrittsmeldungen nicht wieder geöffnet werden. Verschachtelte APIs verwenden dieselbe Deadline und denselben Abbruchtoken. Konstruktorfehler geben Timer, CTS und Runtimebesitzer wieder frei, bevor Ressourcenbuchhaltung verändert wird.

Die Arbeitsvolumeprüfung umfasst Volumeidentität, lokale Verfügbarkeit, Spool/Index und 256 MiB Platzreserve. KPAR2 prüft vor Erzeugung die geschätzte neue Sidecargröße und vor Reparatur den vollständigen zusätzlichen Kandidaten; während der Ausgabe bleiben harte Längengrenzen aktiv. Vorhandene Sidecars werden nicht erneut als freier Zusatzbedarf berechnet. Fehler schreiben keine fremden Dateien um und löschen keine fremden Platzhalter.

## Grenzen der Nachweise

Capture, lokale Read-at-Prüfungen, globale MAC-Blätter, Containerarbeit und Recovery-Hash-/RS-Bereiche verwenden begrenzte parallele Arbeit. Recovery-Worker verwenden die gemeinsamen CPU-Permits; innere Digestberechnungen starten kein weiteres Team. Gleichzeitige Recovery-I/O-Anfragen sind gesondert begrenzt. Es bestehen keine pauschalen 64-Worker-Clamps im aktualisierten macOS-Pfad. Das ist keine Zusage beliebiger CPU-Skalierung; tatsächliche Grants bleiben von verfügbaren CPU-Permits, RAM und I/O abhängig.

Der zusätzlich geprüfte Recovery-Kopierpfad hält seine CPU-Reservation nur während des verbundenen Kopierteams. Seine Worker rufen über `TryReadAtAsync` ausschließlich den objektgebundenen Datei-Read-at, begrenzte Writes, Nullung und Fortschrittsmeldung auf. Sie erreichen weder `RunRecoveryParallel` noch eine Digestberechnung mit zusätzlichem Teamerwerb. Die anschließenden RS-/Digestphasen beginnen erst nach dem vollständigen Join und der Freigabe des Kopierteams. Dieser Callchain-Befund ist ein Quellreview, kein allgemeiner Beweis über beliebige zukünftige Callbacks.

Noch gesondert zu belegen sind die gesamte Plattform-/GUI-/Fehlermatrix, Release-Signierung und konkrete RSS-/Swap-/Datenträgermessungen. Physisches Volumeabziehen, Sleep/Wake und echte Quoten-/ENOSPC-Ereignisse sind nicht durch mathematische 64-Bit-Tests ersetzt. Ein einzelner im Betriebssystem blockierender synchroner Read wird durch den Abbruchcheck zwischen 1-MiB-Bereichen nicht sofort unterbrochen. Die Speicher-/Laufzeitnachweise des finalen Builds werden im Prüfbericht ausgewiesen. Die genehmigten kleinen Tests sind kein praktischer TiB-Durchsatznachweis und keine externe kryptografische Begutachtung.
