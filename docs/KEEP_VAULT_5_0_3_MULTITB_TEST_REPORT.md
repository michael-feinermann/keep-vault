# Keep Vault 5.0.3: Prüfstand Eingabe und Ressourcen

Stand: 28.09.2026, Revision 9, macOS. Reale Tests sind auf ausdrücklichen Benutzerwunsch auf höchstens 256 MiB begrenzt. Eine zusätzliche Paranoia-Strukturrunde mit 512 MiB ist erlaubt: 256 MiB variierte Dateien/Verzeichnisse und eine einzelne 256-MiB-Datei. Dieser Bericht enthält keinen praktischen TiB-Durchsatznachweis.

Ergänzung vom 29.09.2026: Der Quellstand schließt nach Capture nun die eigenen Schreibhandles und übernimmt zuvor identitätsgebundene echte Lesehandles. Die neue Gruppe `io.verified-input-read-only-seal` prüft Kernelrechte, geschlossene ursprüngliche Schreibhandles, weiter offene fremde Schreibhandles mit anschließender Manipulationsablehnung, Originalmodus, Objekt-/Symlinktausch vor dem Lese-Open und vollständiges Handle-/Besitzercleanup bei einem Fehler vor dem Übergang. Die bestehenden Tamper-, Private-Copy- und 10.000 Spoolfälle verwenden dafür eigene vor dem Übergang duplizierte Angreifer-Schreibhandles; ihre Ablehnungsassertions bleiben erhalten. Der gemeinsame neue Build und diese Wiederholungen sind noch ausstehend. Die folgenden älteren PASS-Nachweise gelten für die jeweils dokumentierten Binärstände.

## Ausgeführte Prüfungen

| Prüfung | Umfang | Ergebnis |
|---|---|---|
| Managed Build Mac + Mac.Tests | Release, SDK 10.0.400, geprüfte unveränderte NuGet-Locks | PASS, 0 Warnungen/Fehler einschließlich der IO-Lifecycle-, Testhelper-, Fuzz- und Descriptor-Korrekturen |
| `resources.shared-memory-budget` | Verschachtelte Reservation, globale Konkurrenz, Abbruch, lebende Entropie, additive Child-/KDF-Kapazität; injizierte Fehler nach Runtime-/Lease-Konstruktion | PASS |
| `resources.shared-runtime-budget` | Exakte Wand-/CPU-/Stillstandsgrenzen mit deterministischen Uhren, Eltern-/Child-CPU additiv, Status/Nullbytes ohne Fristverlängerung | PASS |
| `resources.cpu-worker-budget` | Prozessweite CPU-Permits, Kontextvererbung, verschachtelte Hashteams und Join bei Fehlern | PASS |
| Nativer gesamter Speichervertrag | 12 kleine Allokatorprüfungen je ARM64, x86_64 und ARM64 ASan/UBSan; inklusive Reallocfehler, Alignment, Quoten und Overflow | PASS |
| Native Modellzulassung | Memory-order-Selbsttest je Architektur/Sanitizerbinary | PASS |
| Native Plain-/Read-at-/Pipe-Roundtrips | Je 2.097.197 Eingabebytes, Unicode, Leerdatei und Leerordner; vollständiger Baum- und SHA-256-Vergleich | PASS auf ARM64, x86_64/Rosetta und ARM64 ASan/UBSan |
| Native ungültige RAM-Budgets | 6 ungültige CLI-Werte je Binary | PASS, alle verworfen |

Die native Runde setzt außerdem eine freigegebene logische 4-TiB-Extraktionsgrenze, eine Million Einträge und 65 gewünschte Worker. Verarbeitet werden ausschließlich die genannten rund 2 MiB; tatsächliche Worker werden durch Host und RAM begrenzt. Daraus folgt weder ein 4-TiB-Datenlauf noch ein 65-Core-Skalierungsnachweis. Der Sanitizerlauf nutzt `halt_on_error=1`; LeakSanitizer ist auf diesem macOS-Target nicht verfügbar und wurde nicht behauptet. Ein gemeldeter UndefinedBehaviorSanitizer-Befund am typisierten Alignment-Präfixzugriff wurde durch byteweisen `memcpy`-Zugriff innerhalb der reservierten Rohallokation behoben; dieselbe vollständige Runde besteht auf dem korrigierten Stand.

Rohdaten und wiederholbarer Harness: `work/v13-native/memory-zpaq/results.json`, `results.log`, `check.py`. Verwaltete Ressourcenlogs: `/tmp/keep-vault-v13-memory-runtime.log`, `/tmp/keep-vault-v13-deadline-runtime.log`, `/tmp/keep-vault-v13-cpu-runtime.log`. Der übergeordnete Releasebericht übernimmt dauerhafte Kopien der Freigabenachweise.

## Ausführung im signierten Entwicklungsteststand

Alle 19 IO-/Recovery-/Ressourcengruppen wurden am 28.09.2026 aus `work/v13-dev-trust-20260928` ausgeführt. Die nativen Dateien dieses Entwicklungsteststands sind signiert und durch die bestehenden Trust-Prüfungen freigegeben. Ergebnis des ersten vollständigen Laufs: 17 PASS, zwei Testhelperfehler, keine blockierte Gruppe. Nach Korrektur des Helpers und erfolgreicher Wiederholung sind alle 19 Gruppen PASS. Die frühere Trust-Blockierung ist damit für diese Gruppen aufgehoben. Dies ist Entwicklungsnachweis, noch kein Nachweis des abschließend installierten Release-Artefakts.

| Gruppe | Umfang | Ergebnis und Rohlog unter `work/v13-evidence/` |
|---|---|---|
| `io.verified-input-domain-kats` | Unabhängige HMAC-/Skein-Vektoren, 17 öffentliche Datenbytes und Bereichsindex `2^32` | PASS, `dev-io.verified-input-domain-kats.log` |
| `io.verified-input-state` | Beide Globaltags nötig, keine vorzeitige Freigabe, Callback-Ansicht nach Ende entzogen | PASS, `dev-io.verified-input-state.log` |
| `io.verified-input-ranges` | Unaligned Reads, EOF, exaktes 204-Byte-Framing, 2 MiB + 37 Bytes | PASS, `dev-io.verified-input-ranges.log` |
| `io.verified-input-tamper` | Spool, beide Tags einzeln, Index, Länge, Trunkierung, Anhängen, Operationsreplay | PASS, `dev-io.verified-input-tamper.log` |
| `io.verified-input-private-copy` | Mutation nach privater Prüfung, erneuter Read verwirft | PASS, `dev-io.verified-input-private-copy.log` |
| `io.verified-original` | Originalindex ohne Klartextkopie, spätere Originalmutation verworfen | PASS, `dev-io.verified-original.log` |
| `io.verified-input-parallel-lifetime` | Zwei parallele authentifizierte Reads, Dispose wartet, vollständige Puffer-/Schlüssellöschung | PASS, `dev-io.verified-input-parallel-lifetime.log` |
| `io.verified-input-cleanup-retry` | Capturefehler und fortbestehender Unlockfehler; Besitzer bleibt erreichbar, neuer Capture erst nach erfolgreichem Cleanup | PASS, `dev-io.verified-input-cleanup-retry.log` |
| `io.verified-input-policy` | 64-Bit-Grenzrechnungen bis `Int64.MaxValue`, Volumebudget, Abbruch | PASS, `dev-io.verified-input-policy.log` |
| `resources.shared-memory-budget` | Globale RAM- und Entropierechnung, nested reuse, Konkurrenz/Abbruch, Child+KDF, Konstruktorfehler | PASS, `dev-resources.shared-memory-budget.log` |
| `resources.shared-runtime-budget` | Exakte Wand-/CPU-/Stillstandsgrenzen | PASS, `dev-resources.shared-runtime-budget.log` |
| `resources.cpu-worker-budget` | CPU-Permits, Kontext, verschachtelte Teams und Fehlerjoin | PASS, `dev-resources.cpu-worker-budget.log` |
| `recovery.streaming-metadata-canonical` | Inkrementeller KPAR4-Codec erhält exakt kanonische Wirebytes | PASS, `dev-recovery.streaming-metadata-canonical.log` |
| `recovery.streaming-metadata-negative` | Doppelte, überlange, abgeschnittene und nichtkanonische JSON-Eingaben | PASS, `dev-recovery.streaming-metadata-negative.log` |
| `recovery.streaming-metadata-large-logical` | 4-TiB-Archivmaß ausschließlich logisch, kleine diskgestützte Tabellen | PASS, `dev-recovery.streaming-metadata-large-logical.log` |
| `recovery.record-table-cleanup` | Alle sensitiven Mitglieder trotz Unlockfehler löschen/freigeben, Wiederholung | PASS, `dev-recovery.record-table-cleanup.log` |
| `recovery.record-table-budget` | Gemeinsames Metadatenbudget, verschachtelte Scopes, Freigabe | PASS, `dev-recovery.record-table-budget.log` |
| `recovery.record-table-layout` | Feste Recordbreiten und unabhängige BC-HMAC-/Skein-Orakel | PASS, `dev-recovery.record-table-layout-rerun.log`; erster Helperfehler bleibt in `dev-recovery.record-table-layout.log` dokumentiert |
| `recovery.record-table-tamper` | Elf Fälle: Payload, HMAC, Skein, Identität, Position, Typ, Länge, Trunkierung, Anhängen, fremder Record, vertauschter Record | PASS, `dev-recovery.record-table-tamper-rerun.log`; erster Helperfehler bleibt in `dev-recovery.record-table-tamper.log` dokumentiert |

Die beiden Fehler entstanden im ausschließlich testseitigen Speicherzugriff: `GetProperty("Stream")` suchte eine öffentliche Eigenschaft, während `BoundFileTransaction.Stream` intern ist. Der Helper verwendet jetzt nach geprüftem Feldzugriff den typisierten Besitzer und dessen interne `Stream`-Eigenschaft. Keine Orakel-, Layout- oder Manipulationsprüfung wurde entfernt. Beide Wiederholungsläufe bestehen; die vollständigen Orakel- und Manipulationsprüfungen wurden dabei ausgeführt.

Die vollständigen lokalen KATs stehen in `KeepVaultMac.Tests/VerifiedArchiveInputTests.cs`. Öffentliche feste Testschlüssel werden ausschließlich in Tests verwendet. Reparaturrunden müssen zusätzlich zeigen, dass beschädigte Eingaben niemals eine allgemeine Decrypt-Freigabe erhalten und der getrennte Kandidat beide vollständigen globalen MACs und beide zertifizierten Digests besteht.

## Reproduzierbare Fuzzfälle nach REV9 8.6

`native/tests/verified_read_at_fuzz.cpp` führt den unveränderten produktiven `VerifiedArchiveReader` gegen öffentliche synthetische Eingaben aus. Ein getrennt berechnetes Offsetmuster liefert erwartete Antwortbytes, ein einfacher BE64-/BE32-Decoder prüft die tatsächlich erzeugten Requests. Ziel und Testorakel werfen unterschiedliche Fehlertypen, damit ein Oraclefehler nicht als erwartete Parserablehnung gezählt wird. Headerkennung/-länge, signierte 64-Bit-Grenze, Out-of-range-Requests, leere Reads, Fensterteilung und gekürzte Antworten sind enthalten. Caller-Canaries umgeben jeden Ausgabebereich; ein unvollständiger Transport darf keinen Erfolg melden.

Mit Seed `0x4b5631335241465a` bestanden je 10.000 variierte Fälle auf ARM64, x86_64/Rosetta und ARM64 unter ASan/UBSan. Je Binary wurden 3.335 gültige Fälle akzeptiert und 6.665 ungültige verworfen; größte einzelne Responsefixture 1.048.699 Byte, insgesamt 25.296.922 Byte. Es wurden 2.506 vollständige Requesttransaktionen gegen das Orakel verglichen. Die rund zwei Sekunden pro Lauf sind Testlaufzeiten, keine Produkt-Durchsatzmessung. Sanitizergrenzen bleiben wie oben angegeben.

Reproduktion: `python3 native/tests/run_verified_read_at_fuzz_macos.py`. Rohdaten einschließlich Compiler, Seed, Header-/Harness-/Binary-SHA-256 und Kommandos: `work/v13-native/read-at-fuzz/report.json`; Sammelprotokoll: `work/v13-evidence/read-at-fuzz-native.log`.

Die verwalteten Gruppen enthalten jeweils 10.000 Seed-/Index-reproduzierbare Fälle und bestehen im signierten Entwicklungsteststand:

| Gruppe | Fälle | Laufzeit | Ergebnis und Rohlog unter `work/v13-evidence/` |
|---|---:|---:|---|
| `fuzz.verified-input-10000` | 10.000 | 112,132 s | PASS, `dev-fuzz.verified-input-10000.log` |
| `fuzz.recovery-streaming-10000` | 10.000 | 6,405 s | PASS, `dev-fuzz.recovery-streaming-10000.log` |
| `fuzz.verified-read-at-server-10000` | 10.000 | 1,650 s | PASS, `dev-final-fuzz.verified-read-at-server-10000.log` |

Spoolprüfungen verwenden echte kleine Dateien, BC-Digestorakel, gültige Bereiche und gezielte lokale/globale Tag-, Record-, Längen- und Replaymutationen. Die Callback-Digests prüfen die Eingabekomponente; sie ersetzen keinen vollständigen Container-KDF-/MAC-Test. Der Streamingcodec wird gegen unabhängig serialisierte Objekte, fragmentierte Reads und nichtkanonische/überlange/verstümmelte JSON-Eingaben geprüft. Der Read-at-Server erhält unabhängig codierte Requestframes und muss genau die zulässigen Originalausschnitte liefern, ohne bei ungültigen Anfragen Archivbytes zu lesen. Input-/Output-Canaries und terminale Fehlerzustände ergänzen diese Orakel. Sie verwenden keine produktive KDF und keine großen Nutzdatenallokationen.

Je Ziel variieren Fallfamilie, öffentliche Quellbytes, Längen, Offsets, Fragmentierung oder geschützter Operationszustand anhand von Seed und Fallindex. Die Zahl bezeichnet ausgeführte variierte Fälle. Sie behauptet keine paarweise verschiedenen Framingbytes: Gerade kurze Trunkierungspräfixe dürfen mehrfach auftreten. Quelle und Zustand können trotzdem verschieden sein. Fehlerausgaben enthalten den effektiven Seed und Fallindex. Fuzzfälle ergänzen die 19 gezielten Gruppen; sie ersetzen deren feste KATs, Cleanup- und Angriffsprüfungen nicht.

Alle drei verwalteten Aufrufe verwendeten explizit den Schedulerseed `0x5EED0313`. Die Zielseeds sind nach den im Harness festgelegten XOR-Konstanten `0x08A44C00` für die Spoolfälle, `0x15BD4227` für den Streamingcodec und `0x0CAC3220` für den Server. Reproduktion mit dem gebauten macOS-Teststand: `--full --no-smoke --only <Gruppen-ID> --seed 0x5EED0313`. Der Scheduler hält erfolgreiche Nicht-Performance-Workerdiagnostik zurück; die äußeren Logs belegen deshalb PASS und Dauer, nicht zusätzliche von dort aus nicht sichtbare Byte- oder RSS-Zähler.

Dauerhafte Kopien der 19 gezielten Gruppen, der drei Fuzzgruppen, der früheren beiden Testhelperfehler und der nativen Ergebnisse liegen unter [evidence/v13-io-rev9-20260928](evidence/v13-io-rev9-20260928/evidence-manifest.json). Dieses Manifest enthält SHA-256 der abgelegten Evidenzdateien und die Seedzuordnung. Die Zwischenstände der verwalteten Fuzzassemblies wurden nicht separat gehasht. Das ältere `rev9-dev-trust-binary-manifest.json` wird deshalb ausdrücklich nicht nachträglich diesen späteren Läufen zugeordnet. Der finale Release wiederholt die erforderlichen Gruppen mit aufgezeichneten Releasebytes.

## Zusätzlicher Befund beim Mehrchunk-Kryptotest

Der spätere Entwicklungsgruppenlauf `crypto.per-chunk-nonces` scheiterte in `VerifiedArchiveInput.Capture` mit einem aggregierten `Invalid argument`; Rohlog `work/v13-evidence/rev9-dev-crypto.log`, Schedulerseed `0x36D65D68`. Die bereits bestandenen kleinen Gruppen und Fuzzfälle decken diese größere Parallelitätskonstellation nicht abschließend ab.

Der Quellreview fand einen gemeinsamen gepufferten Dateicursor: Nach dem Lesen der sieben Magicbytes konnten parallele Worker erneut `FileStream.SafeFileHandle` aufrufen. Dieser Getter leert den Lesepuffer und korrigiert dabei die Position; er ist kein nebenwirkungsfreier Handlezugriff. Der Vertrag ist in der [.NET-10-Implementierung](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Private.CoreLib/src/System/IO/Strategies/BufferedFileStreamStrategy.cs) sichtbar. Die Korrektur bindet die Handles einmal und verwendet bereits für Magic, Länge und EOF ausschließlich positionsgebundene `RandomAccess`-Operationen. Quellenbindung, beide lokalen MACs und spätere Globalprüfung bleiben erhalten.

Die neue Gruppe `io.verified-input-descriptor-capture` prüft dreimal 32 MiB + 37 Byte, zweimal als Ciphertext-Capture und einmal als Originalindex, mit vollständiger Callback-Verifikation, Vergleich sämtlicher Rückgabebytes, kurzem Endbereich, EOF und Besitzerfreigabe. Nach erneutem Build sind diese Gruppe und die Wiederholung des ursprünglichen Mehrchunk-Kryptotests bestanden:

| Gruppe nach Descriptor-Korrektur | Ergebnis | Laufzeit | Worker-Peak-RSS | Seed |
|---|---|---:|---:|---|
| `io.verified-input-descriptor-capture` | PASS | 3,162 s | 146 MiB | `0x5EED0313` |
| `crypto.per-chunk-nonces` | PASS | 51,609 s | 2.403 MiB | `0x5EED0313` |

Der Kryptotest prüft zwei gleiche 16-MiB-Klartextchunks je Suite, unterschiedliche Ciphertextbereiche und anschließend die vollständige Entschlüsselung aller zwölf Suites. Die Peakwerte stammen aus dem jeweiligen Testworker und sind keine isolierte Bilanz der Spoolkomponente. Rohlogs, vollständige Ergebnisobjekte und die vor diesen Wiederholungen erfassten DLL-/Nativehashes liegen ebenfalls im [IO-Evidenzmanifest](evidence/v13-io-rev9-20260928/evidence-manifest.json). Der Produktassemblyhash ist `05c6410762c802bb346c2494ce7fab2d4559af4d51aefff14a0a5bc3a2b5641e`, der Testassemblyhash `210500f09030cd33d3bc5aeacff32ad2f75961a22ce4af8e89a29fe3fac4c0ce`. Diese Zuordnung gilt für die hier genannten Wiederholungen, nicht rückwirkend für die früheren Fuzzstände.

Der Entwicklungsnachweis umfasst damit 20 gezielte IO-/Metadaten-/Ressourcengruppen plus drei Fuzzgruppen, ausgeführt auf den jeweils ausgewiesenen Ständen, sowie den erfolgreich wiederholten Mehrchunk-Kryptotest. Der frühere Fehler bleibt im Evidenzverzeichnis erhalten. Die abschließende Freigabe prüft erneut die exakten Releasebytes.

## Grenze der Aussage

Der reguläre ZPAQ-Eingabepfad und der KPAR2-Metadatenpfad sind auf begrenzte geschützte Bereichsantworten beziehungsweise diskgestützte Records umgebaut. Die Architektur und ihre verbleibenden Plattformgrenzen stehen in `KEEP_VAULT_5_0_3_MULTITB_DESIGN.md`. Große physisch gespeicherte Archive, Mehr-TiB-Recovery, Windows-Läufe, Volumeabziehen, Sleep/Wake und reale Quoten-/ENOSPC-/EIO-Matrizen sind in dieser Ausführung nicht nachgewiesen. Kleine deterministische Angriffe oder 64-Bit-Rechnungen ersetzen diese Fälle nicht. Abschließende GUI-/Signierungs-/Installations- und Paranoia-Ergebnisse gehören in den übergeordneten Releasebericht. Dieser Zwischenbericht ist keine externe kryptografische Begutachtung und keine Veröffentlichungsfreigabe.
