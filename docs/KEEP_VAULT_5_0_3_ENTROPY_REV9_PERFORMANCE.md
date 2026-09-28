# REV9-Entropie: isolierte Phasenmessung

Gemessen am 28. September 2026 auf Apple M5, 10 vom Prozess gemeldeten CPUs, 16 GiB physischem RAM, macOS 26.6.2, .NET 10, arm64. Die Messung verwendete dieselben produktiven Record-Stores, Fisher-Yates-Implementierungen, Replay-/Finalisierungshilfen, Speicherlöschung und den tatsächlichen macOS-OS-RNG-Adapter. Alle Mausrecords waren öffentliches synthetisches Testmaterial. Zufallsbytes und abgeleitete Ergebnisse wurden nicht protokolliert.

Der Test isoliert die Komponenten sequenziell mit einem reservierten CPU-Platz. Er misst weder die parallele Gesamtsnapshot-Vorbereitung noch Archiv-/KDF-/ZPAQ-/Recovery-Durchsatz und erteilt keine Releasefreigabe. Im abgestimmten Messfenster liefen keine anderen Builds oder größeren Tests der beteiligten Agenten. Normale Desktop-/Betriebssystemprozesse blieben aktiv; Energiezustand, thermische Lage, Context Switches und CPU-Frequenz wurden nicht instrumentiert.

## Methode und Messergebnis

Zwei Vorläufe zeigten deutlich sichtbare Tiered-JIT-Anlaufkosten bei den zuerst gemessenen kleinen Pools. Ihre Werte werden nicht als stabile Skalierung ausgegeben. Der abschließende Lauf führte vor den Samples mindestens drei Sekunden echte Arbeit in beiden Shuffle-/Replaypfaden aus: tatsächlich 1511 Durchgänge zu je 1024 Records in 3001,009 ms. Anschließend wurden fünf vollständige Durchgänge je Poolform gemessen. Die Tabellen zeigen den jeweiligen Median. Es wurden keine Produktparameter für ein günstigeres Ergebnis verändert.

| Records je Pool | Recordaufnahme ms | Indizes ms | FY1 ms | SHA3-Replay ms | FY2 ms | SHA512-Replay ms | Löschen ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| 1024 in allen 11 | 0,440 | 0,052 | 0,312 | 5,656 | 0,315 | 11,551 | 0,063 |
| 4096 in allen 11 | 1,696 | 0,209 | 1,206 | 22,844 | 1,215 | 45,614 | 0,348 |
| 16384 in allen 11 | 7,671 | 0,896 | 4,743 | 93,684 | 4,845 | 180,632 | 1,390 |
| 65536 in allen 11 | 29,488 | 3,543 | 18,872 | 390,856 | 19,441 | 742,930 | 5,036 |
| Ungleich, zusammen 217090 | 9,131 | 1,040 | 5,657 | 117,975 | 5,881 | 222,781 | 1,522 |

Die ungleiche Form war `[1024,1025,2048,4096,4097,8192,16384,16385,32768,65535,65536]`. Die Aufnahme misst das Anlegen/Sperren/Füllen des tatsächlichen segmentierten Stores, nicht die GUI-Ereignisverarbeitung oder die zufällige Poolauswahl. Die Indexphase initialisiert die geschützten Indizes. FY1/FY2 schließen den jeweiligen exklusiven RNG-Cache einschließlich seiner Löschung ein. Replayzeiten schließen den finalen 80-Byte-Poolhash und alle dazugehörigen temporären Aufräumpfade ein. SHA512 prüft weiterhin die Übereinstimmung von Plattform- und BC-Implementierung; seine höhere Zeit ist kein Vergleich zweier gleich implementierter Hashprovider.

Bei 65536 Records in allen elf Pools entfallen 1,191 ms auf die tatsächlich gemessenen OS-RNG-Aufrufe innerhalb beider Shuffles. Diese Zeit ist in FY1/FY2 enthalten und darf nicht nochmals addiert werden.

## Cachevergleich und isolierte letzte Schritte

Für denselben einzelnen 65536-Record-Pool wurden fünf Shuffles je Cachegröße mit frischer realer OS-Zufälligkeit gemessen. Ein separates Korrektheitsgate mit identischem öffentlichen Kandidatenstrom bestätigt vorher, dass 4/16/64 KiB dieselben Permutationen und Replaywerte liefern.

| Cache | FY einschließlich OS-RNG und Cachelöschung, Median ms | OS-RNG-Anteil ms | RNG-Aufrufe | RNG-Bytes |
|---|---:|---:|---:|---:|
| 4 KiB | 1,751 | 0,053 | 64 | 262144 |
| 16 KiB | 1,763 | 0,049 | 16 | 262144 |
| 64 KiB | 1,769 | 0,049 | 4 | 262144 |

Ein größerer Cache bringt in dieser Messung keinen nachgewiesenen Gesamtnutzen. Der produktive 4-KiB-Cache bleibt erhalten. Die geringere Aufrufzahl allein ist kein Geschwindigkeitsbeweis.

Die isolierten letzten Schritte wurden ebenfalls fünfmal mit jeweils 4096 Aufrufen gemessen:

| Schritt | Median für 4096 Aufrufe, ms |
|---|---:|
| P1-Finalisierung, SHA3 einschließlich gesperrtem 80-Byte-Transcript und Löschung | 5,516 |
| P2-Finalisierung, SHA512 einschließlich gesperrtem 80-Byte-Transcript und Löschung | 7,298 |
| 320-Byte-Ausgabegruppe: echter OS-RNG, Produkt-XOR und Zurücksetzen des synthetischen Poolinputs | 4,283 |
| Darin: OS-RNG-Aufrufe für je 320 Byte | 0,993 |
| Darin: eigentliche 320-Byte-XOR-Aufrufe | 3,111 |

Die Teilzeitstempel verursachen Messaufwand. Ihre Teilmediane werden nicht als exakt additive Zerlegung des Gesamtmedians interpretiert.

## Speicher und Evidenzgrenze

Die größte gleichzeitig vorhandene öffentliche Recordmenge betrug 720896 Records mit zusammen 55 MiB Originalbytes. Nach jedem Durchgang wurden die gesperrten Allokationszähler gegen den Ausgangsstand und die Segmentreservierungen gegen null geprüft.

- Prozess-Peak-RSS des vollständigen Tests einschließlich Warmup, Laufzeit und Messharness: 289 MiB.
- Maximal an den instrumentierten Phasengrenzen/RNG-Aufrufen beobachtete gesperrte Speichermenge beim größten Fall: 148,6875 MiB. Kurze transiente Spitzen zwischen Beobachtungspunkten sind damit nicht vollständig erfasst.
- Konservative Record-/Index-Segmentreservation für denselben Fall: 222,75 MiB. Sie ist eine Budgetbuchung und keine RSS-Messung.

Diese unterschiedlichen Größen werden nicht als präziser Beweis des vollständigen Prozessspeicherverbrauchs gleichgesetzt. GC-Heap, Runtime, Code, übrige Worker und Betriebssystemkosten gehören nicht allein zu den Record-/Index-Puffern. Die tatsächliche Auftrags- und Hostspeicherbegrenzung hat eigene Ressourcentests.

`performance.entropy-rev9-phases` bestand in 13,0035 s einschließlich Warmup. [Alle Rohsamples](evidence/v13-core-rev9-20260928/entropy-rev9-phase-performance.json), [Teststatus](evidence/v13-core-rev9-20260928/managed-core-results.json) und [Quell-/Fixture-SHA256](evidence/v13-core-rev9-20260928/source-sha256.json) sind getrennt abgelegt. Dies ist die letzte Messung dieser Reihe; verbleibende Messunsicherheit wird dokumentiert und nicht durch weitere Auswahl von Läufen verborgen.

Der Hashbestand bleibt auf den tatsächlich gemessenen Quellstand eingefroren. Anschließend erhielt die parallele Snapshot-Vorbereitung in `ConsumedEntropySnapshot` einen CPU-Kontextmarker für die bereits gehaltene Lease. Dieser äußere Parallelpfad gehört ausdrücklich nicht zur gemessenen sequenziellen Komponentenreihe; sein neuer Dateihash wird deshalb nicht nachträglich als gemessener Stand ausgegeben. Die Komponenten-/Fixturedateien und Hashwrapper der Messung blieben unverändert.
