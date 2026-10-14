# Keep Vault 5.0.3: Noncepools und Basisvertrag nach REV9

Stand: 28. September 2026, macOS-Implementierungsstand vor Quellfreeze. Dieser Bericht bündelt den Pool-/Basisvertrag; er ist keine zusätzliche Testausführung oder Releasefreigabe. Maßgeblich ist die vom Benutzer bereitgestellte REV9. Historische Prüfzahlen aus deren Modellbeschreibung werden nicht als aktuelle Produktresultate übernommen. Die neuen unabhängigen Shufflefixtures wurden für diese Implementierung erstellt.

## Aufnahme, Vorbereitung und Ausgaben

Der registrierte Katalog enthält elf Rollen: Faktorenhälften 0–3, Salze 4–5 und Noncepools 6–10. Ein akzeptiertes Ereignis wird mit Zurücklegen genau einem Pool zugewiesen. Die 32-Bit-Bereichsverwerfung konsumiert ausschließlich frische OS-Zufallsbytes und berücksichtigt keinen Füllstand. Auch nach 1024 Ereignissen wächst ein Pool weiter. Freigabe prüft alle elf tatsächlichen Zähler und die konsistente Gesamtzahl unter dem Aufnahmegate.

`SensitiveMouseRecordStore` hält die vollständigen ursprünglichen 80-Byte-Records in gesperrten Segmenten. Vor dem atomaren Detach sind Folgeepoche und Indexbudgets vorbereitet. Der Snapshot bindet Rollen, Counts, Sequenzen, Epochen und den unveränderlichen SingleRound-/DualRound-Plan. Neue Liveereignisse gehören danach ausschließlich zur neuen Sammlung.

| Schritt | SingleRound | DualRound |
|---|---|---|
| Erster Shuffle | Rückwärts-Fisher-Yates, eigene exklusive OS-Quelle | Identisch |
| Erster Replay | SHA3-512, A0 = 64 Nullbytes, jeder Originalrecord genau einmal | Identisch |
| Zweiter Shuffle | Kein Zugriff auf R2-Quelle | Frischer vollständiger Fisher-Yates auf dem fertig gelesenen ersten Indexvektor |
| Zweiter Replay | Entfällt | SHA-512 mit eigenem Nullakkumulator über dieselben Originalrecords |
| Pro Pool | Nach letzter erforderlicher Runde Records/Indizes/Caches löschen | Gleicher Vertrag nach Runde 2 |
| Veröffentlichung | Erst nach Join und erfolgreicher Gesamtbereinigung | Gleicher Vertrag |

Der Replayinput ist je Runde `A[64] || Record[80] || LE64(originalSeq) || LE32(purpose)`. Die Endfinalisierung ist genau `H(P[64] || LE64(epoch) || LE32(0) || LE32(purpose))`; H ist SHA3-512 in Runde 1 und SHA-512 in Runde 2. Weder die Ereignisse noch ihre Sequenzen werden neu erzeugt. Runde 2 setzt P1 nicht fort. Eine zufällig identische zweite Reihenfolge ist zulässig.

Q1 liefert elf vollständige 64-Byte-Digests. Die eigenen OS-XOR-Gruppen sind 256 Byte Faktoren, 64 Byte SHA3-Salz, 64 Byte Skein-Salz und 320 Byte erste Noncebasis. Die fünf Nonceanteile stehen in Purpose-Reihenfolge 6–10. DualRound berechnet zusätzlich Q2 aller elf Pools, verwirft die vier zweiten Faktoranteile sicher und verwendet für Salze/Nonce neue Gruppen 64/64/320 Byte. Routing-, Shuffle- und Ausgabe-XOR-Bytes werden nicht wiederverwendet.

Jede Suite erhält B1 mit exakt 320 Byte. Paranoia erhält zusätzlich B2 mit exakt 320 Byte; die Basen werden konkatenatiert. Die sieben Rollen des direkten Salz-/Noncepfads verwenden denselben vollständig freigegebenen elf-Pool-Snapshot. Es gibt keine 94-Byte-Expansion, keinen zweiten Sammlungsverbrauch und keine Kürzung auf die aktive Stufensumme. Bereits vorbereitete Einmalentropie braucht später keine neue Mausbefüllung, kann aber weder erneut verbraucht noch nachträglich von SingleRound zu DualRound erweitert werden.

## Abgrenzung von Basis und aktiver Chunkrotation

Die vollständigen Basen sind im Header und im einmal pro Operation berechneten AAD-Identitätsdigest gebunden. ActivePrefix-v3 hasht nur die benötigten ursprünglichen 64-Byte-Blöcke. Standard verwendet vier von fünf, die aktuelle achtstufige Paranoia fünf von zehn. Die Stufen erhalten direkt die ersten 232 bzw. 312 abgeleiteten Bytes in disjunkten Katalogslices. Es gibt keinen Stagehash. Der Threefish-Tweak bindet separat die vollständige erste 320-Byte-Basis und seinen korrekten Stufenindex.

Reservebytes erhöhen nicht die aktive IV-Breite. Eine Reservemutation lässt rohe Stage-Nonces unverändert, verändert aber die authentifizierte Basisidentität und gegebenenfalls den B1-gebundenen Tweak. Sie ist kein Verfahren zur Erzeugung eines frischen Archivs. Die genauen Domains, Transcripts, k-Grenzen und quantitativen Schlüsselverwendungsbudgets stehen in [Formatspezifikation](KEEP_VAULT_V13_FORMAT.md), [Nonce-Review](KEEP_VAULT_5_0_3_NONCE_REV6_REVIEW.md) und [Nutzungsbudget](KEEP_VAULT_V13_CRYPTO_USAGE.md).

## Vorhandene Evidenz und Grenzen

- Die tatsächlichen Produktgruppen `entropy.rev9-routing`, `shuffle`, `dual-composition`, `suite-plans`, `output`, `faults`, `lifecycle`, `golden`, `finalization-golden` und `cache-equivalence` wurden ausgeführt. Der [Core-Testdatensatz](evidence/v13-core-rev9-20260928/managed-core-results.json) hält die konkreten Ergebnisse fest.
- Das unabhängige öffentliche [Shufflefixture](../KeepVaultMac.Tests/Fixtures/V13Reference/pool_shuffle_rev9_public_vectors.json) wird gegen die tatsächlichen Produkt-Replays in serieller, umgekehrter und paralleler Poolreihenfolge verglichen. Die kleinen Dual-Shuffle-Gates prüfen 15.018 vollständige Paare sowie 154 zulässige R2-Identitätsfälle; dies sind algorithmische Testfälle, keine Aussage über Mausentropie.
- [Isolierte Endfinalisierungen](../KeepVaultMac.Tests/Fixtures/V13Reference/pool_finalization_rev9_vectors.json) prüfen beide Hashfamilien, alle elf Zwecke, Epochengrenzen und zwei 320-Byte-XOR-Ausgaben. Sie ersetzen ausdrücklich nicht den vorherigen Shuffle-/Recordnachweis.
- Fehler-/Lebenszyklustests halten Phasen und Cleanup an, injizieren RNG-/Unlockfehler, prüfen Reader-Join, die unabhängige neue Epoche und gesperrte Veröffentlichung. Eigene Puffer werden nach Nullung und vor Freigabe geprüft. Daraus folgt keine Garantie für sämtliche Library-, JIT-, Register- oder Crashkopien.
- Die getrennte [Phasenmessung](KEEP_VAULT_5_0_3_ENTROPY_REV9_PERFORMANCE.md) beschreibt reale OS-RNG-Nutzung, geschützte Speichergrößen und 4/16/64-KiB-Cachevergleiche. Sie ist keine KDF-/Archiv-/Release-Durchsatzmessung.

Weitere Details und einzelne Nachweisgrenzen stehen im [Routing-Review](KEEP_VAULT_5_0_3_POOL_ROUTING_REV7_REVIEW.md), [Shuffle-Review](KEEP_VAULT_5_0_3_POOL_SHUFFLE_REV9_REVIEW.md) und [Core-Review](KEEP_VAULT_5_0_3_CORE_REV9_REVIEW.md). Die finale signierte Anwendung, reale GUI, Installation und Veröffentlichung benötigen ihre eigenen Artefaktgates. Windows und echte TiB-Läufe gehören wegen der direkten Benutzervorgaben nicht zu diesem Freigabelauf.
