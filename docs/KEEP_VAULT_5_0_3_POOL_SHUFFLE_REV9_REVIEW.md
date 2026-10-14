# Keep Vault 5.0.3: REV9 Record- und Shuffleprüfung

Stand 28.09.2026. Interner Quell- und Testreview, kein externer Audit und keine allgemeine Sicherheitszertifizierung. Windows wurde auf Benutzeranweisung nicht ausgeführt. Finales Paket und installierte GUI werden im Releasebericht separat nachgewiesen.

## Vertrag und Eigentum

Jedes akzeptierte Mausereignis wird unter derselben Sperre einem zufällig ausgewählten Zweck zugeordnet, vollständig abgelegt und gemeinsam mit Pool-/Gesamt-/Originalsequenzzähler committet. Elf gesperrte segmentierte Recordlager speichern sämtliche 80-Byte-Records; Add hasht und balanciert nicht. Bei Fehlern gibt es keinen gewöhnlichen Heap- oder Datenträgerfallback. Die Speicherreservierung zählt volle Segmentkapazitäten, Indexspeicher, mögliche Seitenausrichtung und Metadaten.

Eine vorab festgelegte Vorbereitung entnimmt alle elf bereiten Pools atomar. Frische Live-Pools sind unabhängig vom alten Snapshot. Je altem Pool folgen Indexinitialisierung, rückwärtiger Fisher-Yates mit eigener Quelle, vollständiger SHA3-Replay und Finalisierung. DualRound führt anschließend einen zweiten Fisher-Yates auf der ersten fertigen Reihenfolge und einen SHA512-Replay ab Null aus. Die 32-/64-Bit-Reduktion verwirft den nicht gleich verteilbaren oberen Quellbereich; maximal 128 Kandidaten je Auswahl. Ein Identitätsshuffle ist gültig.

Die Vorbereitung wartet auf alle Leser. Volle Record-, Index-, RNG- und Zwischenpuffer werden vor Veröffentlichung bereinigt. Reset invalidiert noch nicht veröffentlichte Ergebnisse, bricht Leser ab und wartet auf deren Ende. Scheiternde Bereinigung wird als Fehler gemeldet; noch erreichbare Besitzer bleiben für erneute Bereinigung registriert. Ein altes Cleanup berührt keine neu gesammelte Liveepoche. Eine fertige SingleRound-Vorbereitung kann nach gelöschten Records nicht auf DualRound erweitert werden.

## Neue unabhängige öffentliche Referenz

Michael hat ausdrücklich klargestellt, dass vor 5.0.3 keine Shuffle-Referenzwerte existieren. Deshalb wurden neue Werte erstellt, nicht aus historischen Releases übernommen und nicht aus zufälligen Produktläufen exportiert.

Die Dateien stehen unter `KeepVaultMac.Tests/Fixtures/V13Reference`:

- `pool_shuffle_rev9_reference.py` implementiert einen getrennten Präfixauswahl-Encoder und CPython-Hashanbieter. Er erzeugt ausschließlich eine neue Kandidatendatei und verweigert den eingefrorenen Zielpfad sowie Überschreiben.
- `pool_shuffle_rev9_public_vectors.json` hält elf Pools mit 1024 + 37*p Records, insgesamt 13.299 Records, fest. Originalrecordhash, beide Permutationshashes, Q1/Q2 und öffentliche XOR-Ausgaben sind enthalten.
- `verify_pool_shuffle_rev9.py` liest die eingefrorenen Werte, berechnet unabhängig neu und vergleicht vollständig. Er schreibt keine Erwartungen und bestätigt unveränderte Fixturebytes. 77 absichtlich veränderte Felder werden verworfen.
- `EntropyRev9GoldenTests.cs` verwendet die tatsächlichen Produktklassen für Recordlager, Fisher-Yates und Replay und vergleicht mit den eingefrorenen Pythonwerten. Der Kandidatenencoder ist separat in C# umgesetzt. Originalrecordbytes bleiben nach beiden Indexshuffles identisch.

Fixture-SHA-256: `531b54b99ac4e569583e96201ff47abf301a84dc34e2c6d8a5597d033c5ce863`.

Alle Inputs sind öffentliche synthetische Daten. Der deterministische Stream ist ausschließlich Testcode. Im Produkt gibt es keine Benutzeroption für Fake-RNG, künstliche Bereitschaft, Export von Rohrecords oder feste Permutationen. Pythonobjekte sind keine implementierte Geheimnisspeicherung und liefern keinen Löschbeweis.

## Frisch ausgeführte Nachweise

Am 28.09.2026 bestanden zunächst acht macOS-Entropiegruppen einschließlich unabhängiger Golden-Vergleiche, vollständiger 46.234 Wahlfolgen für m=0..8, 4/16/64-KiB-Cachegleichheit, Grenzwerten, Extrarecords, Single-/Dual-Ausgaben, Ressourcenfehlern, RNG-Fehlern, Abbruch, Reset und Bereinigung vor Veröffentlichung. Rohbelege: `work/v13-evidence/rev9-entropy-final-tests.log`, `rev9-entropy-final-results.json`, `rev9-entropy-final-outcomes.json`, `pool_shuffle_rev9_check.json`.

Danach bestanden auch die vollständigen 15.018 Paare erster und zweiter Wahlfolgen für m=0..5 mit 154 Identitätsfällen in Runde 2, sämtliche elf SingleRound-Suites, der direkte Sieben-Rollen-Ausgabepfad bei vollständiger Elf-Pool-Bereitschaft, Invalid-Plan-Ablehnung vor Entnahme sowie isolierte feste P1/P2-Finalisierungs-/320-Byte-XOR-Goldens. Die neuen Recordgoldens stimmen bei serieller, rückwärts serieller und paralleler Poolplanung überein. Zusätzlich werden Kataloge mit nicht zusammenhängenden Purpose-IDs gegen die echte Slot-Zuordnung geprüft.

Der finale vollständige Paketlauf wird nach Abschluss ergänzt. Ein früherer grüner Lauf ersetzt bei späteren Änderungen keine Wiederholung der betroffenen Tests. Native Sanitizer, Zeitmessungen und finale GUI werden getrennt berichtet.
