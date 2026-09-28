# ActivePrefix-v3: Nonceprüfung für 5.0.3 REV9

28. September 2026. Der Dateiname folgt dem vom Auftrag verlangten Prüfartefakt; der geprüfte Vertrag ist REV9 mit zwölf Suites und acht Paranoiastufen. Dieser Bericht übernimmt keine früheren Revision-5-/Revision-6-PASS-Ergebnisse.

## Vertrag und geprüfte Abgrenzung

Alle Suites speichern B1 vollständig mit 320 Byte. Paranoia speichert zusätzlich B2 mit 320 Byte. `ChunkNoncePlan` unterscheidet diese gespeicherte Basis von der aktiven Stufenbreite W. Für Kapazität m=5 beziehungsweise m=10 aktiviert es ausschließlich k=ceil(W/64) Blöcke. Jeder aktive Block bindet die normativen Domains, Version 13, Suite-ID, exakten Algorithmusstring, m/k/W, BE64-Chunkindex, BE32-Blockindex und ausschließlich seinen eigenen 64-Byte-Basisblock. Die Stage-Nonce ist unmittelbar das W-Byte-Präfix der aneinandergereihten SHA3-512-Ergebnisse. Eine zweite Stageprojektion existiert nicht.

| Suite-ID | W in Byte | m | k / SHA3-Rotationen | Reserveblöcke |
|---|---:|---:|---:|---:|
| 0 Kalyna | 64 | 5 | 1 | 4 |
| 1 Threefish | 128 | 5 | 2 | 3 |
| 2 Standard | 232 | 5 | 4 | 1 |
| 3 Paranoia | 312 | 10 | 5 | 5 |
| 4 XChaCha/AES | 40 | 5 | 1 | 4 |
| 5 AES | 16 | 5 | 1 | 4 |
| 6 MARS | 16 | 5 | 1 | 4 |
| 7 SHACAL-2 | 32 | 5 | 1 | 4 |
| 8 XChaCha | 24 | 5 | 1 | 4 |
| 9 Mixed | 168 | 5 | 3 | 2 |
| 10 Camellia | 16 | 5 | 1 | 4 |
| 11 Serpent | 16 | 5 | 1 | 4 |

Für jede Tabellenzeile ist die zusätzliche Anzahl von Stagehashes null. Die konstante AAD-Identität wird einmal je Operation aus der vollständigen Basis gebildet; der Threefish-Tweak wird einmal aus dem vollständigen B1 und dem exakten Threefish-Stufenindex gebildet. Die reservierten Bytes ändern deshalb weder die rohen aktiven Stage-IVs noch deren Hashzahl. Sie bleiben im authentifizierten Header und der AAD-Identität gebunden. B1-Reserve kann zusätzlich den Threefish-Tweak beeinflussen. Keine Aussage dieses Berichts setzt rohe IV, AAD und Tweak gleich.

Paranoia behält zwei vollständige KDF-Runden mit vier paarweise unterschiedlichen Salzen. Seine fünf B2-Blöcke sind derzeit Nonce-Reserve; daraus folgt keine Erlaubnis, die zweite KDF-Runde zu streichen oder bloße Reservemutation als frische aktive Zufallsparameter auszugeben. Die acht Cipherrollen erhalten getrennte Stufen-/Cipher-Kontexte und 440 Byte Ciphermaterial insgesamt.

## Neue Referenzen und frische Ergebnisse

`KeepVaultMac.Tests/Fixtures/V13Reference/nonce_rev6_reference.py` ist eine unabhängige Python-Transkription des in REV9 abgedruckten öffentlichen Referenzalgorithmus. Die 84 eingefrorenen Fälle decken alle zwölf Suites und sieben Indizes bis über die 32-Bit-Grenze ab. Fixture-SHA256:

`AC9D8078DE8E1B410E1BCE6E4F1F1B7110081B3044777090FE897D2E977A7C7C`

`check_nonce_vectors.py` prüft schreibgeschützt gegen die eingefrorene Datei, weist 16 gezielt manipulierte Kandidaten zurück und bestätigt unveränderte Referenzbytes. Das C#-Gate pinnt denselben SHA256. Weder Produktimplementierung noch Testlauf erzeugen ihre eigenen erwarteten Noncewerte neu.

Die fünf Gruppen `v13-nonce-vectors`, `v13-nonce-plan`, `v13-nonce-isolation`, `v13-nonce-capacity` und `v13-nonce-faults` wurden nach den Hash-Cleanupänderungen erneut erfolgreich ausgeführt. Hinzu kommen frische `v13-std-nonces-aad`, `v13-std-tweak`, `v13-std-layout`, `v13-std-catalog` und `v13-header-canonical-fields`. Die Einzelprotokolle liegen unter `work/v13-evidence/`.

Geprüft werden Blocklokalität, Reserve-Unverändertheit der aktiven IVs, vollständige AAD-/Tweak-Bindung, exakte aktive Hashzahl, direkte Slices, Kapazitätsgrenzen bis k=10 über eine isolierte Testplanoberfläche, Abbruch und Löschung nach injizierten Fehlern. Die produktive Planerstellung akzeptiert ausschließlich registrierte Katalogobjekte; die größere Testkapazität erweitert keine produktive Suite.

64-Bit-Indexvektoren sind Ableitungstests. Sie belegen keinen entsprechend großen tatsächlichen Archivlauf und heben das eigenständige [kryptographische Nutzungsbudget](KEEP_VAULT_V13_CRYPTO_USAGE.md) nicht auf. Native Cipher-, vollständige Header-/Container-/Recovery-Gates und der reale strukturtreue Paranoialauf bleiben eigene Nachweise. Das Entfernen unnötiger Hashaufrufe allein ist kein gemessener Durchsatzgewinn.
