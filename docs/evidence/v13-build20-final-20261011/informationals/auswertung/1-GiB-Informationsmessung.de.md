# 1-GiB-Informationsmessung, Build 20

Eine echte Informationsmessung je Suite: 1 GiB Quelldaten, drei Dateien und fünf Verzeichnisse, Kompressionsstufe 3, vollständiger Produktionsworkflow mit KPAR2 und Originalvergleich. Die Lastbeobachtungen gelten nur für die Grenzen des Laufs. Keine ruhige Referenzmessung, kein Median, kein kausaler Vergleich der Suites oder CPU-Skalierung und keine Freigabe der 49 Releasephasen. Der ursprüngliche Builder und der ursprüngliche Phase-8-Test behalten Exit 1.

Jede Suite lief einmal. Durchsatz bedeutet MiB ursprünglicher Quelldaten pro Sekunde. Für alle drei Durchsatzspalten zählt genau 1.024 MiB. Die Entpackzeit umfasst Entschlüsselung und Extraktion für den Originalvergleich. Aufbau der Testdateien und Entropievorbereitung stehen außerhalb der Workflowzeit.

| Suite | Archivieren und verschlüsseln: s / MiB/s | Entschlüsseln und entpacken: s / MiB/s | Vollständiger Workflow: s / MiB/s | Testdatenaufbau: s | Entropievorbereitung: s | Testprozess: s |
|---|---:|---:|---:|---:|---:|---:|
| StandardCascade | 267,555 / 3,83 | 251,506 / 4,07 | 557,270 / 1,84 | 1,196 | 0,083 | 558,892 |
| XChaChaOverAes | 268,799 / 3,81 | 250,280 / 4,09 | 558,822 / 1,83 | 0,996 | 0,083 | 560,194 |
| MixedCascade | 270,171 / 3,79 | 250,833 / 4,08 | 561,746 / 1,82 | 1,043 | 0,082 | 563,159 |
| ParanoiaCascade | 280,664 / 3,65 | 260,186 / 3,94 | 586,512 / 1,75 | 1,062 | 0,097 | 587,964 |
| Threefish1024 | 270,917 / 3,78 | 250,032 / 4,10 | 559,432 / 1,83 | 1,051 | 0,084 | 561,302 |
| Kalyna512_512 | 273,853 / 3,74 | 253,061 / 4,05 | 567,580 / 1,80 | 1,176 | 0,089 | 569,430 |
| Shacal2_512 | 272,900 / 3,75 | 258,713 / 3,96 | 570,848 / 1,79 | 1,084 | 0,093 | 572,649 |
| Mars448 | 296,868 / 3,45 | 255,649 / 4,01 | 593,844 / 1,72 | 1,071 | 0,093 | 595,684 |
| Aes256 | 275,255 / 3,72 | 252,620 / 4,05 | 566,994 / 1,81 | 1,055 | 0,086 | 568,443 |
| Camellia256 | 291,343 / 3,51 | 258,900 / 3,96 | 592,750 / 1,73 | 1,058 | 0,088 | 594,624 |
| Serpent256 | 276,017 / 3,71 | 255,563 / 4,01 | 573,508 / 1,79 | 1,076 | 0,087 | 575,347 |
| XChaCha20Poly1305 | 274,464 / 3,73 | 250,960 / 4,08 | 563,693 / 1,82 | 1,160 | 0,084 | 565,558 |

Die folgenden acht äußeren Abschnitte teilen die vollständige Workflowzeit ohne Überlappung auf. Sie enthalten auch die Prüfungen und Buchführung zwischen ihren Grenzen. Die einzelnen Dienstzeiten oben können deshalb etwas kürzer sein. Interne KDF-, Cipher- und MAC-Zeiten können sich überlappen und werden nicht zusätzlich auf diese Summe aufgeschlagen.

| Suite | 1 Aufnahme: s | 2 Archiv: s | 3 Hash: s | 4 KPAR2: s | 5 Prüfung: s | 6 Entpacken: s | 7 Originalvergleich: s | 8 Bereinigung: s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| StandardCascade | 0,008 | 267,558 | 0,524 | 25,603 | 10,654 | 251,506 | 1,328 | 0,089 |
| XChaChaOverAes | 0,009 | 268,803 | 0,521 | 26,622 | 11,166 | 250,280 | 1,320 | 0,102 |
| MixedCascade | 0,008 | 270,174 | 0,507 | 27,352 | 11,466 | 250,833 | 1,321 | 0,084 |
| ParanoiaCascade | 0,009 | 280,667 | 0,524 | 30,581 | 13,101 | 260,186 | 1,351 | 0,095 |
| Threefish1024 | 0,008 | 270,921 | 0,549 | 25,832 | 10,707 | 250,032 | 1,316 | 0,067 |
| Kalyna512_512 | 0,009 | 273,857 | 0,524 | 27,283 | 11,408 | 253,061 | 1,347 | 0,093 |
| Shacal2_512 | 0,009 | 272,902 | 0,524 | 26,310 | 10,910 | 258,713 | 1,374 | 0,108 |
| Mars448 | 0,009 | 296,872 | 0,523 | 27,197 | 12,172 | 255,649 | 1,331 | 0,092 |
| Aes256 | 0,009 | 275,258 | 0,519 | 26,215 | 10,910 | 252,620 | 1,374 | 0,089 |
| Camellia256 | 0,008 | 291,346 | 0,517 | 28,374 | 12,105 | 258,900 | 1,398 | 0,102 |
| Serpent256 | 0,008 | 276,020 | 0,528 | 28,093 | 11,862 | 255,563 | 1,384 | 0,050 |
| XChaCha20Poly1305 | 0,009 | 274,467 | 0,523 | 25,622 | 10,662 | 250,960 | 1,355 | 0,096 |

1: Speicherzulassung und Aufnahme der Originalstruktur. 2: Archivierung und Verschlüsselung. 3: zusätzlicher Containerhash. 4: authentifizierte KPAR2-Erzeugung. 5: Prüfung des unbeschädigten Archivs mit KPAR2. 6: Entschlüsselung und Extraktion. 7: Produktionsvergleich der Originale sowie unabhängiger Hash- und Strukturvergleich. 8: Freigabe eigener Ressourcen und Entfernung der öffentlichen Testdaten.

Die Nebenlast wurde vor und nach dem gesamten Lauf mit jeweils drei ausgewerteten Top-Abtastungen beobachtet. Diese Grenzbeobachtungen belegen keine durchgehend ruhige Umgebung:

| Grenze | CPU-Leerlauf der drei Abtastungen: % | Höchste weitere Prozesslast: % | Medienanalyse: CPU-Obergrenze % |
|---|---|---|---|
| Vorher | 93,32 / 97,90 / 91,20 | 5,90 / 4,00 / 18,00 | 17,80 / 0,20 / 0,50 |
| Nachher | 96,44 / 97,31 / 97,35 | 6,10 / 7,00 / 5,20 | 0,20 / 0,10 / 0,10 |

Die echte Quellen-, SDK-, Installations- und Harnessbindung wurde vom Informationsrunner vor, während und nach den Workflows geprüft. Diese Auswertung wiederholt keine umfangreichen SDK- oder Quellscans. Sie prüft die tatsächlichen Prozessquittungen, Profilhashes und Messwerte. Der kopierte Phase-1-Befund ist ausschließlich eine Inventarreferenz und kein neuer 302-Test-Lauf.
