# Paranoia-Leistungsprüfung REV12

Status: IN PROGRESS. Produkt 5.0.3, macOS-Prüfumfang. Dies ist keine Releasefreigabe.

Der Benutzer meldet ungefähr 12 MiB/s bei Paranoia. Messphase, Kompressionsgrad und damaliger sichtbarer Zähler sind nicht belegt; der konkrete Befund bleibt `REPORTED_NOT_REPRODUCED`. Die achtstufige Paranoia darf nicht mit einer Einzelsuite verglichen werden. Der historische Vergleichsstand 536d7c2 verwendet bereits dieselben acht Stufen und GCD Utility.

## Aktueller Stand am 4. Oktober 2026

Die originale gemeinsame Zwölf-Suite-1-GiB-Matrix am quellenstabilen Build171619 ist vollständig PASS, einschließlich der unabhängigen v3a-Schlussauswertung. [Vollständiger Schlussbericht mit Zeiten, Durchsätzen und Phasenaufteilung](evidence/v13-rev12-20261003/workflow-1gib-matrix-171619/final-evaluation-v3a/report.de.md) und [Evaluation](evidence/v13-rev12-20261003/workflow-1gib-matrix-171619/final-evaluation-v3a/evaluation.json) binden alle zwölf terminalen Originalfälle an ihren unveränderten Stufe-5-Stand. Report-SHA-256 `7a92a3ca320774b17edafdb1e7ca89d7f5b77a424ef897b7ae437afadf72f352`, Evaluation-SHA-256 `b40dba76afa2687862455d7ab6cf898c233ddcfd53eadf174b9f4010a59f23ff`. Produktive KDF, beide MACs, KPAR2-Erstellung/intakte Prüfung, vollständiger Struktur-/Hashvergleich und Cleanup sind enthalten; je Suite eine Messung ohne Warm-up oder Median. Dies ist Managed-Service-/Native-Entwicklungsevidenz, keine finale installierte AOT-/GUI- oder Releasefreigabe.

Die spätere ausdrückliche Benutzervorgabe vom 4. Oktober setzt die Kompressionsstufe für neue Testserien auf 3. Die bereits gestartete Zwölf-Suite-Matrix hat ihren identischen vorab festgelegten Stufe-5-Stand vollständig abgeschlossen. Die gemeinsamen Testkonstanten und zugehörigen Beschriftungen sind für zukünftige vollständige Workflow-/Paranoiatests auf Stufe 3 gesetzt, der Produktdefault bleibt unverändert. Der neue quellenstabile Build070335 bindet 284 Sourceinputs, Sourcekarten-SHA-256 `de0b75d9e2f71247a58dc408ac5ea923660064cf4871d595c625722a03b81e04`. Die 24 neuen Stufe-3-Kontrollworkflows sind separat vollständig PASS; das [öffentliche Paket](evidence/v13-rev12-20261003/workflow24-level3-070335/README.md) bindet Zeiten, tatsächliche Bytebasen, Phasen und Originalreceipts. Ursprüngliche Stufe-5-Belege werden nicht umbenannt; feste Golden/KAT-Verträge und produktive KDF bleiben erhalten.

Die neuen 24 Kontrollworkflows für Standard/Paranoia/Camellia/Serpent × 4 KiB/256 MiB × Auto/1/4 sind am frisch gebundenen Build070335 mit Kompressionsstufe 3 vollständig PASS. Das [öffentliche Belegpaket](evidence/v13-rev12-20261003/workflow24-level3-070335/README.md) und die [vollständige Auswertung](evidence/v13-rev12-20261003/workflow24-level3-070335/summary.json) erhalten je Fall einen tatsächlichen Workflow ohne Warm-up oder Median, produktive KDF, beide MACs, KPAR2-Erstellung/intakte Prüfung, produktiven Originalvergleich, unabhängige vollständige Struktur-/Hashgleichheit und Cleanup. Die Summe der 24 gemessenen monotonen Workflowzeiten beträgt 1.290,1936005 s (21:30,2 min). Der separate [UTC-Ausführungsrahmen](evidence/v13-rev12-20261003/workflow24-level3-070335/matrix/executions.json) reicht am 4. Oktober 2026 von 07:07:52,376207 bis 07:29:52,466362 UTC, 1.320,090155 s einschließlich Launcher, Inventuren und Verwaltung. Auswertung-SHA-256 `158f15c2004836319bb920778035921850f4bcf1ed90552240e2cfe83afbc5f9`. Source-/Binary-/Metadatenbindungen sind separat vom alten Stufe-5-Lauf; frische Faktoren schließen einen kontrollierten kausalen CPU-Skalierungsvergleich aus. Die alte vorbereitete Stufe-5-Kontrolladministration und der abgewiesene frühere Stufe-3-Verwaltungsstart (24 NOT RUN, null Produktstarts) bleiben historische Belege. Dies ist Managed-Service-/Native-Entwicklungsevidenz; vollständiger neuer Full301, final gebundene Workflow-/Paranoiatests einschließlich 512-MiB-Baum-/Repairabschluss und Native-/Universal-/AOT-/installierte GUI-/Signatur-/Notarisierungs-/Releasegates bleiben offen.

Der kanonische Entwicklungslauf114541 ist ein eigener PASS, siehe unten. Die 24 produktiven Stufe-3-Kontrollworkflows am Build070335 sind ebenfalls vollständig PASS. Vollständige Neuprüfung gegen frische Native-/Universal-/AOT-Bytes und den installierten finalen Build16 bleiben erforderlich. Rosetta ist inzwischen tatsächlich installiert; der frische Skein-Wipe beider Universal-Slices am Build070335 und der optimierte x86_64-Control10k-Lauf unter Rosetta sind eigene PASS-Belege, keine finale Releasefreigabe. Die folgenden früheren FAILs und der Standardvorlauf154322 behalten ihre damaligen Quellen-/Binary-/Hostbindungen.

## Erhaltene Messungen

Auf dem Apple M5 mit zehn gewährten CPU-Permits wurden jeweils 256 MiB öffentliche Daten in 16-MiB-Aufrufen verarbeitet. Ein 16-MiB-Warm-up ging fünf Messungen voraus. Ciphermediane enthalten Chunkkopien, aber keine KDF, Nonceableitung, globalen MACs, ZPAQ oder Datei-I/O. Die Containerwerte sind gesondert bezeichnet und enthalten die produktive Argon2id-KDF und Authentifizierung vor Entschlüsselung, aber keine ZPAQ-Kompression.

| Messung | Standard | Paranoia | Camellia | Serpent |
|---|---:|---:|---:|---:|
| Historischer Cipher-Kontrolllauf 01.10., macOS 26.6.2 | 643,8 | 146,7 | 349,3 | 830,2 |
| REV11 Cipher-Kandidat 01.10., macOS 26.6.2 | 522,5 | 102,7 | 238,8 | 594,3 |
| REV11 Cipher-Diagnose 03.10., macOS 27.0.1 | 530,8 | 143,8 | 372,8 | 857,2 |
| Historischer Cipher-Kontrolllauf 03.10., macOS 27.0.1 | 689,0 | 148,3 | 364,5 | 809,9 |
| Historischer Container 01.10.: Verschlüsseln | 127,3 | 42,0 | 88,3 | 90,8 |
| Historischer Container 01.10.: Prüfen und Entschlüsseln | 47,9 | 27,4 | 41,0 | 41,9 |
| Historischer Container 03.10.: Verschlüsseln | 135,1 | 45,0 | 84,1 | 82,9 |
| Historischer Container 03.10.: Prüfen und Entschlüsseln | 49,8 | 28,9 | 40,8 | 40,2 |

Alle Werte in MiB/s. Die Rohmessungen, Streuungen, Quellpfade und SHA-256 der Logs stehen in [der REV12-Datendatei](benchmarks/keep-vault-5.0.3-v13-rev12.json). Frühere fehlgeschlagene Läufe bleiben erhalten. Der erfolgreiche historische Kontrolllauf allein gibt den aktuellen Kandidaten nicht frei.

Die Diagnose vom 03.10. verarbeitet die unveränderten REV11-Binaries. Die ARM64-Architektur, die 68 ursprünglichen nativen Eingabepins und die übrigen Harnesspins wurden vor Ausführung überprüft. Dieser Lauf beendet das Vergleichsgate mit `FAIL`, weil das installierte Betriebssystem inzwischen macOS 27.0.1, Build 26A434 ist. Die alte Referenz bindet macOS 26.6.2, Build 25G83. Der Hostvergleich wurde nicht gelockert und die alte Referenz nicht umgeschrieben.

Der zusätzliche unabhängige Lauf der unveränderten historischen Binaries unter macOS 27.0.1 hat alle zwölf Primitive und alle zwölf Container mit produktiver KDF gemessen und die Container authentifiziert/hashverglichen. Die nachgeschaltete historische Pipelineprüfung scheiterte: feste zwei Plätze erreichen 241,3 MiB/s, der beste Kandidat zehn Plätze 277,3 MiB/s, somit 87,0 % bei unveränderter 90-%-Schwelle. Der gesamte historische Lauf bleibt `FAIL`. Seine abgeschlossenen Primitivmessungen bilden ausschließlich eine neue, ausdrücklich auf Primitive begrenzte Referenz mit dem passenden Host. Herkunft, Fehlerstatus und Loghash stehen zusätzlich in `work/v13-evidence/rev11-release-b41144e/publication/historical-536d7c2-macos27-primitive-baseline.json`; dies ist kein vollständiger historischer PASS und keine aktuelle Selbstreferenz.

## Befunde und Grenzen

Der vollständige ARM64-Code aller acht Cipherbibliotheken war zwischen historischem Stand und REV11 identisch. Nur Scratchkopien wurden für den Vergleich von Signaturen befreit; die Originale blieben unverändert. Die kleine Startwegdiagnose zeigte identische QoS-Metadaten, erklärt aber weder Kernbelegung noch tatsächliche CPU-Frequenz während längerer Arbeit. Die beiden Leistungsfehler vom 01.10. sind damit noch nicht erklärt.

Das gesonderte REV12-Stufenprofil ist am 03.10. im gebundenen ARM64-Release-Entwicklungsharness bestanden. Es misst jede Cipherstufe und beide Kaskaden mit tatsächlich gewährten 1, 4 und 10 Workern. Pro Variante folgen auf einen vollständigen Warm-up fünf Messungen; Default und aktivierter Beobachter wechseln in einer vorab festgelegten Reihenfolge. Die vollständigen Ciphertexte und Tagfolgen stimmen über Varianten, Wiederholungen und Grants überein. Der Grant 10 ist eine Cipherdiagnose des aufgelösten CPU-Ceilings und kein Nachweis des adaptiven Containerfensters.

| Cipherprofil vom 03.10. | 1 Worker | 4 Worker | 10 Worker |
|---|---:|---:|---:|
| Standard | 123,34 | 424,36 | 660,40 |
| Paranoia | 25,32 | 88,97 | 153,66 |
| Camellia | 56,26 | 213,07 | 382,09 |
| Serpent | 142,52 | 510,90 | 819,72 |

Alle Werte in MiB/s für genau 256 MiB pro Messung. [Öffentliches vollständiges Stufenprofil](evidence/v13-rev12-20261003/cipher-stage-profile.json) und [Messdaten mit Hashbindung](benchmarks/keep-vault-5.0.3-v13-rev12.json) enthalten Rohzeiten, Streuung, Output-/Taghashes und Binaries. Dies sind Cipherwerte ohne KDF, Kompression, globale MACs, Recovery und Datei-I/O. Der Paranoia-Median mit Beobachter und zehn Workern beträgt 153,04 MiB/s; seine mediane Wandzeit ist hier etwa 0,41 Prozent länger. Das ist eine gemessene Differenz dieses Laufs und keine allgemeine Garantie eines festen Beobachteraufwands.

Das Profil erfasst Wandzeit, gesamte Prozess-CPU-Zeit sowie aggregierte GCD-Queue-, Callback- und Joinintervalle. Callbackintervalle können überlappen; ihre Summen sind keine Operationswandzeit und keine CPU-Zeit. Der Join enthält nützliche Cipherarbeit. Die Beobachtung besitzt keine Permit-, Cancel-, Daten- oder Erfolgsautorität und enthält keine Schlüssel, Nonces oder Klartextreferenzen. Ohne aktivierte Testbeobachtung liest sie keine Uhr.

Der erste aktuelle kanonische Vergleichslauf hat seine Primitivmessungen beendet, bleibt jedoch `FAIL`: Der Launcher übergab einen relativen Baselinepfad, den das Unterverzeichnis `KeepVaultMac` falsch auflöste. Container- und Auto-90-Prozent-Prüfung wurden in diesem Lauf nicht ausgeführt. Der unveränderte negative Lauf bleibt erhalten; die Wiederholung bindet den absoluten Baselinepfad und dessen SHA-256.

Diese Wiederholung hat alle zwölf Primitivvergleiche innerhalb der unveränderten 25-Prozent-Schranke bestanden und alle zwölf Container mit produktiver KDF gemessen. Der Gesamtworker bleibt nach 622,7 Sekunden `FAIL`: Das echte adaptive Auto-Fenster erzielt im gesonderten Pipelinevergleich 365,52 MiB/s gegenüber 409,24 MiB/s beim besten festen Fenster mit zwei Slots, somit 89,32 Prozent bei geforderten 90 Prozent. Die fünf Messrunden und ihre feste Reihenfolge bleiben vollständig erhalten. Dieser fokussierte Slotvergleich verwendet die ausdrücklich benannte 8-MiB-KDF-Testseam; seine Raten sind keine produktiven KDF-Raten.

| Produktiver Containervergleich vom 03.10. | Verschlüsseln | Authentifiziert prüfen und entschlüsseln |
|---|---:|---:|
| Standard | 146,66 | 83,13 |
| Paranoia | 51,41 | 40,21 |
| Camellia | 93,95 | 64,13 |
| Serpent | 99,06 | 63,91 |

Alle Werte in MiB/s, jeweils 256 MiB öffentlicher vorgefertigter Containerpayload, ein vollständiger Warm-up und fünf tatsächliche Messungen, Median. KDF und Container-Authentifizierung sind enthalten; ZPAQ, KPAR2 und Originalvergleich sind nicht Teil dieses Vergleichs. [Unveränderte öffentliche JSON-Marker, Inputinventare und FAIL-Beleg](evidence/v13-rev12-20261003/canonical-before-window-fix/README.md) binden die abgeschlossenen Messungen. Im damaligen Stand waren Ursachenanalyse und tatsächlicher korrigierter Vergleich noch offen; die spätere Entwicklungskorrektur und ihre PASS-Belege stehen unten. Der gemeldete Benutzerfall mit ungefähr 12 MiB/s bleibt weiterhin nicht reproduziert.

Zum damaligen Stand noch offen: bestandener Vergleich des korrigierten adaptiven Auto-Fensters, komplette produktive Archivierungs-/Recovery-Matrix, phasenbezogene Messung mit dem final installierten Build, reale GUI-Zählerbasis sowie Vorher-/Nachhervergleich derselben öffentlichen Eingaben. Der später unten dokumentierte korrigierte Entwicklungsvergleich ist inzwischen PASS; finale installierte Neuprüfungen bleiben erforderlich. KDF, globale MACs, Bereichsprüfung, KPAR2, Originalvergleich und Cleanup werden nicht zur Verbesserung einer Zahl abgeschaltet. Ein Messfehler oder ein anderer Hostzustand wird nicht als schneller gewordene Kryptografie dargestellt.

## Tatsächlich korrigiertes adaptives Fenster

Der vollständige gezielte Pipelinevergleich im Entwicklungsbuild `113438`, Lauf `frozen-performance-20261003T113751Z-2158a5cf`, ist PASS: Auto 393,18 MiB/s, schnellster fester Kandidat ein Slot 423,28 MiB/s, somit 92,89 % bei unverändert verlangten 90 %. Dauer 150,336 s, Spitzen-RSS 2.410 MiB. Ein vollständiger Warm-up und fünf vorab geplante interleaved Wiederholungen je unverändertem Kandidaten sind erhalten; alle 54 Ausführungen werden authentifiziert und vollständig per Klartext-SHA-256 geprüft. [Vollständiges öffentliches Paket](evidence/v13-rev12-20261003/pipeline-after-window-fix/README.md).

Der bestätigte Schedulerfehler war der Verlust des bewährten Durchsatzes beim Wechsel auf ein größeres Fenster. Die Korrektur behält dessen Vergleichsrate während einer begrenzten Probe, kehrt bei mindestens 10 % Verlust sofort zurück und verlangt für Annahme mindestens 5 % Medianvorteil. Der erste Auto-Batch bleibt ein Slot; nur konkret bekannte Restarbeit erlaubt die anschließende Startregel. Schema 3 führt für alle festen und automatischen Kandidaten dieselbe frische OS-Beobachtung und Ressourcenplanung durch. Der frühere Schema-2-FAIL bleibt unverändert; die Messverträge sind ausdrücklich getrennt.

Diese Messung isoliert die Pipeline mit der dokumentierten Test-KDF. Sie ist keine neue Cipher-Kernbeschleunigung, kein Produktions-KDF-End-to-End-Durchsatz und kein Nachweis des final installierten AOT-Produkts. Das kanonische Gesamtgate ist im unten dokumentierten Entwicklungsfreeze PASS. Die 24 neuen Stufe-3-Kontrollworkflows am Build070335 sind vollständig PASS; alle erforderlichen final gebundenen Leistungsgates bleiben gegen den abschließenden Stand zusätzlich auszuführen. Der ursprüngliche ungefähr 12-MiB/s-Benutzerbefund bleibt ohne Reproduktion desselben installierten Wegs offen.

## Kanonischer Gesamtvergleich nach der Korrektur

Der gesamte Worker `performance.cipher-suites` im selben gebundenen Build `113438`, Lauf `frozen-performance-20261003T114541Z-78eb5e77`, ist PASS nach 622,194 s mit Spitzen-RSS 3.838 MiB. Alle zwölf Primitive erfüllen die unveränderte 25-%-Schranke gegenüber der erhaltenen unabhängigen historischen Primitivebaseline. Alle zwölf Containerfälle mit produktiver KDF, einem vollständigen Warm-up und fünf tatsächlichen Verschlüsselungs-/Verifikations- und Entschlüsselungsläufen sind abgeschlossen. Das anschließende getrennte Pipelinegate mit Test-KDF besteht ebenfalls: Auto 389,24 MiB/s, best fixed2 408,11 MiB/s, 95,37 % bei unverändert verlangten 90 %. [Vollständiges öffentliches Paket](evidence/v13-rev12-20261003/canonical-after-window-fix/README.md). Der frühere kanonische FAIL wird dadurch nicht überschrieben.

| Suite | Cipher-only MiB/s | Produkt-KDF-Container verschlüsseln MiB/s | Global prüfen und entschlüsseln MiB/s |
|---|---:|---:|---:|
| Standard | 707,52 | 150,85 | 82,38 |
| Paranoia | 159,37 | 50,79 | 39,45 |
| Camellia | 386,90 | 98,41 | 63,82 |
| Serpent | 911,35 | 101,12 | 63,65 |

Die Zahlen sind Mediane für 256 MiB vorgefertigten öffentlichen Payload, keine vollständige Archivierung mit Kompression, Recovery und Originalvergleich. Die produktiven Gesamtworkflows behalten ihre eigene Phase-/Bytebasis und tatsächliche Laufzahl. Zusätzlich hat der Benutzer je einen neuen vollständigen 1-GiB-Lauf für alle zwölf Suites mit Zeit-/Durchsatz-/Phasenaufteilung beauftragt; diese ausdrückliche Ausnahme ersetzt die bisherigen 256-MiB- und 512-MiB-Fixturegrenzen nicht allgemein. Diese zwölf zusätzlichen Läufe sind am gemeinsamen Build171619 mit Stufe 5 vollständig abgeschlossen und unabhängig mit v3a als PASS ausgewertet. Die 24 neuen Stufe-3-Kontrollworkflows besitzen eigene frische Buildbindungen am Build070335 und sind inzwischen vollständig PASS. Sie bleiben von finalen Native-/AOT-/GUI- und Releasegates getrennt.

## Zusätzlich beauftragte 1-GiB-Matrix

Der spätere ausdrückliche Benutzerauftrag ergänzt je einen vollständigen 1-GiB-Lauf über sämtliche zwölf Suites. Je Case beträgt die tatsächliche Summe aller Quelldateien 1.073.741.824 Byte. Der große Payload ist vollständig öffentliches deterministisches SplitMix64-Pseudorandommaterial; kurze Unicode-Datei, Nullbyte-Datei, leere/versteckte/verschachtelte Unicode-Verzeichnisse gehören zum Baum. Kompressionsstufe5, produktive KDF und beide MACs bleiben unverändert. Gemessen werden Archivierung/Verschlüsselung, authentifizierte KPAR2-Erstellung und gesunde Prüfung, Entschlüsselung/Extraktion, produktiver Originalvergleich, unabhängige vollständige Struktur-/Hashgleichheit und Cleanup. Originale werden nicht gelöscht.

Historischer Startstand am Build154322: Der erste Standardfall war damals IN_PROGRESS und ist inzwischen als separater Vorlauf PASS, siehe unten. Ein nachfolgender gezielter Drop-/Path-Callback-Review begründete eine neue GUI-/Testquellenkorrektur; der bisherige Quellenfreeze wurde vor weiteren Fällen abgeschlossen. Der nachfolgende gemeinsame Zwölf-Suite-Vergleich am Build171619 ist inzwischen unter seinem identischen Build-/Binary-/Sourcefreeze vollständig einschließlich unabhängiger v3a-Auswertung PASS. Die 24 bisherigen 4-KiB-/256-MiB-Kontrollfälle und der letzte 512-MiB-Paranoia-Reparaturabschluss bleiben erhalten.

Eine Workflowwiederholung je Suite ist kein Median. Vollständige Quelldaten werden je Durchsatznenner einmal gezählt. Acht aufeinanderfolgende äußere Zeitintervalle partitionieren die Workflowdauer; überlappende innere KDF-/Cipher-/MAC-/ZPAQ-Messungen werden separat ausgewiesen und nicht addiert. Fixtureerzeugung und Entropievorbereitung sind zusätzlich aufgeführt. CPUzeit ist von real verstrichener Zeit getrennt; die beobachtete ZPAQ-Kinder-CPU kann den letzten unsampled Abschnitt auslassen. Final installierte AOT-/GUI-Leistung bleibt eine eigene offene Prüfung.

## Erste tatsächlich abgeschlossene zusätzliche Standardmessung

Der separate Vorlauf am gebundenen Build154322 ist PASS mit exakt 1 GiB Quelle: Workflow1.485,394170s (24:45min), Erstellung696,279903s (11:36min, 1,470673MiB/s), Entschlüsselung/Entpackung747,881616s (12:28min). KPAR2-Erstellung27,762530s, gesunde authentifizierte Prüfung11,602219s, abschließender Original-/Hash-/Strukturvergleich1,265089s. Drei Dateien und fünf Verzeichnisse entsprechen vollständig der Eingabe. [Vollständiger öffentlicher Extra-Beleg](evidence/v13-rev12-20261003/preliminary-1gib-standard-154322/README.md). Alle Werte sind eine Wiederholung ohne Warm-up, kein Median.

Innerhalb dieser überlappenden Workflowintervalle sind fünf KDF-Runde1-Aufrufe mit insgesamt10,790343s sowie Kalyna1,746946s, Threefish0,992233s und beide XChaCha-AEAD-Richtungen zusammen1,198125s beobachtet. PipeRead690,622967s und PipeWrite736,773637s sowie beobachtete ZPAQ-Kinder-CPU dominieren den vollständigen Durchlauf. Das ist eine Beobachtung an vollständig synthetischen schwer komprimierbaren Daten bei normaler Kompressionsstufe5; nicht die behauptete Erklärung des noch nicht im gleichen final installierten GUI-Pfad reproduzierten gemeldeten12MiB/s-Werts. Phasensummen sind keine additive CPU-/Workflowzeit.

Inprozess-CPU157,781144s; kombinierte beobachtete Prozess-/ZPAQ-Kinder-CPU1.586,181542s, mögliche nicht beobachtete letzte Kinderintervalle ausdrücklich ausgenommen. Fixtureerzeugung1,069402s und Vorbereitung0,084770s sind separat gemessen. Der verwaltungstechnisch verbesserte Launcher und fünf winzige simulierte Fehlerkampagnen sind separat geprüft; sie sind keine Produkt- oder 1-GiB-Ergebnisse. Die anschließende Fullregression164715 ist inzwischen mit 288/301 PASS und 13 FAIL abgeschlossen. Nach strengem Testoraclefix bestehen die zwölf betroffenen Containerfälle frisch am quellenstabilen Build171619; die originale einheitlich gepinnte Zwölf-Suite-Matrix ist an diesem Stand inzwischen vollständig einschließlich v3a-Schlussauswertung PASS. Die nachfolgende neue Stufe-3-Kontrollserie besitzt eigene frische Bindungen am Build070335. Der zusätzliche Standardvorlauf wird nicht als Mitglied dieser Matrix gezählt.
