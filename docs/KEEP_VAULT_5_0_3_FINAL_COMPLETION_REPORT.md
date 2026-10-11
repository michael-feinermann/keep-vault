# Keep Vault 5.0.3/v13, Build 20: aktueller Abschlussbericht

Stand: 11. Oktober 2026. Status: unveröffentlichter macOS-Kandidat `v5.0.3-rc.build20`. Die öffentliche Freigabe ist BLOCKED. Dieser Bericht trennt Produktbytes, echte Testausführung, native Bedienung und Distributionsnachweise. Die Prüfmatrix und älteren Berichte vom 5. Oktober dokumentieren historische Durchläufe und werden durch diesen Bericht nicht rückwirkend verändert.

## Produkt und Quellstand

Der kompilierte Produktquellstand ist `ea0eeecface1a8d16760676c1d6a428baef350c0`. Build 20 bleibt bytegleich. Die unveränderte verwaltete Product-Runtime-DLL für die Produktionsdiensttests hat SHA-256 `86f7e82f53e4754061e5e4f2bd4efeaecc921b189f2a7c70e2448ae29d839501`; die passende Referenz-DLL `70faad170681ba195319a260b346eb310b8a5628a3750ef27c8d33f33b6ab29a`. Diese DLL-Bindung ist kein Ersatz für die eigenständig geprüften nativen AOT-Appinventare.

Der erste Abschlusscommit `0cd37e442dece9d09ef3e5cb56ae9d566ebe88fd` enthält ausschließlich `KeepVaultMac.Tests/TestScheduler.cs`, `docs/releases/v5.0.3.md`, diesen neuen Bericht und die im [Belegmanifest](evidence/v13-build20-final-20261011/public-evidence-copy-manifest.json) einzeln aufgeführten öffentlichen Quittungskopien unter `docs/evidence/v13-build20-final-20261011` als Ergänzung oder Änderung. Der TestScheduler hat SHA-256 `68dc270f22a649bcf53bbe61f7c6b6344b78c20fe0b962417bb131f73f4a3d0d`. Es handelt sich um eine Diagnosekorrektur im Test-Harness. Dieser Commit baut das Produkt nicht neu. Der Kandidatentag bindet diesen ersten Abschlusscommit. Nachgelagerte reine Dokumentationscommits ergänzen den tatsächlichen GitHub-Übertragungsnachweis. Der kompilierte ProductHEAD bleibt separat angegeben; Push und Entwurfsdownload erhalten eigene Distributionsquittungen.

v13 ist absichtlich inkompatibel mit v12. Ressourcensteuerung, beide globalen MACs, vollständige Produktionsschlüsselableitung, native Integritätsprüfung und hybride RSA-4096-/ML-DSA-87-Prüfungen behalten ihre Anforderungen. Dieser Bericht genehmigt keine abgeschwächte Sicherheitsprüfung.

## Echte Prüfungen und erhaltene Fehlversuche

| Befund | Tatsächlicher Status | Umfang |
|---|---|---|
| Vollständige frühere Testmatrix | PASS | 302 eindeutige Fälle mit ursprünglichem Test-Harness; keine Neuausführung durch die Informationsauswertung |
| Frühere Phase 8 | FAIL, Exit 1 | Der ursprüngliche Leistungstest verfehlte eine unveränderte Grenze. Sein Ergebnis bleibt erhalten. |
| Ursprünglicher Build-20-Builder | FAIL, Exit 1 | Der echte ursprüngliche Exit 1 bleibt erhalten. Spätere separate Notarisierungs-, Paket- und Installationsnachweise erzeugen keinen rückwirkenden Builder-PASS. |
| 12 × 1 GiB, Kompressionsstufe 3 | PASS, tatsächlicher Exit 0 | Je eine Suite, voller Produktionsworkflow und vollständiger Hash-/Strukturvergleich. Informationsmessung. |
| Neuer isolierter Diagnosetest-Harness | PASS, tatsächlicher Exit 0 | Neuer TestScheduler; Produkt- und Native-Bytes unverändert. Kein neuer Produktbuild. |
| Infrastrukturtest des neuen Harness | PASS, tatsächlicher Exit 0 | `infra.runner-invariants`, genau ein echter Fall mit passender Inventarbindung. |
| Wiederholung Paranoia, 512 MiB Quelldaten | PASS, tatsächlicher Exit 0 | 149 Dateien, 32 Verzeichnisse, ein reparierter Shard, vollständiger Hash-/Strukturvergleich. Funktional; keine kanonische Phase-49- oder Native-GUI-Freigabe. |
| Vollständige formale 49-Phasen-Abschlussfreigabe | BLOCKED | Keine komplette aktuelle Freigabe aus kontrollierten Leistungs- und nativen Pflichtnachweisen. |
| Öffentlicher Download des Kandidaten | NOT RUN | Der Kandidat ist nicht veröffentlicht. Der authentifizierte Entwurfsdownload besteht separat mit sechs bytegleichen Dateien und beiden Hybrid-Verifierarchitekturen. |

Der erste neue Diagnosetest-Harness-Bauversuch scheiterte real an fehlenden unveränderten Produktdateien. Der korrigierte zweite Bau übernahm diese vorhandenen Eingaben, ohne das Produkt neu zu bauen. Auch der erste Infrastruktur-Aufruf mit `--no-smoke` bleibt als Fehlversuch erhalten: Der Zieltest ist ein Smoke-Test, daher lief kein passender Fall. Der korrigierte Aufruf führte den echten Zieltest aus. Keiner dieser Befunde wird umetikettiert oder als frühere Ausführung angerechnet.

## Diagnosetest-Harness und echte Prozessbindung

Der zweite isolierte Bau wurde am 11. Oktober 2026 um 12:48:33 UTC mit Exit 0 abgeschlossen. Tatsächlicher Bauhelper-Prozess: 29751; tatsächlicher Compilerprozess: 29776. Das Manifest enthält 125 Dateien; die zusätzliche Datei heißt `diagnostic-harness-provenance.json`. Die neue Test-DLL hat SHA-256 `d306be46722ea2a7ca5301501f6a6c1ece1c6f22b08318ac32a61f814a49fea3`. Die alte Test-DLL `55b4409de56f8ac21ff85172adb6db6276e58b83ffeaf252d46d9e3e07348856` bleibt für tatsächlich damit ausgeführte historische Fälle gebunden. Alle 68 Native-Eingaben und die zehn vertrauenswürdigen Native-Eingaben bleiben an ihre ursprünglichen Bytes gebunden.

Der Infrastrukturtest lief danach mit Prozess 30579 unter Supervisor 30571 und echtem Exit 0. Er endete am 11. Oktober 2026 um 13:11:50 UTC und bestätigte genau `infra.runner-invariants`. Die Inventarhashbindung bleibt `2b275841e29601cb690e68c2741203b9470ac037a47641946066d9828579c3cd`. Die freigegebenen Composite-V3-Quellen sind Vorbereitung für eine echte Kampagne, kein Ausführungsnachweis und keine Veröffentlichungsgenehmigung.

## Paranoia-Wiederholung

Der echte Prozess 30680 unter Supervisor 30669 endete am 11. Oktober 2026 um 13:17:50 UTC mit Exit 0. Die Prozessdauer betrug 236,556 Sekunden. Der Baum enthielt 149 Dateien und 32 Verzeichnisse mit leeren, verschachtelten, versteckten und Unicode-Pfaden, 256 MiB vielfältigen Dateien und einer zusätzlichen 256-MiB-Datei, zusammen exakt 536.870.912 Bytes. Kompressionsstufe 3, volle Produktionsschlüsselableitung mit Argon2id t=4 und p=4, vorsätzliche KPAR2-Beschädigung, authentifizierte Reparatur eines Shards, anschließende Extraktion und vollständiger Struktur-/Hashvergleich bestanden.

| Abschnitt des Paranoia-Funktionstests | Zeit: Sekunden | Quelldatendurchsatz: MiB/s |
|---|---:|---:|
| Testdatenaufbau und erster Manifestvergleich, außerhalb des Workflows | 0,653 | |
| Archivieren und verschlüsseln | 104,446 | 4,902 |
| KPAR2 erzeugen | 13,112 | |
| Unbeschädigten KPAR2-Satz prüfen | 5,616 | |
| Beschädigten Satz reparieren | 13,497 | |
| Entschlüsseln und entpacken | 97,759 | 5,237 |
| Abschließender vollständiger Struktur-/Hashvergleich | 0,208 | |
| Übrige Workflowzeit, Gesamt minus aufgeführte Dienstzeiten | 0,401 | |
| Gesamter Workflow | 235,039 | 2,178 |
| Tatsächlicher Testprozess | 236,556 | |

Die drei Raten verwenden jeweils genau 512 MiB ursprünglicher Quelldaten als Zähler. Zeit für Testdatenaufbau gehört nicht zur Workflowzeit. Interne Phasen können sich überlappen und werden nicht zusätzlich summiert. Die öffentliche [Validierung](evidence/v13-build20-final-20261011/paranoia-functional/validation.json), [Prozessquittung](evidence/v13-build20-final-20261011/paranoia-functional/terminal.json) und [Testergebnisse](evidence/v13-build20-final-20261011/paranoia-functional/test-results.json) enthalten die ursprünglichen Werte.

Dieser Lauf ist funktional. Er ist kein kontrollierter Geschwindigkeitsvergleich, keine neue native Bedienprüfung und keine kanonische Abschlussphase 49. Der Mac lief dabei auf Akku. Ein neuer kontrollierter AC-Leistungslauf wurde wegen des Akkubetriebs nicht gestartet.

Die zwölf 1-GiB-Ergebnisse sind zusätzlich als [Originalzusammenfassung](evidence/v13-build20-final-20261011/informationals/informational-summary.json), [tatsächliche Auswertungsquittung](evidence/v13-build20-final-20261011/informationals/auswertung/auswertung-nachweis.json) und je Suite als Ergebnis, Start-/Terminalquittung und unverändertes öffentliches Profil verfügbar.

## Geschwindigkeiten und Zeitaufteilung

Die folgenden Zahlen stammen unverändert aus dem tatsächlich abgeschlossenen Informationslauf. Es gab pro Suite einen Lauf, keinen Median. Ein vollständiger Workflow besteht aus Archivierung, KPAR2-Erzeugung und Prüfung, Extraktion, Originalvergleich und Bereinigung. Die Informationsserie beschädigte das Archiv nicht; der Beschädigungs-/Reparaturfall ist gesondert.

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

## Native Bedienprüfung und Grenzen

Bereits aufgezeichnete reale Bedienprüfungen des installierten Build 20 umfassen öffentliche Kameratestzettel A und B auf einem zweiten Gerät, Standard und Fast mit Erstellung und Extraktion, falsches Passwort, manipulierte Container und v12-Verweigerung, authentifizierte KPAR2-Reparatur sowie Abbruch, Geheimnisbereinigung und erneuten Versuch. Diese Einzelbefunde sind keine vollständige native Gesamtfreigabe.

Im abschließenden nativen Nachweis fehlt weiterhin der frische Paranoia-Durchlauf. Der bestandene Funktionstest oben ist keine native Bedienprüfung. Außerdem fehlen die vollständige Abdeckung Mixed/Single, Ressourcensteuerung, Scrollen und Konsole. Nicht sicher auslösbare native RNG-, Speicherlock- und Cleanupfehler sowie internes Phasen-/Schedulerprofil des installierten AOT-Produkts bleiben LIMITED. Ein PASS des verwalteten Produktionsdienstes oder des Diagnosetest-Harness wird dafür nicht als Native-PASS angerechnet.

Für die öffentliche Freigabe verbleiben konkret die vollständigen Pflichtnachweise zu `five-aead-native-roundtrips`, `entropy-single-round-native`, `entropy-dual-round-native`, `auto-resource-manual-cpu1`, `scrolling-inner-outer-both-directions`, `console-twelve-visible-lines-progress-cancel` und `console-follow-toggle-reflow`, soweit noch keine vollständige aktuelle native Quittung vorliegt. Ebenfalls offen bleiben REV12 Abschnitt 9.1.1 für echte native RNG-, Speicherlock- und Cleanupfehler, Shuffle-/Replay-Abbruch und Single-/Dual-Phasen sowie die internen Paranoia-Leistungsnachweise `V13-PAR-PERF-PROVENANCE`, `V13-PAR-PERF-PHASES`, `V13-PAR-PERF-SCHEDULER` und `V13-PAR-PERF-ENDTOEND`. LIMITED erfüllt diese Pflichtnachweise nicht. Die kontrollierte Phase-8-Leistungsregression und die formale Abschlusschronologie sind offen.

Dieser Durchgang umfasst macOS. Windows und physische Mehr-TiB-Läufe wurden vom Benutzer ausgeschlossen und sind NOT RUN. Die Kamera wurde mit dem Handy geprüft; ein tatsächlicher physischer Ausdruck ist ein gesonderter, hier nicht behaupteter Nachweis.

## Paket, Signaturen und Distribution

Der bestehende Build-20-Paketsatz enthält Keep Vault, QR-Scanner und Installer. Der Paketnachweis und der bytegleiche Installationsnachweis liegen gesondert vor. Am 11. Oktober 2026 um 13:22:14 UTC endete zusätzlich die tatsächliche erneute [lokale Verifikation](evidence/v13-build20-final-20261011/local-candidate-verification/verification.json) mit Prozess 31000 und Exit 0: 19 echte CLI-Prozesse prüften alle sechs Artefakte, beide Hybridalgorithmen und die signierten Hashmanifeste auf ARM64 und x86_64, den kompletten ZIP-Inhalt mit 147 Dateieinträgen und das signierte Installationsinventar. Drei Candidate-Apps sowie die zwei installierten Apps bestanden Apple-Signatur-, Stapler- und Gatekeeperprüfung. Geschützte ZPAQ-/Rollbackanker und die installierten Bytes blieben gebunden. Dies ist kein öffentlicher Downloadnachweis und keine funktionale Gesamtfreigabe. Apple-Signatur, Notarisierung/Stapling/Gatekeeper und hybride RSA-4096-/ML-DSA-87-Signaturen sind unterschiedliche Nachweise. Für den hier vorbereiteten GitHub-Entwurf wird kein neuer Produktbuild und kein erneutes Signieren benötigt. Alle privaten Release-Schlüssel verbleiben ausschließlich im geschützten externen Schlüsselspeicher, die Apple-Identität im Apple-Schlüsselbund.

Der Paketpayload hat SHA-256 `84cc050b2ef5588d882b59e154063e6f62e473763d4dfd484c2e4a5f5536a32e`. Ein unveröffentlichter GitHub-Entwurf darf genau die sechs vorhandenen, signierten Dateien mit folgenden Namen enthalten: `Keep.Vault-macOS-universal.zip`, `.sha3`, `.skein`, `.khsig`, `.sha3.khsig` und `.skein.khsig`, jeweils an denselben Basisnamen angehängt. Die Namensanpassung der lokalen Uploadkopien ändert die Payloadbytes nicht.

Der Kandidatentag ist `v5.0.3-rc.build20`. Der Entwurf bleibt unveröffentlicht, der bestehende Latest-Release und v5.0.2 mit seinen Dateien bleiben unverändert. Eine Entwurfsanlage oder ein Quellenpush ist keine öffentliche Releasefreigabe. Der erneute authentifizierte Download aller sechs Entwurfsdateien ist separat PASS; der anonyme öffentliche Download bleibt NOT RUN, solange der Entwurf unveröffentlicht ist. `publicReleaseApproved` bleibt false.

## Öffentliche Nachweisfingerprints

Die ausgewählten nicht geheimen strukturierten Quittungen sind als bytegleiche [öffentliche Belegkopien](evidence/v13-build20-final-20261011/README.md) mit [einzelner Hash- und Herkunftsliste](evidence/v13-build20-final-20261011/public-evidence-copy-manifest.json) verfügbar. Originale Zeitstempel, PIDs und Befunde sind unverändert. Private Schlüssel, Zugangsdaten, Laufprotokolle, SDK-/Buildcaches und Testcontainer sind nicht enthalten. Die folgenden SHA-256-Werte bezeichnen tatsächlich vorhandene Eingaben und Ergebnisse; das Kopieren ist kein neuer Testlauf.

| Nachweis | SHA-256 |
|---|---|
| Informationsauswertung mit zwölf echten Zeilen | `b9796e7d411ba5972611d90c4266baee2fee9769c5ba5b03cdc99fff5394b4d7` |
| Äußerer Informationslauf, Terminal, Exit 0 | `1a830c1b325139df5d1ff37487b3e0159fb8bb1ce1502660de7e5c346a2aaa8c` |
| Innerer Informationslauf, Terminal, Exit 0 | `5583341e7fb3929a055a7a24043b0fdc86a9db88167e240f5428a81e27aa1fbe` |
| Neuer isolierter Harness, 125-Datei-Manifest | `d4a97c33f21682edfc7dfc0f9f320997056d309ba2c723d0ce17f3b4b7b0e18d` |
| Neuer Harness, äußeres Build-Terminal | `640b0e45ad466c58b3db6984c1b808afa2290ea7e0e146f7680376109acc891d` |
| Neuer Harness, inneres Build-Terminal | `fcff6ed6a8c2edb17d2b8554194195d1ca044ef866ae6507571a28cf6078b50d` |
| Infrastrukturtest, echtes Terminal | `9b42a815222e170cef58ddc3309efdf0f521879f029b9fb2cb93961f0879a998` |
| Infrastrukturtest, echtes Ergebnis | `ce32e1622d7755d314b00a66552e00755db4d3a6069340ff1bfa0c60bf46e22f` |
| Infrastrukturtest, Validierung | `e8e7ac53eac209f72b2cb44f633f9574f4779a1fdeb54b1ed818295369fefbe4` |
| 512-MiB-Paranoia, funktionale Validierung | `de2ecdc70656e529d45f9aa2fda472bf537a25ffbfc2481d3c443819e9832c3b` |
| 512-MiB-Paranoia, echtes Terminal | `6cebd9bfaec0760f339d565fa7afbeceef3705d80b514b59a62a2462464a71d0` |
| Frische lokale Paket-/Apple-/Hybrid-/Installationsprüfung | `5dca8d3744daa9b1fba94b7271ba667feab3c66e2b292b2300529e45d0fb28c0` |
| Bytegleiche finale Installation | `7e302742ab968042d9d1536dbf9badad23dee45af63233a65fc60e516e26d9b1` |
| Composite-V3-Quellenmanifest, nur Quellenvorbereitung | `dea0f5bcefea59c1fa23b6dc488ca3838323d6b55ec08b39e4f6a2911776abcf` |

Der abschließende Quellencommit und die tatsächlichen GitHub-Entwurfs-/Downloadquittungen werden aus dem separaten Distributionsabschluss übernommen. Dieser Bericht behauptet keinen durch seinen eigenen Inhalt nachgewiesenen Quellenpush oder GitHub-Entwurf. Die abgeschlossenen Informations- und Funktionstests bleiben davon unabhängig belegt.

## Tatsächlicher GitHub-Abschluss

Der Quellenpush, [Draft-PR #3](https://github.com/michael-feinermann/keep-vault/pull/3) und der unveröffentlichte Build-20-Entwurf mit Release-ID `409690404` im [GitHub-Releasebereich](https://github.com/michael-feinermann/keep-vault/releases) sind angelegt und geprüft. Der Kandidatentag `v5.0.3-rc.build20` zeigt auf den ersten Abschlusscommit. Der Releasebereich dient als stabiler Eigentümerzugang, weil GitHub den direkten `untagged`-Link eines unveröffentlichten Entwurfs bei Bearbeitung ändern kann. Alle sechs Paketdateien wurden erneut authentifiziert heruntergeladen, mit den lokalen Originalen byteweise und per SHA-256 verglichen und auf ARM64 sowie x86_64 mit beiden Hybrid-Signaturalgorithmen geprüft. [Originalquittung](evidence/v13-build20-github-20261011/github-draft-download-completion.json).

Die bestehende v5.0.2-Release einschließlich aller sechs Assetidentitäten bleibt unverändert; Latest ist weiterhin v5.0.2. Der Mac war für die zusätzliche native Bedienprüfung weiterhin gesperrt. Öffentliche Releasefreigabe bleibt BLOCKED, anonym öffentlich heruntergeladene 5.0.3-Dateien werden nicht behauptet.
