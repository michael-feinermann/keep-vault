# Unabhängige Leseprüfung der tatsächlichen KV13CTL1-10k-Belege

Geprüft wurden ausschließlich die erhaltenen Originalartefakte. Kein neuer Build, Test, Runnerimport oder Executablelauf durch die Reviewer; keine Produktions-, Tool-, SDK-, HEAD- oder öffentlichen Dokumentänderung. Ein unabhängiger Peer prüfte zusätzlich alle tatsächlich inventarisierten Inputs gegen die heutigen Dateien. Der Rootkoordinator berichtet die reale sequenzielle Ausführung nach Ende des gemessenen MARS-Childs. Die Originalreports enthalten keine gesonderten UTC-Start-/Endfelder und beweisen allein keine kontinuierliche Nebenlast- oder Energiebedingung.

## Ergebnis und Hashbindung

Alle drei gespeicherten Läufe sind konsistent PASS für jeweils exakt 10.000 tatsächliche Kontrollkanalfälle, davon 2.500 akzeptierte und 7.500 erwartete Ablehnungen. Es ist derselbe Corpus und derselbe vollständige erwartete/tatsächliche Verdicttranscript-Hash. Die enge ARM64-Controlframing-Lücke besitzt damit jetzt aktuelle optimierte sowie ASan/UBSan- und TSan-Laufzeitbelege. Intel/x86_64 bleibt NOT RUN. Dies ist keine vollständige Native- oder Releasefreigabe.

| Laufordner | Modus | Fälle | Laufzeit laut Report, s | Inputs | Report SHA-256 |
|---|---|---:|---:|---:|---|
| control10k-actual-arm64-20261003T2038 | ARM64, O2/NDEBUG | 10000 | 1.7584800420008833 | 862 | d339c65be50e850776c8d3ff37be2391560dede9e8881792a1ef25f791f240ab |
| control10k-actual-asan-ubsan-20261003T2040 | ARM64, O1, ASan+UBSan | 10000 | 2.6889906669966877 | 863 | a9300c5eabc272d34f15ab165e7bfb36b8d52e96c67815b8b67f32db6c8f27c4 |
| control10k-actual-tsan-20261003T2043 | ARM64, O1, TSan | 10000 | 8.49352791599813 | 862 | b24057bfbea7d0600a150fd69d0c1b81e926bea23db119dcddb9c1728b0b3e4f |

Diese Zeiten sind isolierte Harnesslaufzeiten, keine Archiv-, Cipher- oder Anwendungsdurchsätze. Compile- und Inventarzeit liegen außerhalb des aufgezeichneten Harnessintervalls.

Gemeinsamer Corpus SHA-256: `62fc5b7738245e7537ef320f73ee0d3ced2f30680111baa899247d0fa4f9b7d2`. Gemeinsamer vollständiger Verdicttranscript SHA-256: `d4102a27c87876bcf493197e41dc2cbf458e1dd7c87b9115a5e2fed22645b247`.

Alle Corpusdateien wurden tatsächlich gelesen. Sie enthalten die eindeutigen Indizes 0 bis 9999 und jeweils 625 Fälle in jedem der 16 Modi. Die Randprüfung deckt Magicpositionen 0 bis 7 und jede Headerkürzung 0 bis 47 ab. Die gültigen großen Payloadgrößen sind 0, 1, 1.048.575 und 1.048.576 Byte; der Oversize-Modus deklariert 1.048.577 Byte. Alle zehn Requestkinds sind im Corpus vorhanden. Es sind 10.000 Fälle insgesamt, keine Behauptung von 10.000 Fällen je Kind.

Der vollständige erwartete Verdicttranscript wurde unabhängig aus den 10.000 gespeicherten Corpuszeilen rekonstruiert; sein SHA-256 stimmt in allen drei Reports mit dem dort erhaltenen tatsächlichen Verdicttranscript-Hash überein. Die unveränderte gebundene Runnerquelle verlangt pro Fall den tatsächlich gelesenen exakten Nativefallmarker nach Destruktorjoin sowie abschließend den Komplettmarker, EOF und Childexit 0. Ein separates rohes stdout-Markertranscript wurde vom Runner nicht gespeichert. Die Leseprüfung kann deshalb die vollständigen tatsächlichen Markerbytes nicht nochmals unmittelbar zählen; sie prüft den sourcegebundenen Producerbeleg und den erhaltenen vollständigen Hash. Es wird kein erwartetes Transcript nachträglich als tatsächlich gespeicherte Nativeausgabe ausgegeben.

## Inputs, Binaries und Sanitizer

Vorher-/Nachherinventare sind jeweils vollständig identisch. Der Peer prüfte alle 863 unterschiedlichen Dateien auch aktuell hinsichtlich SHA-256, aufgelöstem Pfad, Größe, dev/inode und mtime/ctime: keine Abweichung. ARM64 und TSan verwenden exakt dieselben 862 Zeilen; ASan/UBSan ergänzt ausschließlich clang21/share/asan_ignorelist.txt.

| Gemeinsamer Input | SHA-256 |
|---|---|
| native/zpaq_control.hpp | 49e451e0713658ad75d44c96d2805cadf22cee9a2f3022153cbe97ef14df147c |
| ursprünglicher control_framing_fuzz.cpp | b7c7fdde2bc8fee7dfe4c5b3c9af41327145c0d22b9575f99ad6ca4005c31493 |
| ursprünglicher run_control_framing_fuzz_macos.py | 0eef36ecf3d6edfa379f69dd63a5f0ace497ecbc3d1b78fc09327ac4a2f12fda |
| clang++ auf physischem clang | 1590ac950a3d627817d09ade5cb60b2115f17a72182a3141e010b4bcc482a0c9 |
| SDKSettings.json | 7b93ad7e534cc4b31c6a4e39d19b5e0288acf2168c2649479a796d1cb51939fb |
| Python-Executable | 2477b47fa3ae65b9574eb18a15edb364e96948eaa1875ad3f1c80d780efc9c12 |
| ASan-ignorelist | f0180e94133315446c6e45287e1801e70ea94de1905a237c974627a732ebeadc |

Gespeichert sind Apple clang21.0.0 (clang-2100.3.34.2), Target arm64-apple-darwin27.0.0, SDK27.0, macOS27.0.1 ARM64 und Python3.14.5. Compile-/Dependencycommands verwenden denselben tatsächlichen Header über -I, C++17/pthread/-arch arm64 und denselben SDK. Optimierung und Sanitizerflags unterscheiden sich genau wie geplant; Sanitizermodi benutzen O1/g/fno-omit-frame-pointer und address,undefined beziehungsweise thread. Unveränderte C++-/Python-Reproduktionsquellen entsprechen exakt dem vor den Läufen geprüften work-Vorschlag.

| Tatsächlich erhaltenes Testbinary | SHA-256 vor = nach = heute |
|---|---|
| control-framing-arm64 | d68bb9b3881dfa87bc536b73617bdfb62e95cddeb705c883653bddf2007226a9 |
| control-framing-asan-ubsan | b44f0d8cd8dc2102a2ededb90b9148da97c70eefc1c68051075c9890cbb3da92 |
| control-framing-tsan | 20d890d80e1361cfcafd32605fdfdd9ba2d4ffd93a8321c6a88b15377a9f005f |

Reine Mach-O-Inspektion mit file/otool/nm bestätigt alle drei als ARM64-Executables. ASanbinary referenziert die ASan-Dynamiclibrary und tatsächliche ASan-/UBSan-Callbacks; TSanbinary referenziert die TSan-Dynamiclibrary und tatsächliche TSan-Callbacks. Es wurden keine Binaries ausgeführt. Alle build.stdout-, build.stderr- und run.stderr-Dateien sind tatsächlich leer. Jeder Report meldet stderr_bytes_seen=0 und stderr_capture_truncated=false; Observer-/Failurefelder fehlen. Keine Diagnostik wurde durch eine gekürzte Capture verdeckt.

Tatsächliche Wirehashes unterscheiden sich teilweise. Das ist mit den ausdrücklich erlaubten Reihenfolgen zweier nativer Caller sowie dem Duplicate/Reject-Rennen vereinbar: jeder tatsächliche Request wird individuell gegen den bytegenauen Normvertrag geprüft. Corpus- und Verdicttranscript sind zwingend identisch. Eine pauschale Wirehashgleichheit zwischen Sanitizermodi wird nicht als Gate erfunden.

## Verbleibende Grenzen

Geprüft ist die tatsächliche unveränderte native control_channel-Klasse mit unabhängigem Python-48-Byte-Big-Endian-Wireoracle, echten Requests, Parent-PID-Vertrag, Closeack und Readerjoin. Nicht geprüft sind vollständige source_entry-Anwendungsmetadaten, komplette CPU-/Memorygrant-Lebenszyklen, private UINT64-Sequenzerschöpfung oder injizierte Threadstartfehler. Ebenso offen bleiben Windows und heutiges Intel/x86_64. LeakSanitizer ist deaktiviert; kein Leakfreiheitbeweis.

Die Inputbindung enthält tatsächliche Compilerbinary/Dependencyheader/SDKdescriptor sowie Runner/Harness/Python-Executable. Sie bindet nicht pauschal sämtliche Linker-, dynamischen Sanitizer- oder Systemruntimekomponenten, den vollständigen Python-Framework-/Standardbibliotheksbestand oder finale signierte Produktartefakte. Das ist eine konkrete enge aktuelle Controlframingprüfung mit den genannten Sanitizern und keine hermetische Gesamttoolchain-, installierte GUI- oder Releasefreigabe.

## Empfehlung für ein unverändertes öffentliches Belegpaket

Root kann ausschließlich unter `docs/evidence/v13-rev12-20261003/native-control10k-20261003/` ein neues separates Paket anlegen:

1. Originalreports, corpus.ndjson sowie alle drei leeren build.stdout/build.stderr/run.stderr-Dateien je Modus bytegleich in drei separaten Unterordnern kopieren. Die drei erhaltenen Testbinaries können zusätzlich als ungeänderte reine Evidenz aufgenommen werden; sie sind keine signierten Produkt- oder Releaseassets. dSYM bleibt optional. Keine Compiler-, SDK- oder Pythonbinaries/-Headerbestände kopieren.
2. `reproduction/control_framing_fuzz.cpp` und `reproduction/run_control_framing_fuzz_macos.py` bytegleich aus dem ursprünglichen Proposalordner übernehmen. Deren ursprüngliche PROPOSAL/NOT-RUN-Kommentare werden zur Erhaltung der sourcegebundenen Bytes nicht umgeschrieben. Der Paket-README erklärt ausdrücklich, dass diese Kommentare den Vorbereitungsstand beschreiben und die drei neuen Originalreports anschließend tatsächlich ausgeführte Läufe belegen. Bei Reproduktion wird der Root/native-Header mit dem oben gebundenen SHA verwendet; zukünftige Ergebnisse gehören in frische ignorierte work-Verzeichnisse.
3. Diese unabhängige Reviewkopie und einen knappen README mit exakter enger ARM64-/ASan-/UBSan-/TSan-Aussage, aktuellem Intel-NOT-RUN und den Scopegrenzen hinzufügen. Alle Originalpfade und Reportfeldwerte erhalten; keine Marker-, UTC- oder Exitlogs erfinden.
4. Über das fertige Paket ein vollständiges SHA256SUMS mit relativen Pfaden erzeugen und jede Kopie gegen die Originalbytes prüfen. Kein bestehendes historisches Paket oder ursprünglicher Proposalbeleg wird überschrieben. Keine Produktions- oder TestSourceänderung und kein neuer Test ist dafür erforderlich.

Konkrete Findings: keine widersprüchliche Input-/Corpus-/Verdict-/Binary-/Stderrbindung in den drei erhaltenen Originalbelegen gefunden. Die ausdrücklich benannten Provenienz- und Scopegrenzen bleiben bestehen. Dieses Review aktualisiert selbst keine öffentlichen Gate- oder Release-PASS-Aussagen.
