# Tatsächlicher x86_64/Rosetta-Control10k-Beleg

Dieses neue Paket sichert den tatsächlichen optimierten x86_64-Lauf gegen die unveränderte native `control_channel`-Klasse aus `native/zpaq_control.hpp`. Der dünne x86_64-Harness wurde auf dem M5-Mac ausdrücklich über `/usr/bin/arch -x86_64` unter Rosetta ausgeführt. Der native Pythonparent lief als ARM64. Das ist kein Lauf auf nativer Intel-Hardware und keine finale AOT-, GUI-, Signierungs- oder Releasefreigabe.

| Lauf | Originalstatus | Tatsächliche Fälle | Akzeptiert | Erwartete Ablehnungen | Isolierte Harnesszeit, s |
|---|---|---:|---:|---:|---:|
| [x86_64, O2/NDEBUG, Rosetta](x86_64-rosetta/report.json) | PASS, Childexit 0 | 10000 | 2500 | 7500 | 2.317280750008649 |

Die Zeit stammt unverändert aus dem tatsächlichen Report und ist keine Archivierungs- oder Ciphergeschwindigkeit. Compile- und Inventarzeit liegen außerhalb dieses Harnessintervalls. Der Report enthält tatsächliche UTC-Felder für Vorbereitung, Start und Abschluss; deren Grenzen werden nicht nachträglich als identische monotone Harnessdauer ausgegeben. Ein einzelner Lauf begründet keinen Median, keinen kontrollierten Leistungsvergleich der CPU-Architekturen und keinen kontinuierlichen Energie- oder Nebenlastnachweis.

## Originale und tatsächliche Bindung

Die fünf Dateien unter `x86_64-rosetta/` stammen bytegleich aus `work/v13-evidence/rev12-development-20261003/control10k-actual-intel-rosetta-20261004T0702/`. Dies sind `report.json`, der vollständige öffentliche `corpus.ndjson` und die tatsächlich leeren Dateien `build.stdout.txt`, `build.stderr.txt` und `run.stderr.txt`. Der Report meldet `stderr_bytes_seen = 0` und `stderr_capture_truncated = false`. Es wurde keine Diagnostik gekürzt oder nachträglich erzeugt.

Die drei Dateien unter `comparison/` stammen bytegleich aus `control10k-actual-architecture-comparison-20261004T0703/`. Die [ursprüngliche deutsche Auswertung](comparison/README.de.md) und [Comparisonreceipt](comparison/comparison.json) führen den tatsächlichen historischen ARM64-Lauf und diesen neuen tatsächlichen x86_64/Rosetta-Lauf getrennt auf. Der originale `comparison/SHA256SUMS.txt` bleibt unverändert und prüft nur seine ursprünglichen beiden Nachbardateien. Das neue vollständige Paketmanifest ist `SHA256SUMS` im Paketroot.

Das [historische ARM64-/Sanitizerpaket](../native-control10k-20261003/README.md) und sämtliche ursprünglichen work-Reports wurden durch diese Veröffentlichung nicht verändert. Seine damaligen Intel-NOT-RUN-Aussagen beschreiben den Stand vom 3. Oktober. Der neue Intel-PASS stammt ausschließlich aus seinem eigenen späteren Originalreport. Dieser Lauf ist optimiert ohne Sanitizer; die vorhandenen ASan/UBSan- und TSan-Belege bleiben ausschließlich ARM64-Belege.

| Gebundene öffentliche Eingabe oder Beleg | SHA-256 |
|---|---|
| tatsächlicher Intelreport | `cc3c52dbc7376ff4ef017b202f1db8c6648657fedd31ad34fc4d6c6b5d822422` |
| vollständiger gemeinsamer Corpus | `62fc5b7738245e7537ef320f73ee0d3ced2f30680111baa899247d0fa4f9b7d2` |
| erwarteter und tatsächlicher vollständiger Verdicttranscript | `d4102a27c87876bcf493197e41dc2cbf458e1dd7c87b9115a5e2fed22645b247` |
| tatsächliches x86_64-Testbinary, vor und nach dem Lauf | `80db156153f329ab2c75c506853cd01461ee45ae88929b747860077ae71e3c00` |
| unveränderter Produktionsheader | `49e451e0713658ad75d44c96d2805cadf22cee9a2f3022153cbe97ef14df147c` |
| unveränderter C++-Harness | `b7c7fdde2bc8fee7dfe4c5b3c9af41327145c0d22b9575f99ad6ca4005c31493` |
| tatsächlicher Intelrunner | `919ef129e00275fcadbf1a8b5ded775280edc9b4e4c8bbe79a25bb06334e4835` |
| tatsächlicher Architekturreporter | `a7f5225351f491872eb5db7db25f29dfa55000809656df19034087b60f44ddaf` |

Die erhaltenen Vorher-/Nachherkarten des Intelreports sind vollständig identisch und enthalten jeweils 866 tatsächliche Inputzeilen. Die Binaryidentität ist ebenfalls vor und nach dem Lauf identisch. Der Report erhält Compile-/Dependencycommands mit `-arch x86_64`, das tatsächlich gelesene dünne x86_64-Mach-O-Headerformat, den expliziten arch-Aufruf, Pythonparent-PID 14313 und Child-PID 14326. Der sourcegebundene Runner verlangt die produktive Parent-/Socketpeer-Authentisierung des unveränderten Konstruktors für jeden Fall. Es werden keine fehlenden ARM64-PID-, Exit- oder UTC-Felder ergänzt.

## Öffentliche Quellkopien und Erhaltung

Die drei Dateien direkt unter `reproduction/` stammen bytegleich aus `intel-control10k-proposal-20261004/`. Der zusätzliche `reproduction/native/zpaq_control.hpp` ist eine bytegleiche Kopie des tatsächlich im Intelreport gebundenen Produktionsheaders. Die beiden Dateien unter `native-evidence-reuse-readonly-20261003/proposal/` sind die tatsächlich gebundenen ursprünglichen ARM-Proposalquellen. Diese Verzeichnisanordnung erhält den relativen Originalquellenvertrag des unveränderten Intelrunners. Dessen ursprüngliche PREPARED/NOT-RUN-Kommentare beschreiben den früheren Vorbereitungsstand; der später gespeicherte Originalreport belegt den tatsächlichen Lauf.

Alle 14 Originalkopien wurden beim Zusammenstellen bytegleich geprüft. Die [Kopierreceipt](COPY_VERIFICATION.json) nennt für jede Kopie Originalpfad, SHA-256 und Größe. Quell-/Corpuskopien entsprechen den tatsächlichen Reportpins; die Reporterquelle entspricht dem ursprünglichen Comparisonpin. Das neue Paket bewahrt sämtliche Originalpfade und Reportfeldwerte. Testbinary, dSYM und Compiler-/SDK-/Pythonbestände werden nicht mitveröffentlicht. Die Kopierprüfung ist keine erneute Inventur aller heutigen SDK- und Runtimeinputs.

`SHA256SUMS` bindet sämtliche Nutzdateien dieses neuen Pakets und enthält sich selbst nicht. Prüfung aus dem Paketverzeichnis:

```sh
/usr/bin/shasum -a 256 -c SHA256SUMS
```

## Enge Aussage und verbleibende Grenzen

Der unabhängige Python-Wireoracle prüft den 48-Byte-Big-Endian-Vertrag, echte Requests, den tatsächlichen Parent-PID-Vertrag, Closeack und Readerjoin. Der gleiche seeded Corpus enthält 16 Modi mit je 625 Fällen, alle zehn Requestkinds, Headerkürzungen 0 bis 47 und Payloadgrenzen um 1 MiB. Dies sind 10.000 Fälle insgesamt. Tatsächliche Wirehashes dürfen zwischen Läufen wegen zweier Caller und Reject-Rennen abweichen; Corpus und vollständiger Verdict sind gleich. Jeder jeweilige Runner verlangt seinen eigenen bytegenauen Wireoracle.

Ein rohes stdout-Markertranscript wurde vom Runner nicht als separate Datei gespeichert. Die erhaltene Bindung besteht aus den vollständigen Verdict-Hashes und der unveränderten prüfenden Runnerquelle. Es werden keine tatsächlichen Markerbytes nachträglich aus einem erwarteten Transcript erfunden. Der Originalreport enthält diesmal den tatsächlichen Childexit 0 und die tatsächlichen PIDs; diese ergänzen keine fehlenden historischen ARM-Felder.

Offen bleiben vollständige `source_entry`-Anwendungsmetadaten, komplette CPU-/Memorygrant-Lebenszyklen, private UINT64-Sequenzerschöpfung und Threadstart-Faultinjektion. LeakSanitizer ist deaktiviert. Die Inputbindung umfasst tatsächliche Compiler-, Dependencyheader-, SDKdescriptor-, Runner-, Harness-, Python-Executable-, arch- und xcrun-Inputs, aber keine hermetische Inventur sämtlicher Linker-, System-, Rosetta-, Python-Framework- oder Standardbibliotheksruntimes. Dieser Lauf belegt weder vollständige Native-Sicherheit noch Windows, native Intel-Hardware oder ein final signiertes Anwendungsartefakt.

## Spätere bewusste Reproduktion

Eine spätere echte Reproduktion benötigt eine passende macOS-Toolchain und Rosetta und gehört nach Ende konkurrierender Geschwindigkeitsmessungen in ein frisches ignoriertes work-Verzeichnis. Die unveränderte Intelquelle kann mit `--mode x86_64`, `--source-root <absolutes Paketverzeichnis>/reproduction`, `--output-dir <neues work-Verzeichnis>` und `--report <neues work-Verzeichnis>/report.json` verwendet werden. Ein solches neues Ergebnis ersetzt diesen Originalbeleg nicht. Der unveränderte Architekturreporter liest zusätzlich die in seinen Originalreports genannten tatsächlichen Binarypfade; diese Binaries sind im work-Bestand erhalten und nicht Bestandteil des öffentlichen Pakets.

Beim Zusammenstellen dieses Pakets wurden keine Runner-/Reportermodule importiert, kein Build oder Test gestartet und keine Produktions-, Tool-, SDK-, HEAD- oder ursprünglichen Evidencebytes verändert.
