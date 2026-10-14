# Tatsächliche native KV13CTL1-Control10k-Belege

Dieses Paket enthält drei tatsächlich ausgeführte, unabhängig gelesene ARM64-Läufe gegen die unveränderte native `control_channel`-Klasse aus `native/zpaq_control.hpp`. Jeder Originalreport belegt PASS für genau 10.000 Kontrollkanalfälle, davon 2.500 akzeptierte und 7.500 erwartete Ablehnungen. Intel/x86_64 ist NOT RUN. Das Paket ist keine vollständige Native-, installierte Anwendungs- oder Releasefreigabe.

| Lauf | Ergebnis | Fälle | Isolierte Harnesslaufzeit, s |
|---|---|---:|---:|
| [ARM64, O2/NDEBUG](arm64/report.json) | PASS | 10000 | 1.7584800420008833 |
| [ARM64, ASan und UBSan](asan-ubsan/report.json) | PASS | 10000 | 2.6889906669966877 |
| [ARM64, TSan](tsan/report.json) | PASS | 10000 | 8.49352791599813 |

Diese Zeiten sind Harnesslaufzeiten, keine Archivierungs- oder Ciphergeschwindigkeiten. Der Koordinator führte die drei Läufe sequenziell nach Ende des gemessenen MARS-Workflows aus. Die Reports besitzen keine eigenen UTC-Laufgrenzen und beweisen allein keine kontinuierlichen Energie- oder Nebenlastbedingungen.

## Originale und Bindung

Die je fünf Originaldateien `report.json`, `corpus.ndjson`, `build.stdout.txt`, `build.stderr.txt` und `run.stderr.txt` stammen bytegleich aus diesen erhaltenen work-Verzeichnissen:

- `control10k-actual-arm64-20261003T2038`
- `control10k-actual-asan-ubsan-20261003T2040`
- `control10k-actual-tsan-20261003T2043`

Die beiden Dateien unter `reproduction/` stammen bytegleich aus `work/v13-evidence/rev12-development-20261003/native-evidence-reuse-readonly-20261003/proposal/`. Ihre ursprünglichen PROPOSAL/NOT-RUN-Kommentare beschreiben den Vorbereitungsstand. Die drei später erzeugten Originalreports belegen die tatsächlichen ausgeführten Läufe. Die [unveränderte unabhängige Reviewkopie](READ_ONLY_REVIEW.md) entstand vor Zusammenstellung dieses Pakets; ihre Paketempfehlung ist hier erfüllt. Originalpfade und Reportfeldwerte bleiben erhalten. Testbinaries und dSYM sind nicht Teil dieses Pakets; die Reports enthalten ihre vorherigen und nachherigen SHA-256-Werte.

Alle drei vollständigen Corpusdateien haben SHA-256 `62fc5b7738245e7537ef320f73ee0d3ced2f30680111baa899247d0fa4f9b7d2`; der erwartete und tatsächliche vollständige Verdicttranscript-Hash lautet jeweils `d4102a27c87876bcf493197e41dc2cbf458e1dd7c87b9115a5e2fed22645b247`. Der verwendete Produktionsheader hat SHA-256 `49e451e0713658ad75d44c96d2805cadf22cee9a2f3022153cbe97ef14df147c`. Die genauen Toolchain-, Eingabe- und Binarybindungen stehen in den Originalreports und im Review.

Alle 18 Originalkopien einschließlich Reproduktionsquellen und Review wurden beim Zusammenstellen erneut bytegleich geprüft. `SHA256SUMS` enthält sämtliche 19 Nutzdateien einschließlich dieses README; die Prüfsummendatei enthält sich selbst nicht. Prüfung aus diesem Paketverzeichnis:

```sh
/usr/bin/shasum -a 256 -c SHA256SUMS
```

## Scope und Grenzen

Der unabhängige Python-Wireoracle prüft den 48-Byte-Big-Endian-Vertrag, echte Requests, Parent-PID, Closeack und Readerjoin. Der gleiche seeded Corpus enthält 16 Modi mit jeweils 625 Fällen, alle zehn Requestkinds, Headerkürzungen 0 bis 47 und die Payloadgrenzen um 1 MiB. Alle Build-/Stderrdateien sind tatsächlich leer; die Stderrcapture wurde nicht gekürzt. ASan/UBSan und TSan sind getrennte tatsächliche ARM64-Läufe.

Ein rohes stdout-Markertranscript wurde vom Runner nicht gespeichert; die Bindung besteht aus den erhaltenen vollständigen Verdict-Hashes und der unveränderten prüfenden Runnerquelle. Es werden keine Marker, Exitlogs oder UTC-Zeitpunkte nachträglich erfunden. Offen bleiben vollständige `source_entry`-Anwendungsmetadaten, CPU-/Memorygrant-Lebenszyklen, private UINT64-Sequenzerschöpfung und Threadstart-Faultinjektion. LeakSanitizer ist deaktiviert. Die Bindung umfasst tatsächliche Compiler-/Dependencyheader-/SDKdescriptor-Inputs, jedoch nicht sämtliche Linker-/System-/Sanitizerruntimes oder den vollständigen Python-Framework-/Standardbibliotheksbestand.

## Spätere Reproduktion

Der Python-Wireoracle erzeugt und prüft den Normvertrag unabhängig vom Produktionscodec; der C++-Harness verwendet die tatsächliche native `control_channel`-Klasse. Der Runner verwendet den Header unter `--source-root/native`, kompiliert und führt den gewählten Harness tatsächlich aus. Ein neuer Lauf gehört in ein bisher nicht vorhandenes ignoriertes work-Verzeichnis, erst nach Ende anderer Geschwindigkeitsmessungen. Beispiel für eine spätere bewusste ARM64-Ausführung mit ersetzten Pfaden:

```sh
/usr/bin/python3 reproduction/run_control_framing_fuzz_macos.py \
  --mode arm64 --source-root /path/to/Kalyna \
  --output-dir /path/to/Kalyna/work/control10k-fresh-arm64 \
  --report /path/to/Kalyna/work/control10k-fresh-arm64/report.json
```

Für getrennte neue Sanitizerläufe sind `--mode asan-ubsan` beziehungsweise `--mode tsan` und jeweils eigene neue Ausgabeverzeichnisse vorgesehen. Dieses Paket hat beim Zusammenstellen keinen neuen Build, Test oder Runnerimport ausgelöst. Die ursprünglichen Belege bleiben unverändert erhalten.
