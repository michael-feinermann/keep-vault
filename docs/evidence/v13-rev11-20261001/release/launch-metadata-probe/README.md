# Kleine Diagnose der beiden Teststartwege

Ausgeführt am01.10.2026 von12:55:46,284 bis12:55:48,148MESZ. Vier Starts mit jeweils eigenem Koordinator und identisch zum TestScheduler selbst gestartetem Worker, insgesamtacht Prozesse und80kurze GCD-Metadaten-Callbacks. Kein Cipherpayload, keine Durchsatzmessung, keine KDF, keine Produkt- oder Testharnessänderung.

| Variante | Start | Sleep-Assertion |
|---|---|---|
| A | zsh, bereinigte Builderumgebung, dotnet run, Apphost, Apphost-Worker | caffeinate -i nur bis Probeende |
| B | Python, bereinigte Ergänzungsumgebung, dotnet DLL, dotnet exec-Worker | keine |
| C | Wie A | keine |
| D | Wie B | caffeinate -i nur bis Probeende |

Alle acht Prozesse lieferten nice0, Taskrolle TASK_UNSPECIFIED0, Base-Latency-/Throughput-Tier0, .NET10.0.11, Workstation-GC und ThreadPool-Minimum10/Maximum32767. Die Metadatengetter für Nice, Kategorie und Base-QoS waren erfolgreich. Mainthreads hatten QoS0x21, .NET-ThreadPool-Threads UNSPECIFIED0 und alle GCD-Callbacks Utility0x11 mit relativer Priorität0. Keine Darwin-Background-, externe Background- oder Suppressionflags waren gesetzt. Das Arbeitsverzeichnis war in allen Varianten das ursprüngliche KeepVaultMac-Verzeichnis.

Beobachtete Unterschiede: Prozesspfad/Apphostname und die SDK-Auflösungsvariable. dotnet run setzte DOTNET_ROOT_ARM64, der direkte Start nutzte DOTNET_ROOT. Nur der Buildernachbau führte die NuGet-Cachevariablen mit. In den beobachteten Thread-/Prozessmetadaten entstand daraus kein Unterschied. Keine beliebigen Umgebungsvariablen und keine privaten Werte wurden ausgegeben.

IOConsoleLocked war vor und nach jeder Variante No. Der zusätzliche ScreenIsLocked-Schlüssel fehlte. Die Probe führte keinerlei Entsperrung aus; dieser Zustand ist ausschließlich eine Beobachtung zu ihrer kurzen Laufzeit.

Die Diagnose belegt keine gleiche CPU-Frequenz, Kernbelegung, Konkurrenzlast oder unveränderte Prozessbehandlung während minutenlanger Cipherarbeit. Sie erklärt die beiden erhaltenen Performancefehler nicht. Insbesondere ist dies kein weiterer Benchmark und kein neuer Performance-PASS.

`results.json` enthält alle Einzeldaten und Aufrufketten; `summary.json` die Zusammenfassung. `build-provenance.json` bindet Probequellen, Probeprogramme und Compileraufrufe. `evidence-index.json` bindet die Ausgaben. Vor und nach der Probe waren alle in der bestehenden Harnessinventur gebundenen Eingabedateien vollständig hashgleich; auch die Diagnoseprogramme blieben während ihrer Ausführung bytegleich. Es wurden keine Produkt-, Kandidaten-, Baseline- oder ursprünglichen Harnessdateien geändert.
