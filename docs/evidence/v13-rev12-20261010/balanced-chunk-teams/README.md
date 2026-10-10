# Ausgeglichene CPU-Freigaben, 10. Oktober 2026

Der reguläre Build 18 endete am 8. Oktober tatsächlich mit Exit 1. Full302 und sechs zusätzliche funktionale Phasen waren PASS. Das Auto-Performancegate war FAIL: 345,034 gegenüber 386,667 MiB/s, also 89,234 % bei unveränderter 90-%-Schwelle. Die nachfolgenden 41 regulären Phasen liefen nicht. Die ursprünglichen Terminalbelege bleiben unverändert.

Ein bestätigter Schedulingbefund wird korrigiert: Gleich große Chunks teilen die frisch beobachtete CPU-Kapazität per Quotient und Rest. Zehn CPUs und drei Chunks erhalten 4+3+3 Freigaben, vier Chunks erhalten 3+3+2+2. Tatsächliche Leases bleiben global begrenzt und prüfen die Verfügbarkeit erneut. Kryptografie, Pufferbesitz und Abbruchbarrieren bleiben erhalten.

Die heutige vorab deklarierte Diagnose führte den ursprünglichen und den korrigierten Managed-Harness jeweils genau einmal mit dem unveränderten Benchmark aus. Jeder Benchmark besitzt neun Modi, einen ausgeschlossenen Warm-up und fünf vorab durchmischte Messrunden pro Modus. Alle 54 Proben werden authentifiziert und außerhalb der Zeitmessung per vollständigem Klartext-SHA-256 geprüft. Die 256-MiB-Payload ist vorkomprimiertes öffentliches synthetisches Testmaterial; die KDF ist ausdrücklich isoliert. Beide Messungen liefen auf Akku bei zehn logischen CPUs, 16 GiB und macOS 27.0.1. Signierte Nativebytes wurden unverändert aus installiertem Build 18 verwendet. Dies sind Entwicklungsdiagnosen, keine neuen Universal-/AOT- oder 1-GiB-Kompressionsworkflows.

Beide Worker endeten tatsächlich mit Exit 0:

| Stand | Auto MiB/s | Bester fester Modus | Dessen MiB/s | Auto-Anteil | Dauer |
|---|---:|---:|---:|---:|---:|
| Ursprünglicher Build 18 | 399,527 | 1 | 419,998 | 95,126 % | 150,551 s |
| Ausgeglichene Freigaben | 381,592 | 2 | 413,810 | 92,214 % | 150,053 s |

Eine allgemeine Auto-Beschleunigung ist damit nicht belegt. Die festen Fenster 3, 4 und 6 verbesserten sich von 362,455/318,864/329,414 auf 382,073/379,777/388,412 MiB/s. Die korrekt verteilten Freigaben sind außerdem mit echten gleichzeitig blockierten Callbacks, konkurrierender Reservierung, Abbruch, vollständigem Join und Permit-Rückgabe geprüft. Alle zwölf Suites erzeugen weiterhin bitgleiche Containerbytes unabhängig von der Parallelität. Die historische 90-%-Schwelle und der frühere FAIL bleiben erhalten.

Die kontrollierten Inputs waren vor und nach beiden Messungen unverändert. Vollständige öffentliche Fensterprofile stehen in den beiden samples.json. `paired-result.json` und die terminal.json halten Umfang und tatsächliche Exitcodes fest. `source.diff` bindet den damaligen uncommitteten Produkt- und Testpatch am ursprünglichen HEAD 7f174f8. Nachfolgende Build-19-Metadaten und Releasebelege sind davon getrennt.

Funktionale Originalbelege liegen unter `work/v13-evidence/rev12-balanced-chunk-teams-focused-continuation-20261010T063602Z/` (vier PASS) und `work/v13-evidence/rev12-balanced-chunk-teams-byte-equivalence-20261010T063642Z/` (zwei PASS). Der erste Ergebniswrapper hatte nach erfolgreicher Kompilierung und erstem PASS einen eigenen Schemafehler (`testId` statt `id`) und endete mit 1. Die getrennte Fortsetzung verwendet das tatsächliche Schema.

Build 19 benötigt eigene finale Pakete, Funktions- und Leistungsphasen sowie reale installierte GUI-Nachweise. Dieses Paket erteilt keine Releasefreigabe.
