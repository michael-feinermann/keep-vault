# Windows 5.0.3: kompakte Nachweise

Produktquellstand: `c5f4f256c9494147d08055a1deb5f9513a11af26`, Windows x64.
Diese Sammlung enthält überprüfte Kopien und klar bezeichnete Zusammenfassungen.
`SHA256SUMS.txt` bindet die Datei-Bytes; `.gitattributes` verhindert deren
Zeilenenden-Normalisierung. Die vollständigen lokalen Diagnoseprotokolle bleiben
unter `C:\Dev\Kalyna\work\windows-503-20261021` erhalten.

| Dateien | Umfang |
| --- | --- |
| `build-result.json`, `source-inputs-summary.json` | Erfolgreicher signierter c5-Build; 4820 unveränderte inventarisierte Quelldateien |
| `final-full-preflight.json`, `final-full-receipt.json`, `final-full-results.json` | Quellmanifest und Test-DLL vor dem Lauf gebunden; tatsächlich beendete Vollsuite, Exit 0, c5-Head, 109/109 Gruppen PASS |
| `acceptance-*.json` | Finale c5-Paketabnahme: 40 Fälle, 81 abgewartete Verifier-/Setup-Prozesse; Originale, Quellen und Benutzerverknüpfungen unverändert |
| `qr-tests-summary.json`, `native-source-summary.json` | Zusammenfassungen tatsächlicher Zeilen des erfolgreichen c5-Buildlogs, gebunden an dessen SHA-256; 151 QR-Prüfungen und aktuelle native Quellpins |
| `control-lifecycle-summary.json` | Frischer c5-Buildlauf: 224 erfolgreiche aktuelle Pipe-Lebenszyklen, stabil gemeldete Handle-Zahlen und nachgewiesener historischer Negativfall; keine Roh-Streams kopiert |
| `native-ci-receipt.json` | c5-GitHub-Job aus Run `39664877104`: native Quellen bauen, aktiver Defender und Kontrollkanal; ersetzt keine lokale Vollsuite |
| `desktop-startup-receipt.json` | Tatsächlicher Start der signierten installierten Testkopie über Accessibility beobachtet; Navigation nicht bestätigt, visuelle/hardwarebezogene Freigabe nicht durchgeführt |
| `normalized-publication-assets.json`, `local-artifacts-sha256.txt` | Alle zwölf akzeptierten lokalen Dateien und geplante GitHub-Namen mit Punkten; keine Behauptung eines Uploads/Downloads |
| `public-key-export.json` | Hashes der öffentlichen Exporte unter `A:\Keep Vault Keys` |
| `dependency-security-result.json`, `managed-warning-summary.json` | Frühere SDK-10.0.402-/Laufzeit-10.0.13-Komponentenprüfungen für acht Windows-Projekte; kein eigenständiger c5-Vollsuitebeleg |
| `native-analysis-result.json` | Frühere native Analyse: null Fehler, 300 erhaltene Herstellerwarnungen; der Produktions-Kontrollheader ist unverändert. Der damalige SDK-Pfad bleibt im Originalbeleg sichtbar |
| `focused-gui-results.json`, `static-gui-summary.json`, `static-gui-review.md` | Frühere fokussierte GUI-/Stilprüfung und Hashes von acht synthetischen DE/EN-Renderings. Der frühere Head wird beibehalten; die fünf GUI-Gruppen bestehen zusätzlich in der c5-Vollsuite |
| `gate-status.json` | Begrenzter Status dieses Dokumentationsstandes; c5-Leistungstest `FAIL`, Veröffentlichung gesperrt |
| `superseded-c5-performance-*.json` | Tatsächlicher abgelehnter c5-Leistungslauf: Auto erreicht 82,0 % des besten festen Fensters; Ergebnisse, Prozessbeleg und Messwerte bleiben historische Fehlerbelege |
| `superseded-c5-primitive-*.json` | Tatsächlich abgeschlossene Primitivmessungen des später abgelehnten c5-Kandidaten als eng begrenzte Vergleichsreferenz. Die öffentliche Ansicht entfernt den stabilen Rechneridentitätshash; alle zwölf Mediane bleiben erhalten. Dies ist kein bestandener Gesamtlauf und keine freigegebene historische Windows-Version |

Die archivierten `invoke-final-package-acceptance.ps1` und `run-final-suite.ps1`
sind bytegleiche, geprüfte Kopien der verwendeten lokalen Runner. Ihre Hashes
stehen in `harnesses.json` und im Dateiinventar. Die Ausführung wird durch die
Ergebnisbelege dokumentiert; der Skripttext allein ist kein Ausführungsnachweis.
Für eine Wiederholung sind die Runner zuerst in ein frisches ignoriertes
Arbeitsverzeichnis zu kopieren. Nicht in dieser Belegsammlung ausführen:
der Vollsuite-Runner schreibt relativ zu seinem eigenen Verzeichnis.

Das Feld `Preserved` im Vollsuite-Preflight bindet ausschließlich zuvor
weggelegte historische 485-Belege. Dort ist die frühere Vollsuite `FAIL`; das
alte Ergebnis einer einzelnen bestandenen Gruppe ist ebenfalls kein c5-
Vollsuitebeleg. Diese historischen Dateien werden nicht als neue Erfolge gezählt
und ihre Rohprotokolle sind nicht Teil dieser Sammlung.

Nicht enthalten sind private Schlüssel, rohe geschützte Desktop-Ausgaben,
Benutzerverknüpfungszustände, lange Rohprotokolle oder unklar zugeordnete
Kandidatenbelege. Die ausdrücklich als `superseded-c5` bezeichneten Dateien
behalten ihren Fehler- beziehungsweise eingeschränkten Vergleichsumfang.
Reale Papier-/Kameraabläufe, andere DPI-/Hardwarekonfigurationen, physische
Mehr-TiB-Läufe, ein externer Kryptografieaudit und ein unabhängiger historischer
Windows-Leistungsvergleich sind nicht nachgewiesen. Die historische macOS-
Prüfserie mit 49 Gates ist kein Windows-Nachweis und wird hier nicht mitgezählt.

Die c5-Leistungsprüfung ist fehlgeschlagen. Ein korrigierter Produktquellstand
benötigt einen neuen Build und neue Abschlussbelege. Erst nach deren tatsächlichem
Erfolg werden Performance und Veröffentlichung aktualisiert; c5-Fehlerbelege
bleiben als solche erhalten.
