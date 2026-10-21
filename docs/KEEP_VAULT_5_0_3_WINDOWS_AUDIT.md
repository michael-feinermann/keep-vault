# Keep Vault 5.0.3: Windows-Prüfbericht

Stand: 21. Oktober 2026. Der signierte Windows-x64-Build des Produktquellstands
`c5f4f256c9494147d08055a1deb5f9513a11af26`, seine Vollsuite und die finale
Paketabnahme sind bestanden. Die separate Leistungsprüfung dieses Kandidaten ist
`FAIL`: Auto erreicht 156,14 MiB/s gegenüber 190,31 MiB/s mit einem festen Slot
(82,0 % statt der geforderten mindestens 90 %). Die Veröffentlichung bleibt
gesperrt. Eine korrigierte Ressourcenplanung benötigt einen neuen signierten
Build und erneut gebundene Abschlussprüfungen.

Die Umsetzung folgt dem GitHub-v13-Stand
`ba9949ad1b93a89f75dd8078414371d1a1b7ad0d` mit den unten beschriebenen
Windows-Korrekturen. Gebaut und geprüft wurde unter `C:\Dev\Kalyna` in einem
unveränderlichen Quellsnapshot. Der vorhandene macOS-Release `v5.0.3` bleibt
erhalten. Für Windows ist das getrennte Tag `v5.0.3-windows` am tatsächlich
kompilierten Produktquellstand vorgesehen.

## Änderungen

- Windows-Kompilierungsfehler der WPF- und nativen Komponenten behoben; native
  Sicherheitsflags und Warnungsfehler für Adapter bleiben erhalten.
- Das signierte Installationsinventar verlangt die kompilierte Produktversion
  5.0.3. Authentisch signierte Inventare mit 5.0.2 oder 5.0.4 werden abgelehnt.
- Der native ZPAQ-Kontrollkanal verwendet getrennte überlappte Windows-I/O-
  Vorgänge und wartet deren Ende vor dem Freigeben der Handles ab. Abschluss-
  Antworten werden streng nach Typ, Sequenz und leeren Feldern geprüft.
- Die verwaltete Windows-Pipe benötigt nach vollständig abgewarteten Schreib-
  vorgängen keinen weiteren Flush. Eine sofort nach der gültigen Antwort
  schließende Gegenstelle löst dadurch keinen nachträglichen Fehler aus.
  Echte Schreibfehler bleiben Fehler; das macOS-Verhalten ist unverändert.
- Extraktions-Staging übernimmt eine reduzierte Kopie des bereits gebundenen
  Verzeichnishandles. Identität, Umbenennungs- und Reparse-Schutz bleiben erhalten.
- Die globale Prüfung eines reparierten Archivs übernimmt einen nur lesenden
  Handle des exklusiv gebundenen Reparaturkandidaten. Die ursprüngliche
  Transaktion behält ihre Commit-/Löschrechte; ein erneutes Öffnen über den Pfad
  oder eine Lockerung der Dateifreigaben entfällt.
- Vier eingefrorene v13-JSON-Referenzen behalten auf Windows ihre ursprünglichen
  LF-Bytes. Vektoren und kryptografische Hash-Pins werden nicht geändert.
- Die Entropie-Testdaten werden abwechselnd in die elf Pools geschrieben.
  Anzahl und Inhalt der Prüfungen bleiben erhalten; dadurch entfällt die
  künstlich erzwungene ungenutzte Windows-Speicherreservierung bei jedem
  einzelnen Ereignis. Der gesonderte Test einer schiefen Poolverteilung bleibt
  bestehen. Alle elf Suite-Pläne, der direkte Plan sowie Ergebnis-, Fehler-
  und Abbruchregressionen bestehen mit unverändertem Produktcode.
- Die abgeleiteten Faktorfelder erhalten den vorhandenen dunklen WPF-Stil.
- Eine Folgekorrektur der Auto-Pipeline sammelt zunächst eine warme Ein-Slot-
  Referenz, berücksichtigt Planungs- und Bereinigungszeiten und begrenzt neue
  Wachstumsversuche durch gemessene Anlaufkosten und verbleibende Arbeit.
  CPU-/Speicher-/Warteschlangengrenzen und die 90-%-Leistungsschwelle bleiben
  erhalten. Die gezielten Planungsregressionen und der unveränderte komplette
  Pipeline-Vergleich bestehen im Entwicklungsbuild: 97,6 % des besten festen
  Fensters. Das ist noch kein Abschlussnachweis eines neuen signierten Pakets.
- SDK `10.0.402`, Laufzeit und PKCS-Abhängigkeit `10.0.13` ersetzen den
  verwundbaren Zwischenstand. Release-Restores behandeln NuGet-Meldungen
  NU1901 bis NU1904 als Fehler.

## Tatsächlich geprüfte Ergebnisse und Umfang

| Prüfung | Ergebnis und Grenze |
| --- | --- |
| Signierter c5-Build | Erfolgreich; alle 4820 inventarisierten Quelldateien nach Build, Abnahme und Vollsuite unverändert |
| Vollsuite | **109/109 Gruppen PASS**, null FAIL/BLOCKED, tatsächlicher Prozess-Exit 0; Ergebnis-Head exakt c5, Windows x64 |
| Finale Paketabnahme | **40/40 Fälle, 81 tatsächlich abgewartete Verifier-/Setup-Aufrufe**, Exit 0. Paket, ZIP, externe Verifier-Dateien und isolierte Installation ohne neue Verknüpfungen geprüft; fehlende/veränderte/zusätzliche Dateien, Sidecars, ZIP-Manipulation sowie Reparse-/Hardlink-Fälle abgewehrt |
| Erhaltung | Originalpaket, alle zwölf externen Assets, Quellen und vorhandene Benutzerverknüpfungen unverändert; alle sieben Erhaltungsprüfungen bestanden |
| QR-Scanner | **151 Arbiter-/Decoder-Prüfungen** im erfolgreichen c5-Releasebuild; kein realer Kameratest |
| Native Quellprüfung | Im c5-Build 433 externe Dateien, drei Windows-Pins und 202 Crypto++-Übersetzungseinheiten geprüft |
| Kontrollkanal | Im frischen c5-Build **224 erfolgreiche aktuelle Lebenszyklen** über echte Windows-Pipes; Handle-Zahlen stabil. Der verzögerte historische Negativfall erreicht nachweislich den Abschluss und läuft erwartungsgemäß ins Zeitlimit |
| Native Windows-CI | Exakt c5, [Run 39664877104 / Job 119447160304](https://github.com/michael-feinermann/keep-vault/actions/runs/39664877104/job/119447160304): Build, aktiver Defender und Kontrollkanal erfolgreich |
| Windows-Pipe und Reparaturleser | Abschluss-/Schreibfehler-, Dateifreigabe-, Identitäts-, Abbruch- und Reparaturregressionen bestehen in der c5-Vollsuite |
| WPF | Alle fünf GUI-Gruppen bestehen in der c5-Vollsuite. Die gesonderte frühere Stilprüfung umfasst acht statische DE/EN-Renderings; deren ursprünglicher Head und begrenzter Umfang bleiben dokumentiert |
| Realer Desktopstart | Die signierte installierte c5-Testkopie startet tatsächlich: Version 5.0.3, Integrität und gepinnter QR-Begleiter bestanden, Capture-Status „active“ über Accessibility beobachtet. Navigation ist **nicht bestätigt**; dies ist keine visuelle Freigabe oder unabhängige Messung der Capture-Blockade |
| Acht Windows-Projekte | Frühere Komponentenprüfung mit SDK 10.0.402/Laufzeit 10.0.13: Locked Restores und Produktionsbuilds ohne Compilerwarnungen/-fehler; direkte/transitive NuGet-Abfragen ohne gemeldete Schwachstellen. Der Releasefehler-Gate wurde mit einem verwundbaren synthetischen Paket geprüft |
| Native Analyse | Frühere Komponentenprüfung: Exit 0, null Fehler, **300 erhaltene Herstellerwarnungen**, Adapterprüfung mit `/WX` bestanden. Keine Behauptung eines warnungsfreien nativen Builds; der Produktions-Kontrollheader ist unverändert |

Die Quellinventare vor und nach dem Build besitzen denselben SHA-256:
`DA6445706CFCFEED0F9A2097CBA08E8572F19DF05548D707A19FD96B0D689940`.
Die Erhaltungsaussage umfasst inventarisierte, eingecheckte Eingaben und deren
Bytes; zulässige Build-/Testausgabeverzeichnisse sind getrennt davon.

Die kompakten, hashgebundenen Nachweise stehen unter
[evidence/windows-5.0.3-20261021](evidence/windows-5.0.3-20261021/README.md).
[Vollsuite](evidence/windows-5.0.3-20261021/final-full-results.json),
[Vorlauf mit Quell-/Test-DLL-Bindung](evidence/windows-5.0.3-20261021/final-full-preflight.json),
[Paketabnahme](evidence/windows-5.0.3-20261021/acceptance-summary.json),
[Erhaltung](evidence/windows-5.0.3-20261021/acceptance-preservation.json) und
[Status](evidence/windows-5.0.3-20261021/gate-status.json) behalten ihren tatsächlichen
Umfang. Der Vollsuite-Ergebnis-SHA-256 ist
`0146145C73164A155F257C2412BFD22DE77172078E7E1BB0FDEA89A3B5157CDA`,
der Abnahme-Ergebnis-SHA-256
`AD3144145E0E4CEF05AD16B2CADB5936B1B381A62D1721C2C5A3582B9D0C3695`.
Alle Belegdateien und die bytegleichen verwendeten Runner sind zusätzlich im
lokalen Dateiinventar gebunden. Skripttext allein gilt nicht als Ausführungsbeleg.

Frühere Komponentenbelege werden nicht nachträglich als c5-Läufe bezeichnet.
Überholte oder fehlgeschlagene Kandidatenläufe zählen nicht als Abschlussprüfung.
Die historische macOS-Serie mit 49 Gates liegt außerhalb dieses Windows-Berichts.

## Lokale Artefakte vor der Veröffentlichung

| Datei | SHA-256 |
| --- | --- |
| `Keep Vault-portable-win-x64.zip` | `25056074E5DAAF065F16DFD91B554D6688D1D58533CF77D91A86AEFCD7FB9722` |
| `Keep Vault Release Verifier-win-x64.exe` | `D83362A556FFEB42C316F20D33729F7B34748C509CBC01BE91655E8ED9AC9E8C` |

Alle zwölf Dateien einschließlich Sidecars stehen mit Größen sowie SHA-256 und
SHA-512 im [lokalen Artefaktinventar](evidence/windows-5.0.3-20261021/normalized-publication-assets.json).
Die Namen mit Punkten sind für den GitHub-Upload vorbereitet. Noch wird kein
Upload oder erfolgreicher öffentlicher Download behauptet.

## Signierung und Public Keys

Der Windows-Release verwendet die getrennt gepinnte RSA-4096-/ML-DSA-87-
Produktionsidentität. Zertifikat-Thumbprint:
`7BA65B5130F34AB9F15C0D074699D46D9BCCD21C`.
RSA-SPKI-SHA-256:
`D0C5454E2C122FFD03D6F265876468E3935537FF6BB312EEEE48D883A889CFBB`.
ML-DSA-Public-Key-SHA-256:
`B3CF5B4465033351222AC5D6E1CC20F66432BB18AEC623EF76BB2C7823812219`.
Die vollständigen öffentlichen Pins stehen in
`WindowsRelease/Signing/Directory.Build.props`.

Die gewünschten öffentlichen Dateien liegen unter `A:\Keep Vault Keys`:
Zertifikat, RSA-PEM, ML-DSA-Public-Key, öffentliche Build-Pins, SHA-256-Inventar
und Erläuterung. Ihre Bytes wurden erneut geprüft. Private Schlüssel wurden
nicht dorthin exportiert. Das selbstsignierte Zertifikat installiert keine
allgemeine Windows-Vertrauenswurzel.

## Noch offene Abschlussprüfungen

| Gate | Aktueller Stand / nachzutragender Beleg |
| --- | --- |
| Separate Leistungstests | **FAIL für c5**: Auto nur 82,0 % des besten festen Fensters; [tatsächlicher abgelehnter Lauf](evidence/windows-5.0.3-20261021/superseded-c5-performance-summary.json). Ein korrigierter Kandidat benötigt neue Abschlussbelege |
| GitHub-Veröffentlichung | **PENDING**; Release-URL, Windows-Tagziel, tatsächliche Assetnamen/-IDs/-Digests und Prüfung aller zwölf authentifiziert sowie anonym frisch heruntergeladenen Dateien ergänzen; `--latest=false`, macOS-Tag/-Assets unverändert nachweisen |

Die vor dem Auto-Fehler abgeschlossenen zwölf c5-Primitivmediane bleiben als
eng begrenzte Vergleichsreferenz erhalten. Das macht den abgelehnten c5-
Gesamtlauf nicht erfolgreich. Ein Vergleich mit einer früher freigegebenen
Windows-Version oder einem unabhängigen nativen historischen Benchmark,
reale Kamera- und Papierprüfungen, andere DPI-/Hardwarekonfigurationen, physische Mehr-TiB-Läufe,
ein externer Kryptografie-/Sicherheitsaudit sowie vollständige interaktive
Navigation und Benutzer-Sichtfreigabe sind **nicht nachgewiesen**. Ein Start-
oder Statusnachweis ersetzt diese Abläufe nicht.

v13 liest und schreibt ausschließlich v13; v12-Archive benötigen eine passende
frühere Version und werden nicht automatisch konvertiert.
