# Keep Vault 5.0.3: Windows-Prüfbericht

Stand: 21. Oktober 2026. Die abschließende Windows-Paketprüfung läuft noch;
dieser Zwischenstand erteilt keine Releasefreigabe. Der Quellstand folgt dem
GitHub-v13-Stand `ba9949ad1b93a89f75dd8078414371d1a1b7ad0d` mit den hier
beschriebenen Windows-Korrekturen. Gebaut und geprüft wird unter `C:\Dev\Kalyna`.
Der bestehende macOS-Release `v5.0.3` bleibt erhalten. Für Windows ist ein eigener
Tag `v5.0.3-windows` vorgesehen, der auf den tatsächlich kompilierten Stand zeigt.

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
- SDK `10.0.402`, Laufzeit und PKCS-Abhängigkeit `10.0.13` ersetzen den
  verwundbaren Zwischenstand. Release-Restores behandeln NuGet-Meldungen
  NU1901 bis NU1904 als Fehler.

## Bisher tatsächlich geprüfte Ergebnisse

| Prüfung | Ergebnis und Grenze |
| --- | --- |
| Acht Windows-Projekte | Locked Restore und Produktionsbuild erfolgreich, null Compilerwarnungen/-fehler; direkte und transitive NuGet-Abfragen ohne gemeldete Schwachstellen |
| Native Quellprüfung | 433 externe Dateien, drei Windows-Pins und 202 Crypto++-Übersetzungseinheiten geprüft |
| Native Analyse | Exit 0, null Fehler, 300 beibehaltene Herstellerwarnungen; Adapterprüfung mit `/WX` bestanden |
| Kontrollkanal | 224 tatsächliche Durchläufe bestanden; verzögerter historischer Negativfall läuft erwartungsgemäß ins Zeitlimit; Handle-Zahlen stabil |
| Windows-Pipe-Abschluss | Deterministische asynchrone Regression einschließlich echter Schreibfehler bestanden; zuvor fehlgeschlagener Traversal-Fall 20/20 bestanden |
| Gebundener Reparaturleser | Kernel-Schreib-/Löschverbote, exklusive Freigaben, falscher Pfad, Abbruch und Eigentümer-Lebensdauer bestanden; tatsächliche KPAR2-Grenzfallgruppe bestanden |
| WPF | Fünf GUI-Testgruppen bestanden; acht statische DE/EN-Ansichten geprüft. Diese Renderings sind kein Nachweis einer realen Desktop-, Kamera- oder Papierprüfung |

Eine vorläufige Paketabnahme des später zu ersetzenden Standes `865b965` bestand
40/40 Fälle mit 81 abgewarteten Verifier-/Setup-Aufrufen. Quellen, zwölf externe
Assets, Paketdateien und vorhandene Benutzerverknüpfungen blieben unverändert.
Diese Abnahme wird am endgültigen Ersatzkandidaten wiederholt.

Die lokalen Originalbelege liegen unter
`work/windows-503-20261021`: insbesondere `native-analysis-final-result.json`,
`dependency-security/result.json`, `close-flush-summary.json`,
`focused-gui2-results.json` und `gui-render-review.md`. Frühere fehlgeschlagene
Paketläufe bleiben erhalten und gelten nicht als bestandene Abschlussprüfung.

## Signierung und Public Keys

Der Windows-Release verwendet die getrennt gepinnte RSA-4096-/ML-DSA-87-
Produktionsidentität. Zertifikat-Thumbprint:
`7BA65B5130F34AB9F15C0D074699D46D9BCCD21C`.
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

Der endgültige unveränderliche signierte Build, dessen vollständige Testsammlung,
separate Leistungstests, Paket-/ZIP-/Installer-Manipulationsprüfung, reale
Desktop-Prüfung und der GitHub-Upload mit erneutem Download sind noch offen.
Abschließende Commit-, Paket- und Download-Hashes werden erst nach tatsächlichem
Abschluss ergänzt.

Reale Kamera- und Papierprüfungen, andere DPI-/Hardwarekonfigurationen, physische
Mehr-TiB-Läufe und ein externer Sicherheitsaudit sind bislang nicht nachgewiesen.
v13 liest und schreibt ausschließlich v13; v12-Archive benötigen eine passende
frühere Version und werden nicht automatisch konvertiert.
