# Windows 5.0.3: kompakte Nachweise

Produktquellstand: `103e87fd6335bdc4ef8a2ffafa2384ecaad6504b`, Windows x64.
Die tatsächlichen Kernprüfungen dieses Kandidaten sind abgeschlossen. SHA256SUMS.txt
bindet die gespeicherten Bytes; Skripttext allein belegt keine Ausführung.

| Dateien | Umfang |
| --- | --- |
| `build-result.json`, `source-inputs-summary.json` | Tatsächlicher signierter Build; 4861 frisch nachgeprüfte, unveränderte inventarisierte Quelldateien |
| `final-full-*.json` | Exakter Quellstand/Test-DLL vor dem Lauf gebunden; 109 eindeutige Windows-x64-Gruppen PASS, tatsächlicher Exit 0 |
| `acceptance-*.json` | Finale Abnahme mit 40 Fällen und 81 tatsächlich abgewarteten Verifier-/Setup-Prozessen; Originale/Quellen/Verknüpfungen laut Erhaltungsbeleg unverändert |
| `qr-tests-summary.json`, `native-source-summary.json` | Tatsächliche 151 QR-Prüfungen und native Quellpins; abgeleitete Zusammenfassungen mit Original-Loghash und Zeilen |
| `control-lifecycle-summary.json`, `native-ci-receipt.json` | Frische 224 aktuelle Pipe-Lebenszyklen und erfolgreicher exakter GitHub-Quellstand; keine Roh-Prozessbäume kopiert |
| `desktop-startup-receipt.json` | Tatsächlicher Start der signierten installierten Testkopie beobachtet; Navigation/visuelle Hardwarefreigabe behalten ihren begrenzten Originalstatus |
| `normalized-publication-assets.json`, `local-artifacts-sha256.txt` | Alle zwölf akzeptierten lokalen Ausgangsdateien und GitHub-Namen mit Punkten; tatsächliche Veröffentlichung separat belegt |
| `public-key-export.json`, `public-key-current-validation.json` | Unveränderte öffentliche Exporte unter A:\Keep Vault Keys, frisch mit dem neuen Kandidaten abgeglichen |
| Frühere Komponentenbelege | Abhängigkeiten, native Analyse mit 300 Herstellerwarnungen und synthetische GUI-Renderings behalten ihren ursprünglichen Umfang und Head |
| `superseded-*.json` und zugeordnete Archivdateien | Bytegleiche historische Kandidatenbelege; die Mapping-Datei erhält Originalnamen, Hashes und Geltungsumfang. Keine neuen Erfolge |
| `gate-status.json` | Leistung `PASS`; Veröffentlichung `PASS` nach tatsächlichen passenden Belegen |

`evidence-index.json` benennt ursprüngliche und abgeleitete Nachweise separat.
Die archivierten Runner sind vor einer Wiederholung in ein frisches ignoriertes
Arbeitsverzeichnis zu kopieren. Nicht in dieser Belegsammlung ausführen.

Frühere Vollsuite-Preflight-Felder Preserved bleiben historische Nachweise ihrer
ursprünglichen Quellen/Ergebnisse und werden nicht als neue Vollsuite gezählt.
Der alte Kandidat `c5f4f256c9494147d08055a1deb5f9513a11af26` wurde durch `103e87fd6335bdc4ef8a2ffafa2384ecaad6504b` abgelöst. Die historische
macOS-Prüfserie ist kein Windows-Nachweis. Physische Kamera-/Papierabläufe, andere
DPI-/Hardwarekonfigurationen, Mehr-TiB-Läufe, externer Kryptografieaudit und ein
unabhängiger veröffentlichter historischer Windows-Leistungsvergleich sind nicht
nachgewiesen. Roh-UI, Roh-Prozesslisten, Verknüpfungszustände und private Schlüssel
werden nicht ergänzt. Die ursprünglichen IndexScope-Fakten bleiben erhalten.

<!-- evidence-refresh-status:begin -->
Die tatsächlichen vier Performance-Gruppen für `103e87fd6335bdc4ef8a2ffafa2384ecaad6504b` und ihre Originalbelege sind ergänzt (`performance-*.json`, `run-final-performance.ps1`). Die Metrik-Auszüge nennen SHA-256 und Zeilen der Originalprotokolle; der stabile Rechnerbezeichner und große Ressourcen-Traces sind ausdrücklich ausgelassen. Historische NOT_RUN-Aussagen bleiben unverändert.
Die tatsächliche Veröffentlichung samt frischen authentifizierten/anonymen Downloads und Erhaltung ist separat belegt (`publication-*.json`, `publish-windows503-resume-owned.ps1`).
Der Parent aktualisiert den Audittext und gegebenenfalls Release-Verweise anhand dieser tatsächlichen Belege.
<!-- evidence-refresh-status:end -->

Der erste Veröffentlichungsversuch bleibt als ursprüngliches `FAIL` erhalten
(`publication-prior-attempt-*.json` und ursprünglicher Runner).
`publication-recovery-lineage.json` bindet ihn an die erfolgreiche Fortsetzung
des eindeutig eigenen Entwurfs; der anfängliche Identitätsbeleg
`publication-recovery-provenance.json` wird nicht nachträglich als Publikation
bezeichnet. Der abschließende `PASS` steht in `publication-summary.json`.
