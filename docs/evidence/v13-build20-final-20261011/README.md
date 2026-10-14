# Öffentliche strukturierte Belege zu Build 20

Dieses Verzeichnis enthält bytegleiche Kopien ausgewählter nicht geheimer Quittungen bereits tatsächlich ausgeführter Prüfungen vom 11. Oktober 2026. Das Verpacken ist keine neue Testausführung. Originale Zeitstempel, PIDs, Exitcodes, Test-DLL-/Produktbindungen, Profilwerte und Fehlversuche bleiben im Inhalt unverändert. Absolute lokale Arbeitsverzeichnisse in den Originalen sind Provenienz, keine extern verfügbaren Dateiverweise; die relative Dateiliste im [Manifest](public-evidence-copy-manifest.json) ordnet die öffentlich mitgelieferten Kopien zu.

- `informationals`: zwölf echte 1-GiB-Produktionsworkflows bei Kompressionsstufe 3, jeweils PASS. Öffentliche Profile, Ergebnisse, Start-/Terminalquittungen, ursprüngliche Zusammenfassung und tatsächliche Auswertung. Informationsmessung, keine kontrollierte Leistungsgatefreigabe.
- `paranoia-functional`: erneuter echter 512-MiB-Paranoia-Funktionstest mit Beschädigung, authentifizierter Reparatur und vollständigem Struktur-/Hashvergleich, PASS. Kein kanonischer Phase-49-Nachweis und kein neuer nativer GUI-Durchlauf.
- `diagnostic-infra`: genau ein tatsächlicher PASS für `infra.runner-invariants` des isoliert korrigierten Diagnosetest-Harness.
- `diagnostic-harness-build`: tatsächlicher isolierter Test-Harness-Bau, Exit 0, 125-Datei-Manifest. Keine mitgelieferte Test-DLL, kein SDK und kein neuer Produktbuild.
- `local-candidate-verification`: tatsächlich erneut geprüfte bestehende sechs Artefakte, hybride Signaturen ARM64/x86_64, drei Candidate-Apps und zwei installierte Apps mit Apple-/Stapling-/Gatekeeperprüfung. 19 echte CLI-Prozesse mit Exit 0. Kein öffentlicher Download und keine Releasefreigabe.
- `historical/phase-01`: Originalmatrix mit 302 PASS, als historische Referenz. Das Kopieren führt die Matrix nicht erneut aus.
- `historical/phase-08`: ursprünglicher Leistungsregressionstest mit FAIL/Exit 1. Die Informationsmessungen löschen oder ersetzen diesen Befund nicht.

Es sind ausschließlich die im Manifest einzeln genannten JSON-/Markdownquittungen enthalten. Vollständige Laufprotokolle, Quell-/SDK-/Buildcaches, Testdaten, Container, Schlüsselzettel, private Release-Schlüssel, Keychains und Zugangsdaten werden nicht mitgeliefert. Ursprüngliche Quittungen können SHA-256 von nicht mitgelieferten Laufprotokollen oder lokalen Eingaben enthalten; deren Hashbindung ist keine Behauptung, diese Dateien seien öffentlich enthalten.

Die vollständige formale Releasefreigabe bleibt BLOCKED. `publicReleaseApproved` ist false. Native und kontrollierte Pflichtnachweise bleiben voneinander getrennt.
