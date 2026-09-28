# Keep Vault 5.0.3: Release und Installation

Status: BLOCKED bis alle noch verbindlichen macOS-Gates bestanden und die finalen Artefakte geprüft sind. Dieser Zwischenstand ist weder veröffentlicht noch installiert.

Ziel: Produkt 5.0.3, Build 14, ausschließlich Containerformat 13. Ausgangsinstallation: `/Applications/Keep Vault.app`, Produkt 5.0.2, Build 13. Die historische Veröffentlichung `v5.0.2` bleibt unverändert.

Der Benutzer hat diesen Durchgang ausdrücklich auf macOS und reale Testgrößen bis 256 MiB je Lauf beschränkt. Windows ist deshalb kein Gate dieser Veröffentlichung; seine Binärdateien werden nicht als geprüft angeboten. Das ist keine Behauptung von Mehr-TB-Testnachweisen.

Neue externe Releaseidentität erzeugt und als öffentliche Pins eingebunden. Private Dateien ausschließlich im VeraCrypt-geschützten APFS-Schlüsselspeicher. Prüfstatus für Signatur, Notarisierung, Stapling, Paketinventar, Downloadabgleich und lokale GUI wird mit tatsächlichen Belegen ergänzt.

Vor einem Installationsabschluss muss ausdrücklich auf die Inkompatibilität hingewiesen werden: 5.0.3 öffnet keine vorhandenen v12-Archive. Benutzerarchive, KPAR2-Dateien, Schlüsselblätter und alte private Schlüssel bleiben erhalten.

Kein Tag `v5.0.3`, keine fertigen Assets, keine Installationsbehauptung ohne entsprechenden Nachweis. Commit und Push eines geprüften Arbeitsstands sind von Release und Installation getrennt.
