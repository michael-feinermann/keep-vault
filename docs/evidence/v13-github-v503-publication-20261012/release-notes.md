# Keep Vault 5.0.3/v13 für macOS, Build 21

5.0.3 wird auf ausdrücklichen Wunsch jetzt als regulärer GitHub-Release veröffentlicht. Die restlichen Tests folgen später. Die technische Gesamtfreigabe ist weiterhin ausstehend.

Das Universal-Paket für Apple Silicon und Intel ist bytegleich zum bereits signierten, notarisierten und installierten Build 21 der Vorabversion. Die sechs Download-Dateien und ihre SHA-256-Werte bleiben unverändert. Es wurde dafür kein neuer Build erzeugt und keine zusätzliche bestandene Prüfung behauptet.

Bereits nachgewiesen:

- Reguläre vollständige macOS-Funktionssuite: 319 PASS, 0 FAIL, 0 BLOCKED.
- Gezielte KDF-/Schlüsselübergaben: 2.504 injizierte Fehler, 440 weitere Cipher-/MAC-/Recovery-Fälle und 48 Caller-Cleanup-Fälle.
- Echte native Nullpointer-/Breitenprüfungen: je 161 PASS auf ARM64 und Intel/Rosetta, mit neun Produktbibliotheken und einer separaten nicht ausgelieferten SHA3-Referenz.
- Paranoia mit 512 MiB Quelldaten und Kompressionsstufe 3: KPAR2-Beschädigung, Reparatur sowie vollständiger Struktur-/Hashvergleich bestanden.
- Developer ID, Notarisierungstickets, Gatekeeper, hybride RSA-PSS-/ML-DSA-87-Signaturen und der installierte CLI-Vertrag wurden für exakt diesen Build geprüft.

Noch offen: der vollständige 49-Phasen-Freigabelauf, die abschließenden vergleichbaren Tests aller zwölf Suites mit je 1 GiB und Kompressionsstufe 3 sowie verbleibende reale Bedienprüfungen. `overallReleaseApproval=false`; die reguläre GitHub-Veröffentlichung ersetzt keinen technischen Abnahmenachweis. Windows und reale Mehr-TiB-Läufe gehören nicht zu diesem macOS-Durchgang. Ein externer Sicherheitsaudit wird nicht behauptet.

v13-Archive, KPAR2-Dateien und Schlüsselzettel sind inkompatibel zu v12. Für vorhandene v12-Daten brauchst du eine passende frühere Version; der Release 5.0.2 bleibt erhalten. Es gibt keine automatische Konvertierung.

Entpacke das vollständige ZIP und starte „Keep Vault Installer.app“. Die Begleitdateien enthalten SHA3-/Skein-Manifeste und hybride Signaturen.

Tag: `v5.0.3`; kompilierter Quellstand: `8c68571695ae9072555ffb462b3c0b9c500811ea`. Dokumentationsänderungen bewegen diesen Tag nicht. Die Vorabversion `v5.0.3-rc.build21`, der ältere Build-20-Draft und Version 5.0.2 bleiben erhalten.

[Gebundener Build-21-Bericht und Nachweise](https://github.com/michael-feinermann/keep-vault/blob/733bc0d80cacdc1fafba6e4b2b91f9314e03f96f/docs/PRERELEASE_BUILD21_REPORT.md)

## English

Keep Vault 5.0.3/v13 for macOS, Build 21, is published as a regular GitHub release at the user's explicit request. Remaining tests are deferred. Technical overall release approval is still pending. The six assets are byte-identical to the previously signed, notarized and installed Build 21 candidate. The 49-phase release campaign, final twelve-suite 1-GiB/compression-level-3 measurements and remaining real GUI acceptance gates have not been completed. Publishing this release does not claim those tests passed. The earlier releases remain available; v13 and v12 are incompatible.
