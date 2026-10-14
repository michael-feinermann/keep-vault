Vorläufige macOS-Version 5.0.3/v13, Build 21, als Universal-Paket für Apple Silicon und Intel. Die stabile Version 5.0.2 bleibt unverändert.

Der vollständige Funktionslauf besteht mit 319 PASS, 0 FAIL und 0 BLOCKED. Der signierte und notarisierte Kandidat wurde regulär installiert. Die zusätzlichen nativen Nullpointer- und Breitenprüfungen bestehen mit je 161 Fällen auf ARM64 und x86_64 unter Rosetta; neun ausgelieferte Bibliotheken sind bytegleich gebunden, SHA3 ist eine getrennte Testreferenz.

Die KDF-/Schlüsselübergabeprüfungen umfassen 2.504 injizierte Fehler an 626 Grenzen, 440 Cipher-/MAC-/Recovery-Fälle sowie 48 Caller-Cleanup-Fälle. Sie prüfen NULL, All-00, All-01 und All-FF, Ablehnung und Cleanup. Gleichförmige Primitive-Schlüssel bleiben für unabhängige bekannte Testvektoren zulässig. Diese Prüfungen sind kein allgemeiner Entropiebeweis oder externer Audit.

Der Paranoia-Strukturtest mit 256 MiB Verzeichnisbaum plus einer zusätzlichen 256-MiB-Datei besteht einschließlich KPAR2-Beschädigung, Reparatur und vollständigem Struktur-/Hashvergleich.

Alle drei App-Bundles besitzen Developer-ID-Signaturen und gültige Notarisierungstickets. Die sechs Download-Dateien enthalten das Paket sowie seine SHA3-/Skein-Manifeste und drei hybride RSA-PSS-/ML-DSA-87-Signaturpaare. Der Abschlussbericht dokumentiert die getrennte authentifizierte und anonyme Downloadprüfung.

v13-Archive, KPAR2-Dateien und Schlüsselzettel sind absichtlich inkompatibel zu v12. Bewahre für vorhandene v12-Daten Version 5.0.2 auf; es gibt keine automatische Konvertierung.

Gesamtstatus: NICHT GESAMTFREIGEGEBEN. Der vollständige 49-Phasen-Releaseblock einschließlich der verschobenen Lang- und Geschwindigkeitsmessungen sowie verbleibende reale Bedienprüfungen sind offen. Dieser Kandidat ist eine Vorabversion, keine stabile Gesamtfreigabe. Windows und Mehr-TiB-Tests sind nicht Bestandteil dieses Durchgangs.

Kompilierter Quellstand: `8c68571695ae9072555ffb462b3c0b9c500811ea`. Tag und Produkt gehören zu diesem Stand; spätere Dokumentationsbelege werden separat im offenen Draft-PR 3 ergänzt.

[Abschlussbericht und Nachweise](https://github.com/michael-feinermann/keep-vault/blob/codex/keep-vault-5.0.3-v13/docs/PRERELEASE_BUILD21_REPORT.md) · [Draft-PR 3](https://github.com/michael-feinermann/keep-vault/pull/3)
