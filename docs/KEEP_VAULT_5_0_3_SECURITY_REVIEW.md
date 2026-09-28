# Keep Vault 5.0.3: Sicherheitsreview

Stand: 28.09.2026, Umsetzung und laufende Prüfung auf macOS. Kein externer Audit, keine Zusicherung der Lückenfreiheit.

## Geprüfte Änderungen

XChaCha20-Poly1305 nutzt den IETF-Unterbau, Subkey aus HChaCha20 über die ersten 16 Noncebytes und `00000000 || N[16:24]` als inneren Nonce. Die veröffentlichten KATs und unabhängigen Vergleichspfade sind im Testbericht abgegrenzt. Primärquellen: [XChaCha-Entwurf 03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03), [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html), [libsodium](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction). Der XChaCha-Text ist ein Internet-Draft, kein verabschiedeter RFC.

Die Master-KDF bleibt zweigeteilt mit unveränderten produktiven Argon2id-Parametern und 1024-Bit-Master. Neue Formatdomänen sind kein Grund zur Reduktion des Aufwands. Standard hat vier getrennte Rollen, Paranoia weiterhin zwei vollständige Master-Runden. Die Summe der Schlüsselbreiten ist keine behauptete Entropie oder addierte Sicherheitsstärke.

Globale HMAC-SHA3-512- und Skein-MAC-Prüfung bleiben vor der Ausgabe an ZPAQ erforderlich. Bei AEAD-Suites kommt die lokale Poly1305-Verifikation hinzu. Der disk-backed Bereichsschutz ergänzt die globalen MACs und schützt nachträgliche Rereads auch bei Nicht-AEAD-Suites; er ersetzt keine globale Authentisierung.

## Release-Schlüssel

Auf ausdrücklichen Auftrag wurden neue RSA-4096- und ML-DSA-87-Schlüssel erzeugt. Der VeraCrypt-Zielordner liegt auf FAT mit deaktivierter Eigentümerprüfung. Um die bestehenden Prüfungen beizubehalten, liegt dort ein 128-MiB-APFS-Sparsebundle mit aktiviertem Eigentümerschutz. Das Sparsebundle bleibt innerhalb des VeraCrypt-Containers. Sein Mount und das Schlüsselverzeichnis sind 0700, die Schlüsseldateien 0600. Es wurden keine alten Schlüssel überschrieben.

RSA liegt als AES-256-verschlüsseltes PKCS#12 mit 200.000 PBKDF-Iterationen und SHA-512 vor. PFX-Passwort und ML-DSA-Private-Key verwenden die bestehenden getrennten AES-256-GCM-Umschlagformate und unabhängige 32-Byte-Wrapping-Keys. Die Bezeichnung v12 dieser Umschläge bleibt unverändert und ist kein v12-Archivmodus. Die Wrapping-Keys sind endgültige Dateien im geschützten Schlüsselspeicher. Kein privater Schlüssel und kein Passwort wurde als Prozessargument, Log oder Git-Inhalt ausgegeben.

Die native ML-DSA-Referenz wurde aus dem gepinnten `pq-crystals/dilithium@d35ba3fe5449bee3e6d43e1f296c3ca818bd36be` neu gebaut. Beide Signaturrichtungen gegen Bouncy Castle und RSA-PSS/SHA-512 sowie erneutes Einlesen der gespeicherten Schlüssel bestanden. Öffentliche Fingerprints stehen in `work/v13-evidence/key-generation.json` und im externen öffentlichen Erzeugungsbeleg.

Beim separaten Review der Provisionierung wurden zusätzliche Härtungen veranlasst: ungepufferte Secret-Dateischreibvorgänge, der bestehende isolierte temporäre macOS-Keychain-Vertrag, eine durchgehende Verzeichnisbindung und explizite ACL-Prüfung. Der ursprüngliche tatsächliche Erzeugungslauf benutzte bereits einen privaten TMPDIR innerhalb des VeraCrypt-geschützten APFS-Images; nach dem Lauf war dieses Verzeichnis leer. Reproduzierbare Negativtests und deren Abschlussstatus stehen im Testbericht.

## Abgleich und konkrete Korrekturen

Auch unveränderte Vertrauenspfade wurden gegen den bisherigen GitHub-Stand geprüft. Die verpflichtende Kombination aus RSA und ML-DSA, beide signierten Hashmanifeste, gebundene Native-Dateideskriptoren, Apple-Teamprüfung und Installer-Rechte-/Austauschprüfungen bleiben erhalten. Der [Kernbericht](KEEP_VAULT_5_0_3_CORE_REV9_REVIEW.md) trennt unabhängiges Nachrechnen öffentlicher Pins von der Quellprüfung der übrigen Policy. Private Schlüssel wurden dabei nicht gelesen.

Im Review wurden konkrete Fehler korrigiert: nichtkanonische Base64-Header, unvollständige Hash-/HMAC-Zwischenwertbereinigung, verborgene Workerobergrenzen, fehlende gemeinsame Parent-/Child-Speicherreservierung und Fehler bei Ressourcenbesitz auf Konstruktor-/Cleanupfehlern. Der Reparaturpfad authentisiert erst den vollständig wiederhergestellten Kandidaten, bevor er ihn veröffentlicht. Beschädigte Eingaben müssen dafür nicht bereits einen gültigen globalen MAC besitzen. Der ursprüngliche Container bleibt erhalten.

Der sichere Eingabepfad verwendet eigene geprüfte Bereichspuffer und einen versiegelten Index auf dem Datenträger. Parallele Leser werden vor Schlüssellöschung und Freigabe der vollständigen Pufferkapazität beendet. Fehlgeschlagene Bereinigung behält den Besitzer und verhindert eine neue Aufnahme bis zum erfolgreichen Wiederholungsversuch. Die 19 gezielten Eingabe-/Metadaten-/Ressourcengruppen sind mit einzeln signierten Entwicklungs-Natives bestanden; zwei zuvor fehlerhafte Reflection-Testhelper wurden korrigiert und erfolgreich wiederholt. Das ersetzt den abschließenden Lauf mit den exakten Paketbytes nicht.

Zusätzlich bestanden je 10.000 reproduzierbare variierte Fälle für geschützte Eingabespeicher, Streaming-Recoverymetadaten und den verwalteten Read-at-Server. Der native Read-at-Reader bestand je 10.000 Fälle auf ARM64, x64/Rosetta und ARM64 mit ASan/UBSan. Feste Orakel, Canaries und gezielte Negativfälle bleiben neben diesen Läufen erhalten. Die Seed-, Größen- und Evidenzgrenzen stehen im [IO-Bericht](KEEP_VAULT_5_0_3_MULTITB_TEST_REPORT.md).

Der spätere Mehrchunk-Kryptotest fand außerdem einen Capturefehler mit `Invalid argument`. Beim Quellreview zeigte sich, dass die parallelen Worker denselben `FileStream.SafeFileHandle`-Getter nach einer gepufferten Magic-Lesung verwendeten. Der Getter verändert über Flush/Seek den gemeinsamen Lesecursor und konnte dadurch parallel mehrfach zurücksetzen. Der Eingabepfad bindet jetzt die Handleobjekte einmal vor Beginn; auch Magic, Länge und EOF verwenden ausschließlich positionsgebundene Operationen. Quellenidentität, lokale Doppel-MACs und globale Freigabe werden weiterhin geprüft. Die neue Regression verarbeitet dreimal 32 MiB + 37 Byte mit vollständigem Bytevergleich und besteht nach dem neuen Build in 3,162 Sekunden. Auch der ursprüngliche Mehrchunktest über alle zwölf Suites besteht nun in 51,609 Sekunden. Beide Läufe verwenden Seed `0x5EED0313`; die tatsächlichen DLL-/Nativehashes und getrennten früheren Fehlerprotokolle sind im [IO-Nachweis](evidence/v13-io-rev9-20260928/evidence-manifest.json) erhalten. Die älteren 19+3 PASS-Gruppen werden nicht rückwirkend dieser späteren Änderung zugeordnet.

Die REV9-Entropiekette hat neue unabhängig erzeugte öffentliche Referenzwerte. Historische Shufflewerte existierten vor 5.0.3 nicht. Beide Fisher-Yates-Durchläufe, SHA3-/SHA512-Replay, Finalisierung, OS-XOR-Rollen und Löschbarrieren werden getrennt geprüft. Details stehen im [Shufflebericht](KEEP_VAULT_5_0_3_POOL_SHUFFLE_REV9_REVIEW.md).

Der aktuelle Installationsprüfer wurde zusätzlich von der bisherigen Buildnummer 13 auf die neue Buildnummer 14 korrigiert. Der Schutz gegen alte oder gemischte Paketsätze bleibt dabei strikt; Versionsnummer und Containerformat sind getrennte Werte.

## Grenzen

Hashbasierte Chunknonce-Expansion ist keine mathematisch kollisionsfreie Permutation. Ein größerer äußerer Nonce beseitigt weder Counterintervall-Überlappungen innerer CTR-Stufen noch Grenzen von 128-Bit-Blockchiffren. Aus Tests bis 256 MiB folgt keine unbegrenzte sichere Schlüsselverwendung.

Schutz gegen Same-UID-Dateimanipulation schützt nicht gegen einen kompromittierten Kernel oder erfolgreiches Lesen des geschützten Prozessspeichers. Bibliotheksinterne temporäre Kryptografiestrukturen können nicht allein durch das Nullen unserer expliziten Puffer als vollständig nachgewiesen gelöscht gelten. Reguläre unverschlüsselte ZPAQ-Sidecars bleiben unkeyed Fehlererkennung.

Windows und reale TiB-Läufe sind auf ausdrückliche Benutzeranweisung nicht Teil dieses Durchgangs. Kleine virtuelle Größenprüfungen sind keine Mehr-TB-Laufnachweise. Noch ausstehende Paket-, produktive Archiv-/Recovery-, Fehler-/Crash- und reale GUI-Nachweise stehen im jeweiligen Bericht. Keine Veröffentlichung darf offene bestätigte Sicherheitsfehler oder fehlende verbindliche Nachweise übergehen.
