# Keep Vault 5.0.3 / v13: Implementierungsnachweis

## Aktueller REV11-Stand, 1. Oktober 2026

Die verbindliche aktuelle Grundlage ist REV11. Die Benutzerfreigabe umfasst dynamische Ressourcen, Originaldatei-Lesepfade, Fortschritt ohne Laufzeitabbrüche und die englische Beschriftung „password“. Die untenstehenden REV9-Nachweise bleiben historische Entwicklungsbelege. Der neue signierte REV11-Kandidat und seine installierten Tests sind noch offen.

Siehe [Auto-Ressourcen](KEEP_VAULT_5_0_3_AUTO_RESOURCES_REV10_REVIEW.md), [Fortschritt und Zeitverhalten](KEEP_VAULT_5_0_3_PROGRESS_ETA_REV11_REVIEW.md) und [Golden-Verifier](KEEP_VAULT_5_0_3_GOLDEN_VERIFIER_REVIEW.md).

## Historische REV9-Dokumentation

Arbeitsstand 29. September 2026, REV9, eingefrorener Produktquellstand `536d7c2afc47a27397f5a611b7ca4a0127067c82`. Der neue vollständige Produkt- und Performanceablauf ist RUNNING/PENDING. Diese Datei beschreibt tatsächlich ausgeführte Arbeiten und offene Gates. Ein Quellbuild ist keine Releasefreigabe.

## Verbindlicher Umfang

Grundlage ist Michaels aktualisierte Datei `KEEPVAULT_5.0.3_V13_CODEX_GESAMTUEBERARBEITUNG_REV9.md`. Sie ersetzt die frühere Revision 3. Michaels direkte Anweisungen begrenzen die Freigabe wie folgt:

1. Reale Datenläufe sind auf höchstens 256 MiB je Test begrenzt. Mehrere solche Läufe sind erlaubt und erforderlich. Der ausdrücklich ergänzte Paranoia-Strukturtest enthält einen vollständigen 256-MiB-Baum und zusätzlich eine einzelne 256-MiB-Datei, insgesamt 512 MiB. Er prüft Beschädigung, KPAR2-Reparatur, sämtliche Verzeichnisse einschließlich leerer Verzeichnisse und Dateihashes.
2. Dieser Durchgang betrifft ausschließlich macOS. Windows-Build, Windows-GUI, Windows-Installation und gemeinsame Veröffentlichung beider Plattformen sind nicht Bestandteil der aktuellen Freigabe. Gemeinsame Quellen behalten ihre Windows-Adapter; das ist kein Windows-Testnachweis.

3. Bereits veröffentlichte GitHub-Versionen dienen als Altpfadvergleich. Nach ausdrücklicher Klarstellung gab es vor dieser Umsetzung keine Shuffle-Referenzwerte. Für 5.0.3 wurden deshalb neue unabhängige öffentliche Fixtures erstellt und schreibgeschützt gegen die Produktimplementierung geprüft. Historische Modellprüfungen in der Spezifikation wurden nicht als aktuelle Produktnachweise übernommen.

Die Architektur- und Sicherheitsanforderungen werden durch die kleinere Testgröße nicht als nachgewiesen behandelt. Es gibt keine behaupteten realen 1-/4-TiB-Ergebnisse.

## Ausgangsstand

Der lokale Checkout war sauber und stand auf `codex/m5-performance-docs` bei `7ff2eda764ad321ed25c88f862ee20a8a9822690`. Nach `git fetch origin --prune` zeigte `origin/master` auf `1546fc76067c40c516fa7a9c7054623c64cb6306`; `origin/codex/windows-v12-5.0.2` enthielt diesen Stand vollständig und war 16 Commits voraus, 0 zurück. Neuer gemeinsamer Arbeitsbranch: `codex/keep-vault-5.0.3-v13`, Ausgangscommit `305da05`. Es wurden keine Benutzeränderungen zurückgesetzt. `v5.0.3` existierte zu Beginn nicht. Der historische Tag `v5.0.2` und seine Assets bleiben unverändert.

Ausgangsumgebung: Darwin 25.6.0, arm64. Zu Beginn war unter `/Applications/Keep Vault.app` Version 5.0.2, Build 13 installiert. Ziel: 5.0.3, Build 14; Containerformat: 13. Die spätere Kandidateninstallation ist im Releasebericht getrennt dokumentiert. Der macOS-SDK-Pin bleibt .NET 10.0.400. Der integrierte Windows-Pin 10.0.401 ist davon getrennt.

## Umsetzung

- Katalog mit genau zwölf Suites, fünf mit XChaCha20-Poly1305; ID 2 bezeichnet ausschließlich den neuen vierstufigen Standard, ID 3 die achtstufige Paranoia-Kaskade. Camellia-256 und Serpent-256 ergänzen den Katalog. Rollenweise Schlüssel, Standard-Defaults, Tweak, Chunknonce und AAD sind auf v13 umgestellt.
- Elf unbalancierte, zufällig mit Zurücklegen ausgewählte Mausrecord-Pools. Sämtliche ursprünglichen 80-Byte-Records einschließlich Sequenz bleiben bis zur Entnahme in gesperrten Segmenten. Alle elf Pools benötigen mindestens 1024 Records; weitere Ereignisse werden vollständig aufgenommen.
- Vor Entnahme festgelegter SingleRound-/DualRound-Plan. Fisher-Yates arbeitet auf geschützten Indexvektoren. Runde 1 startet einen neuen SHA3-512-Replay; Runde 2 mischt denselben Indexvektor frisch und startet SHA512 wieder bei null. Alte Records, Indizes, Zufallsreserven und temporäre Ergebnisse werden nach dem letzten Leser vor Ergebnisveröffentlichung bereinigt. Fehlerhafte Bereinigung behält Eigentum und sperrt Veröffentlichung.
- Vollständige 320-Byte-Archivnonce je Runde. ActivePrefix-v3 berechnet nur aktive 64-Byte-Blöcke; Standard braucht vier, Paranoia fünf Hashes. Headerauthentisierung bindet auch Reservematerial. Das kryptografische Schlüsselbudget ist getrennt von der Datenträgerfreigabe auf 64 TiB Nutzlast je Archiv begrenzt; Begründung und Modellgrenzen stehen im eigenen Bericht.
- Native XChaCha-ABI mit expliziten Längen, 24-Byte-Nonce, HChaCha20, 16-MiB-Aufrufgrenze und Fehlerpfaden. Der interne IETF-ChaCha-Kern und seine ausschließlich als Testreferenz genutzte Raw-API bleiben fachlich unabhängig.
- Kalyna-v13-Bibliotheksnamen, Loader, Packaging und Buildpfade; neue Pipekennung `KVP13ZP1`.
- Versiegelte datenträgergestützte Ciphertext-Eingabe mit temporären getrennten MAC-Schlüsseln, 1-MiB-Bereichen und 204-Byte-Belegen. Globale Freigabe verlangt beide Container-MACs. Jeder spätere Bereich wird erneut in einem privaten Puffer geprüft.
- Unveränderliche Ressourcenpolicy und macOS-Ressourcenauswahl für Arbeitsordner, endliche Größen-/Zeitbudgets, RAM, CPU-Worker, I/O und Warteschlangen. Kein Archivheader erhöht diese Budgets. Prozessweiter CPU- und Speicherkoordinator bindet untergeordnete native Arbeit, Argon-Matrizen und laufende Entropieaufnahme ein.
- Neue separate RSA-4096-/ML-DSA-87-Releaseidentität ausschließlich auf dem externen VeraCrypt-Speicher; nur öffentliche Schlüssel/Pins im Repository.

## Werkzeugketten-Befund

Ein erster Restore scheiterte an NU1403 für `Microsoft.DotNet.ILCompiler` und `Microsoft.NET.ILLink.Tasks`, Version 10.0.11. Ursache: Der Homebrew-SDK-Offlinecache enthielt anders gepackte `library-packs`. Die offiziellen NuGet-Dateien wurden neu geladen und mit `dotnet nuget verify --all` geprüft. Microsoft-Autorensignatur, NuGet-Gegensignatur und die bereits gepinnten NuGet-Inhaltshashes stimmten. Ein isolierter Restore mit deaktivierter impliziter Offlinequelle bestand; die beiden Lockwerte wurden nicht geändert.

Für die neue mutable-password-basierte PKCS#12-Erzeugung wurde `System.Security.Cryptography.Pkcs` 10.0.11 im separaten Signierwerkzeug hinzugefügt und dessen Lockdatei kontrolliert aktualisiert. Der eigentliche App-Abhängigkeitsbestand bleibt getrennt.

## Nachweise

Weitere Einzelheiten stehen im Format-, Sicherheits-, Test-, Optimierungs-, GUI- und Releasebericht für 5.0.3. Die maschinenlesbaren lokalen Rohbelege liegen unter `work/v13-evidence` und `work/v13-native`; große Wegwerfdaten und private Schlüssel gehören nicht in Git.

Am 29.09. bestand der bereits installierte Kandidat `253b5fa` 225/227 Gruppen und blieb wegen zweier Fehler ohne Freigabe. Die sieben gezielten Korrekturregressionen bestanden anschließend im korrigierten verwalteten Arbeitsbaum mit den unveränderten zuvor installierten Natives; `work/v13-evidence/postfix-check-20260929/` bindet Quellpatch, Binärdateien und Ergebnisse. Diese Historie bleibt erhalten und wird nicht zu einem alten Full-PASS umgedeutet.

Der nächste vollständige Build verwendet den Freeze `536d7c2`. Nach Native-Neubau und beiden tatsächlichen Slice-KATs stimmten sämtliche 1.931 erfassten versionierten Dateien einschließlich 39 Native-Dateien mit dem eingefrorenen Bestand überein. ARM64 und x86_64 unter Rosetta bestanden jeweils den neuen KAT; Quellen, Harnesses, Logpräfix und Eingabehashes stehen unter `work/v13-evidence/native-freeze-536d7c2-20260929/`. Das bestätigt weder physische Intel-Hardware noch Windows.

Die vollständige neue automatische Suite und die fünf gesonderten Performancephasen laufen noch. Ihre getrennte Belegsicherung liegt unter `work/v13-evidence/final-run-536d7c2-20260929/`; der [Testbericht](KEEP_VAULT_5_0_3_TEST_REPORT.md#eingefrorener-kandidat-536d7c2) unterscheidet diese ausstehenden Ergebnisse von den bereits bestandenen Teilprüfungen. Reale finale GUI, endgültiger Paket-/Downloadabgleich und Veröffentlichung werden erst nach ihren tatsächlichen Nachweisen ergänzt.
