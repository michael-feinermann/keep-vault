# Keep Vault 5.0.3: macOS-GUI

## Aktueller REV11-Stand, 1. Oktober 2026

REV11 ersetzt feste Ressourcenvorgaben durch Auto-Präferenzen mit optionalen manuellen Obergrenzen. Arbeitsordner werden nur bei tatsächlicher Metadatenauslagerung benötigt. Laufzeitfelder sind entfernt; die Fortschrittsanzeige zeigt Phasen, erledigte Einheiten und bedingt eine Restzeitschätzung. „passphrase“ unter „Repeat PIN“ ist zu „password“ korrigiert. Drei gezielte Headless-GUI-Gruppen sind bestanden; die abschließende reale installierte GUI-Abnahme ist noch offen.

Siehe [Auto-Ressourcen](KEEP_VAULT_5_0_3_AUTO_RESOURCES_REV10_REVIEW.md), [Fortschritt und Zeitverhalten](KEEP_VAULT_5_0_3_PROGRESS_ETA_REV11_REVIEW.md) und [Golden-Verifier](KEEP_VAULT_5_0_3_GOLDEN_VERIFIER_REVIEW.md).

## Historische REV9-Dokumentation

Stand am 29.09.2026 nach Installation des eingefrorenen Kandidaten `536d7c2afc47a27397f5a611b7ca4a0127067c82`: Die reguläre Installation als 5.0.3/Build 14 und die abschließende Installer-Identitätsprüfung sind belegt. Die fünf geforderten realen GUI-Rundläufe bleiben `NOT RUN`; die vollständige GUI-Abnahme ist nicht abgeschlossen. Der unten dokumentierte echte Kamera-/Zwischenablagetest wurde zuvor am Kandidaten `253b5fa` ausgeführt. Seine Scanner-Codeidentität wurde inzwischen mit dem final installierten Scanner abgeglichen. Weder dieser Vergleich noch erfolgreiche Headless-Tests ersetzen die offenen Hauptapp-Rundläufe.

Implementiert sind die zwölf Suitebezeichnungen über den gemeinsamen Katalog, der vierstufige Standard, die achtstufige Paranoia-Kaskade und die Migration alter Auswahlpräferenzen. Die Ressourcenseite enthält Arbeitsordner, endliche Größen-/Zeitbudgets, RAM, CPU, I/O und Warteschlangen in Deutsch/Englisch. Die Auswahl wird pro Operation eingefroren; Originaldateien werden nicht zur Platzbeschaffung gelöscht.

Die Entropieanzeige enthält alle elf individuellen Zähler einschließlich Nonce 4 und 5. Bereitschaft hängt von jedem einzelnen Pool und gesundem Speicherzustand ab. Generierung läuft asynchron; der sichtbare Abbruchknopf bleibt auch bei gesperrter Eingabeseite erreichbar. SingleRound zeigt Mischen 1, SHA3 und Bereinigen; DualRound zusätzlich Mischen 2 und SHA512. Der zugehörige Headless-Test durchläuft die echte MainWindow-Implementierung, prüft beide Pläne und bricht einen kontrolliert angehaltenen SHA3-Replay über den tatsächlichen Button ab. Dieser Test bestand am 28.09.2026; er ist kein Nachweis der final installierten GUI.

Bei der Nachprüfung wurde der Lebenszyklus der Abbruchquellen getrennt: Startintegritätsprüfung und Hintergrundhinweise verwenden einen stabil gespeicherten Fenstertoken, einzelne Archiv-/Entropieoperationen einen neuen eigenen verknüpften Token. Das verhindert einen nachträglichen Zugriff auf `CancellationTokenSource.Token` nach Dispose und eine Übernahme eines alten Operationsabbruchs in die nächste Operation. Das ergänzte Gate `gui.operation-cancel-lifetime` bestand am 28.09.2026 in 0,4 Sekunden; es prüft Abbruch, neue Operation und anschließendes Dispose.

Die neue Installation unter `/Applications/Keep Vault.app` und `/Applications/QR-Scanner.app` ist durch den aktuellen Builderlauf belegt. Offen bleiben die reale abschließende Bedienung und der normale Startpfad der Hauptapp, beide Hauptapp-Sprachen, Mindestfenstergröße und Skalierung, Entropie und Druckbindung, die fünf XChaCha-GUI-Rundläufe, falsche Credentials, v12-Ablehnung, Abbruch sowie der geforderte Paranoia-Struktur-/KPAR2-Rundlauf in der realen GUI. Der Strukturtest umfasst 256 MiB Baum plus eine zusätzliche 256-MiB-Einzeldatei, insgesamt 512 MiB als ausdrücklich genehmigte Ausnahme. Der automatische 512-MiB-Test bestand am älteren Kandidaten `253b5fa`; dies ist weder ein neuer Lauf am Kandidaten `536d7c2` noch ein GUI-Nachweis. Der neue vollständige Produkttestlauf ist zu diesem Berichtsstand noch nicht abgeschlossen. Der bestehende Aufnahmeschutz bleibt aktiv.

Windows ist auf direkte Benutzeranweisung außerhalb dieses Durchgangs.

## Tatsächlich ausgeführte Kamera-/Zwischenablageprüfung an `253b5fa`

Am 29.09.2026 las der damals installierte, notarisierte Scanner 5.0.3/Build 14 aus `253b5fa33f0d93cf87525b6e70ad9d4a9af8c3f8` das korrigierte öffentliche Faktor-A-Testblatt von einem zweiten Gerät durch die reale Mac-Kamera. Alle 256 Hex-Zeichen stimmten exakt mit dem öffentlichen Sollwert überein; der Benutzer meldete denselben erkannten Wert unabhängig zurück. Einfügen über die normale Zwischenablage in das Faktor-A-Feld der damals installierten Hauptapp gelang. Nach 30,537 Sekunden blieb ein erneutes Einfügen leer. Ein neuerer, durch normales GUI-Kopieren gesetzter öffentlicher Marker blieb nach 50,307 Sekunden erhalten. Deutsch/Englisch im Scanner und „Erneut scannen“ wurden tatsächlich bedient; letzteres leerte das Ergebnis und startete die Kamera erneut.

Dies war ein Kameratest mit zweitem Display, kein physischer Papierdruck. Widersprüchliche physische QR-Codes wurden dabei ebenfalls nicht geprüft. Es wurden keine Kamerabilder oder privaten Faktoren aufgezeichnet. Nachweis: `work/v13-evidence/real-camera-253b5fa-20260929/result.json`; die damalige Scanner-Mach-O-Datei hatte SHA-256 `a10023c4db6155708845ef008b6f7a74f1def15aa4631e03d49b417b9419e9e5`. Der damalige vollständige Produkttestlauf endete separat mit 225/227 bestandenen Gruppen und war nicht freigegeben. Die inzwischen korrigierte Hauptapp wurde mit `536d7c2` neu gebaut; die alte Einfügebeobachtung ist kein erneuter Interaktionstest dieser neuen Hauptapp.

Anschließend verdeckte der Benutzer einen der beiden QR-Codes auf dem zweiten Gerät. Der verbleibende Code wurde durch die reale Kamera erkannt und erneut exakt mit allen 256 öffentlichen Sollzeichen verglichen. Die einzelnen Kamera-Frames wurden nicht aufgezeichnet oder gezählt; der Acht-Lesungen-Vertrag hat seinen getrennten automatisierten Nachweis.

Der Scanner wurde nach dieser Prüfung beendet; dies wurde ausdrücklich beobachtet. Die Aussage zur beendeten Kamera betrifft den beendeten Scannerprozess. Es wurde damit keine neue systemweite Hardwaremessung der Kamera vorgenommen.

## Neue Installation und Scannerbindung an `536d7c2`

Der aktuelle Builderlauf `work/v13-evidence/finish-5.0.3.z9wGjkRO/build.log` dokumentiert Apple-Annahme des Scanners unter `8d500d1b-6567-41e7-b02b-f9a2a203807d`, Annahme des Gesamtpakets unter `7052c9ae-5e45-42b8-a263-b83385b741ca`, Stapling und Ticketprüfung aller drei Apps sowie die reguläre Installation nach lokaler macOS-Autorisierung. Die Abschlussmarker `installed_identity_set=verified`, `release_pair_version=5.0.3`, `release_pair_build=14` und `zpaq_anchor=matches this build` belegen den installierten Kandidaten. Beide neuen Native-Slice-KATs bestanden mit unveränderten Quellen und Eingabehashes, dokumentiert unter `work/v13-evidence/native-freeze-536d7c2-20260929/`. Diese Prüfungen sind keine GUI-Bedienung.

Der anschließende lesende Vergleich um 10:25:33 UTC erfasste die finale Scanner-App aus `/private/tmp/keep-vault-release.zJ53UHwC/dist-stage/QR-Scanner.app` und `/Applications/QR-Scanner.app`. Dateimenge, Verzeichnisstruktur, Größen und SHA-256 stimmten exakt überein; beide Bestände blieben während des Vergleichs unverändert. Die strikte Apple-Prüfung aller Architekturen bestand. Nachweis: `work/v13-evidence/final-run-536d7c2-20260929/scanner-final-installed-comparison.json`.

Gegenüber der historischen Kamera-Baseline entsprechen beide Architektur-CDHashes sowie Identifier `de.michael-feinermann.qr-scanner` und Team `2T6K9PGS55` exakt dem tatsächlich geprüften Code:

| Architektur | Unveränderter CDHash |
|---|---|
| ARM64 | `8d7173411ed3e4200b93f24615e18d560cb47a74` |
| x86_64 | `eff3a4883aa1feddf4311e635631d279e350508c` |

Vier der sechs Bundle-Dateien stimmen auch bytegenau mit der alten Kamera-Baseline überein. `Contents/CodeResources` und `Contents/MacOS/QR-Scanner` unterscheiden sich nach der neuen Signierung/Notarisierung; das aktuelle Mach-O hat SHA-256 `9c8d359ba5829d82ff577db8e376731769e4e07bde03158e08544dc74cde6294`. Deshalb wird keine vollständige Bytegleichheit des neuen und alten Gesamtbundles behauptet. Belegt sind die exakte Installation der neuen finalen Scanner-App und ihre unveränderten signierten Codeidentitäten gegenüber dem realen Kameratest. Der Vergleich selbst startete weder Scanner noch Kamera, verwendete keine Zwischenablage und führte keinen neuen physischen Scan aus. Die fünf abschließenden GUI-Rundläufe der Hauptapp bleiben `NOT RUN`.
