# Keep Vault 5.0.3: macOS-GUI

Aktueller Stand: NOT RUN für die reale finale installierte 5.0.3-GUI. Erfolgreiche verwaltete Builds und Headless-Tests ersetzen diesen Nachweis nicht.

Implementiert sind die zwölf Suitebezeichnungen über den gemeinsamen Katalog, der vierstufige Standard, die achtstufige Paranoia-Kaskade und die Migration alter Auswahlpräferenzen. Die Ressourcenseite enthält Arbeitsordner, endliche Größen-/Zeitbudgets, RAM, CPU, I/O und Warteschlangen in Deutsch/Englisch. Die Auswahl wird pro Operation eingefroren; Originaldateien werden nicht zur Platzbeschaffung gelöscht.

Die Entropieanzeige enthält alle elf individuellen Zähler einschließlich Nonce 4 und 5. Bereitschaft hängt von jedem einzelnen Pool und gesundem Speicherzustand ab. Generierung läuft asynchron; der sichtbare Abbruchknopf bleibt auch bei gesperrter Eingabeseite erreichbar. SingleRound zeigt Mischen 1, SHA3 und Bereinigen; DualRound zusätzlich Mischen 2 und SHA512. Der zugehörige Headless-Test durchläuft die echte MainWindow-Implementierung, prüft beide Pläne und bricht einen kontrolliert angehaltenen SHA3-Replay über den tatsächlichen Button ab. Dieser Test bestand am 28.09.2026; er ist kein Nachweis der final installierten GUI.

Bei der Nachprüfung wurde der Lebenszyklus der Abbruchquellen getrennt: Startintegritätsprüfung und Hintergrundhinweise verwenden einen stabil gespeicherten Fenstertoken, einzelne Archiv-/Entropieoperationen einen neuen eigenen verknüpften Token. Das verhindert einen nachträglichen Zugriff auf `CancellationTokenSource.Token` nach Dispose und eine Übernahme eines alten Operationsabbruchs in die nächste Operation. Das ergänzte Gate `gui.operation-cancel-lifetime` bestand am 28.09.2026 in 0,4 Sekunden; es prüft Abbruch, neue Operation und anschließendes Dispose.

Offen: reale Installation/Start mit finalem Paket, beide Sprachen, Mindestfenstergröße und Skalierung, Entropie und Druckbindung, fünf XChaCha-Suites, falsche Credentials, v12-Ablehnung, Abbruch, Scanner, Paranoia-Struktur-/KPAR2-Rundlauf mit 256 MiB Baum plus zusätzlicher 256-MiB-Einzeldatei (512 MiB insgesamt, ausdrückliche spätere Benutzerergänzung). Der bestehende Aufnahmeschutz bleibt aktiv.

Windows ist auf direkte Benutzeranweisung außerhalb dieses Durchgangs.

## Echte Kamera und Zwischenablage, 29.09.2026

Der installierte, notarisierte Scanner 5.0.3/Build 14 aus dem Prüfkandidaten `253b5fa` las das korrigierte öffentliche Faktor-A-Testblatt von einem zweiten Gerät durch die reale Mac-Kamera. Alle 256 Hex-Zeichen stimmten exakt mit dem öffentlichen Sollwert überein; der Benutzer meldete denselben erkannten Wert unabhängig zurück. Einfügen über die normale Zwischenablage in das Faktor-A-Feld der installierten Hauptapp gelang. Nach 30,537 Sekunden blieb ein erneutes Einfügen leer. Ein neuerer, durch normales GUI-Kopieren gesetzter öffentlicher Marker blieb nach 50,307 Sekunden erhalten. Deutsch/Englisch und „Erneut scannen“ wurden tatsächlich bedient; letzteres leerte das Ergebnis und startete die Kamera erneut.

Dies ist ein Kameratest mit zweitem Display, kein physischer Papierdruck. Es wurden keine Kamerabilder oder privaten Faktoren aufgezeichnet. Nachweis: `work/v13-evidence/real-camera-253b5fa-20260929/result.json`. Der Kandidat benötigt wegen separat gefundener Test-/Fehlervertragsprobleme einen neuen vollständigen Build; die übrigen finalen GUI-Rundläufe bleiben offen.

Anschließend verdeckte der Benutzer einen der beiden QR-Codes auf dem zweiten Gerät. Der verbleibende Code wurde durch die reale Kamera erkannt und erneut exakt mit allen 256 öffentlichen Sollzeichen verglichen. Die einzelnen Kamera-Frames wurden nicht aufgezeichnet oder gezählt; der Acht-Lesungen-Vertrag hat seinen getrennten automatisierten Nachweis.
