# Keep Vault 5.0.3: macOS-GUI

Aktueller Stand: NOT RUN für die reale finale installierte 5.0.3-GUI. Erfolgreiche verwaltete Builds und Headless-Tests ersetzen diesen Nachweis nicht.

Implementiert sind die zwölf Suitebezeichnungen über den gemeinsamen Katalog, der vierstufige Standard, die achtstufige Paranoia-Kaskade und die Migration alter Auswahlpräferenzen. Die Ressourcenseite enthält Arbeitsordner, endliche Größen-/Zeitbudgets, RAM, CPU, I/O und Warteschlangen in Deutsch/Englisch. Die Auswahl wird pro Operation eingefroren; Originaldateien werden nicht zur Platzbeschaffung gelöscht.

Die Entropieanzeige enthält alle elf individuellen Zähler einschließlich Nonce 4 und 5. Bereitschaft hängt von jedem einzelnen Pool und gesundem Speicherzustand ab. Generierung läuft asynchron; der sichtbare Abbruchknopf bleibt auch bei gesperrter Eingabeseite erreichbar. SingleRound zeigt Mischen 1, SHA3 und Bereinigen; DualRound zusätzlich Mischen 2 und SHA512. Der zugehörige Headless-Test durchläuft die echte MainWindow-Implementierung, prüft beide Pläne und bricht einen kontrolliert angehaltenen SHA3-Replay über den tatsächlichen Button ab. Dieser Test bestand am 28.09.2026; er ist kein Nachweis der final installierten GUI.

Bei der Nachprüfung wurde der Lebenszyklus der Abbruchquellen getrennt: Startintegritätsprüfung und Hintergrundhinweise verwenden einen stabil gespeicherten Fenstertoken, einzelne Archiv-/Entropieoperationen einen neuen eigenen verknüpften Token. Das verhindert einen nachträglichen Zugriff auf `CancellationTokenSource.Token` nach Dispose und eine Übernahme eines alten Operationsabbruchs in die nächste Operation. Das ergänzte Gate `gui.operation-cancel-lifetime` bestand am 28.09.2026 in 0,4 Sekunden; es prüft Abbruch, neue Operation und anschließendes Dispose.

Offen: reale Installation/Start mit finalem Paket, beide Sprachen, Mindestfenstergröße und Skalierung, Entropie und Druckbindung, fünf XChaCha-Suites, falsche Credentials, v12-Ablehnung, Abbruch, Scanner, Paranoia-Struktur-/KPAR2-Rundlauf mit 256 MiB Baum plus zusätzlicher 256-MiB-Einzeldatei (512 MiB insgesamt, ausdrückliche spätere Benutzerergänzung). Der bestehende Aufnahmeschutz bleibt aktiv.

Windows ist auf direkte Benutzeranweisung außerhalb dieses Durchgangs.
