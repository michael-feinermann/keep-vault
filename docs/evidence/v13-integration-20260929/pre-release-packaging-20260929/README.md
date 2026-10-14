# Vorabprüfung Schlüssel-/Packagingharness, 29.09.2026

Bestehende Testassembly in einer exklusiven Dateikopie ausgeführt; kein Neubuild, keine echten Release-Schlüssel gelesen/erzeugt und keine nativen Signaturen geändert. 78 native Dateien und Begleiter sind vor/nach den Läufen bytegleich. Assembly- und Dateihashes stehen in `harness-provenance.json`, genaue Befehle und Loghashes in `summary.json`. Jedes Ergebnis wurde unmittelbar nach seiner Gruppe separat gesichert.

| Gruppe | Status | Testzeit s | Peak-RSS MiB |
|---|---|---:|---:|
| `packaging.usb-wrapping-key-input` | PASS | 0.011 | 57 |
| `packaging.private-directory-lease` | PASS | 0.096 | 63 |
| `packaging.keychain-secret-not-in-argv` | PASS | 0.003 | 54 |
| `packaging.installer-lock-cleanup` | PASS | 0.510 | 61 |
| `packaging.hybrid-key-separation` | PASS | 95.629 | 72 |

`packaging.hybrid-key-separation.json` und die zugehörige Logdatei bewahren den ersten FAIL auf: Der direkte Aufruf aus der Kopie unter `work/` erbte die Windows-SDK-Vorgabe 10.0.401. Die Wiederholung mit unveränderter Assembly und gleichem Seed aus `KeepVaultMac` bestand. Dieser CWD entspricht dem regulären macOS-Teststarter mit SDK 10.0.400. Kein SDK-Pin oder Skript wurde dafür verändert.

USB-/Directory-/Envelopeprüfungen verwenden synthetische Werte und echte Datei-/ACL-/Cleanup-Pfade. Die Keychain-argv-Gruppe ist eine Quellassertion, keine Messung einer echten Schlüsselprovisionierung. Installer-Lock-Cleanup prüft vier synthetische PTY-Fälle. Die Hybridgruppe enthält zusätzlich vorhandene isolierte Toolpath-/Umgebungs-Selbsttests.

Diese Ergebnisse sind keine Freigabe eines finalen Pakets: tatsächliche Native-Trust-, Bundle-/Scanner-, Apple-/Notarisierungs-/Stapling-, Installations- und reale GUI-Gates bleiben separate Prüfungen.
