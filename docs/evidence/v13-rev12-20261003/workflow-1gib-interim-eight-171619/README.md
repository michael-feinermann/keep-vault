# Zwischenstand: acht tatsächliche 1-GiB-Produktläufe

[Ausführliche Zeit- und Geschwindigkeitsauswertung](report.de.md) und [gebundener Zwischenbeleg](interim-evaluation.json) berichten acht tatsächliche Produkt-PASS. Die gemeinsame zwölfteilige Matrix ist unvollständig. AES 256, Camellia 256, Serpent 256 und XChaCha20-Poly1305 wurden noch nicht gestartet.

Der Original-Matrixparent wartet auf Netzstrom. Sein Checkpoint enthält weiterhin sieben terminale PASS und den gestarteten, noch nicht gesammelten MARS-Fall. MARS hat seinen Originalproduktlauf mit Exit 0/PASS am 3. Oktober 2026 um 20:36:01 UTC tatsächlich beendet; sein Original-Launcherstdout und dessen terminaler Matrixreceipt sind noch nicht gesammelt. Das zusätzliche aktuelle Nachherinventar ist ausdrücklich vom 21:06:14 UTC und wird nicht rückdatiert. Der Bericht trennt diese beiden Belegumfänge.

Je Suite genau ein vollständiger Workflow mit 1.073.741.824 Quelldatenbytes, Auto, Kompression 5, produktiver KDF, KPAR2-Erstellung und intakter Prüfung, Originalvergleich sowie unabhängigem Struktur- und Hashvergleich. Null Warmups, kein Median. Entwicklungsbeleg mit den gebundenen Build-15-Natives, keine finale installierte AOT-GUI- oder Releasefreigabe.

Alle Dateien aus dem separaten ignorierten work-Zwischenpaket sind bytegleiche Kopien. Dessen ursprünglicher SHA256SUMS steht unverändert als ORIGINAL_SHA256SUMS zur Verfügung. SHA256SUMS inventarisiert dieses Paket einschließlich des zusätzlichen README, ohne sich selbst. Die ursprünglichen absoluten Referenzen und Reportwerte bleiben erhalten. Der Auswerter-FAIL am noch nicht terminalen Originalcheckpoint ist ausdrücklich kein Produkt-FAIL und wird erhalten.

```sh
/usr/bin/shasum -a 256 -c SHA256SUMS
```
