# Vollständige Funktionssuite 164715, tatsächlicher FAIL

Am 3. Oktober 2026 tatsächlich ausgeführte 301 Gruppen: 288 PASS und 13 FAIL, Exitcode 1. Kein Gesamt-PASS und keine Releasefreigabe. Zwölf Containergruppen erreichen am vorhandenen Ziel die neue typisierte Destination-Vorabverweigerung; der damalige Test erwartet noch IOException. Skein-Wipe: ARM64-Bau/Lauf erreicht, x86_64-Start mit Bad CPU type abgewiesen, Rosetta fehlt. Die Fehler bleiben erhalten.

Der 512-MiB-Paranoia-Struktur-/KPAR2-Reparaturtest besteht im selben Lauf: 149 Dateien, 32 Verzeichnisse, 666,821 s Workflow. Dieser Test ist noch nicht der letzte finale Releaseabschluss.

Originale Ergebnis-/Zeitbelege und Ausführungsreceipt sind kopiert und SHA-256-gebunden. Sourcekarte vor/nach Build und nochmals nach vollständigem Lauf identisch. Binarykarte erst nach Laufende erfasst, ausdrücklich kein vor-Lauf-Binarybeleg. Installierte Build15-Natives plus managed Release-Entwicklung, keine neue Universal-/AOT-/GUI-Abnahme. Vollständiger Runlog bleibt im ursprünglichen Workpfad; sein Hash steht im Originalreceipt. Nur geschlossene öffentliche E2E-Marker hier kopiert.
