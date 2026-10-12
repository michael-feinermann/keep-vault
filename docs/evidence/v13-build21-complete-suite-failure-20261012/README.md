# Build 21: erster vollständiger Durchgang

Status: FAIL. Eingefrorener Quellstand `a57882eca4c5a6694bae167527005bb0391babf8`, tatsächlicher Builder PID 8295, Exit 1, 12. Oktober 2026. Dieser Durchgang wurde nicht als GitHub-Release veröffentlicht und erteilt keine Gesamtfreigabe.

Die vollständige Suite erfasst 319 Gruppen: 317 PASS, 2 FAIL, 0 BLOCKED. Die Original-Ergebnis- und Timingdateien bleiben bytegleich. `failure-excerpt.txt` ist ausdrücklich nur ein Auszug; `capture.json` bindet ihn zusätzlich an die SHA-256-Werte der vollständigen Originalausgaben und unterscheidet NativeAOT-Produkt und Managed-Harness.

Die Fehler betreffen `packaging.hybrid-key-separation`, dessen Before-Unlock-Fixture während Dispose erneut den nun korrekt geschlossenen Getter verwendet, und `spec.lockfile-runtimes`, dessen unveränderte Projektprüfung eine archivierte `.csproj` als aktives Projekt erkennt. Die Korrektur prüft den vorher erfassten Array-Alias und den blockierten Getter. Die archivierte Projektdatei erhält bytegleich `.csproj.txt` mit ausdrücklicher Wiederherstellungsanleitung. Die Releaseprüfung wird nicht gelockert.

Die 317 bestandenen Gruppen und die bereits akzeptierte Notarisierung wandeln diesen fehlgeschlagenen Builder nicht in einen erfolgreichen Release um. Ein neuer korrigierter Build muss seine eigenen vollständigen, signierten und öffentlich heruntergeladenen Nachweise erhalten.
