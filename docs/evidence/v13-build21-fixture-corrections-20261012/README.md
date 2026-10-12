# Build 21: gezielte Korrekturprüfungen

Zwei tatsächliche reguläre `Test-KeepVault.sh`-Durchläufe bestehen mit je einer exakt ausgewählten Gruppe: `spec.lockfile-runtimes` und `packaging.hybrid-key-separation`. Start-/Terminalreceipts erfassen PID, Exit 0 und denselben Fixturehash vor/nach. Originallogs, Ergebnisse und Timings bleiben bytegleich.

Die Läufe prüfen den korrigierten Arbeitsbaum vor dem neuen Quellen-Freeze. Ihr gemeldeter Git-HEAD `a57882e` bezeichnet den damaligen alten HEAD bei geändertem Arbeitsbaum, keinen neuen unveränderten Produktbuild. Die vollständige eingefrorene neue Suite, neue AOT-/Universalbytes und öffentliche Downloadprüfung bleiben eigene Nachweise. Die vorigen 317/319 mit Exit 1 werden nicht überschrieben.

Die Before-Unlock-Prüfung verwendet den zuvor erfassten Array-Alias und verlangt den gesperrten Getter. Die Transfer-Fehlersäume deaktivieren sich nach ihrem ersten Fehler; Cleanup-Retries verwenden echtes `munlock`, versuchen alle Owner unabhängig und setzen den Hook garantiert zurück. Die normale strenge Projektprüfung bleibt unverändert; die öffentliche Probe ist bytegleich als `.csproj.txt` archiviert. Die normalen sicheren Native-/SDK-Stagingprüfungen bleiben aktiv.

Diese zwei gezielten PASS erteilen keine Gesamtfreigabe und keinen vollständigen Releaseentscheid.
