# Build 22: erster Versuch und Korrektur der Manifest-Buildbindung

Der erste tatsächliche Build-22-Builder (PID 64988) am Quellstand `e79af0483afb10c1206f1cd5a0d975ac0ba6971d` endet mit Exit 3. Der tatsächliche äußere Runner (PID 37656) endet ebenfalls mit Exit 3. Originalbelege und Logs bleiben bytegleich erhalten. Der Scanner-Antrag `d8669be3-e4db-4e74-a5e8-b59632bfdb7c` ist Accepted; die Paketierung endet anschließend vor Kit-Notarisierung, Installation und Funktionssuite. Keine der 49 vorgesehenen Funktions-/Leistungsphasen wurde abgeschlossen.

Die strenge Installationsprüfung lehnt das korrekt erzeugte Build-22-Manifest ab, weil `InstallationManifestVerifier.cs` sowohl im authentifizierten Manifest als auch in allen drei Info.plist-Prüfungen noch Build 21 verlangt. Der Fix setzt beide Pins und den Builder-Standard strikt auf Build 22. Schema 1, Version 5.0.3, vollständige Inventar-/Hash-, Hybrid-, Apple- und Dateibindungsprüfungen bleiben erhalten. Andere Version-/Buildpaare werden nun schon vor temporären Build-/Signierarbeiten mit Exit 64 abgewiesen.

Vier tatsächlich ausgeführte CLI-Negativfälle bestehen: 5.0.3/21, 5.0.3/23, 5.0.2/22 und ungültiger Build. Dies ersetzt keinen positiven signierten Paketnachweis oder vollständigen Release-Lauf. Der korrigierte Quellstand verlangt einen neuen eingefrorenen Builderlauf und neue AOT-Verifier für beide Architekturen. Der ursprüngliche Fehlversuch bleibt FAIL mit 0 abgeschlossenen Phasen; `overallReleaseApproval=false`.

`copy-binding.json` bindet alle kopierten Originale. `SHA256SUMS` deckt sämtliche Dateien außer sich selbst ab. Private Schlüssel, Wrapping-Schlüssel und Passwortdateien sind nicht Bestandteil des Pakets.
