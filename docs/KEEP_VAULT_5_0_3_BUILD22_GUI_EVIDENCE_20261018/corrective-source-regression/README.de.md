# Keep Vault 5.0.3: PDF-/Druck-Fortschrittsregression

Gezielte managed macOS-arm64-Prüfung des kleinen GUI-Statusfixes vom 18. Oktober 2026. Keine Release- oder Gesamtfreigabe.

Der Runner meldet weiterhin Basis-HEAD `ba9949ad1b93a89f75dd8078414371d1a1b7ad0d`. Zum Testzeitpunkt waren die vier Fix-/Testdateien uncommittet. Ihre exakten SHA-256 stehen in `source-file-pins.json`; HEAD allein identifiziert den Fix nicht.

Save/Print melden Erfolg erst nach vollständiger Ausgabe, erneuter Entwurfsprüfung, Schlüsselblattbindung und Erfolgslog. Echte Fehler bleiben Failed, Abbrüche/abgelehnte Dialoge bleiben Cancelled. Der schmale Servicevertrag ist intern und instanzgebunden; der öffentliche parameterlose Konstruktor verwendet unverändert den realen Standardservice. KDF, Consume, Cleanup und Ressourcenverhalten wurden nicht geändert.

Die neue Gruppe `gui.key-sheet-operation-progress` bestand mit 24 internen Kombinationen: zwei Sprachen, zwei Buttons und sechs Ergebniswege. Das sind keine 24 eigenständigen Resultreceipts. Echte Headless-Button-/Bestätigungsfolgen und tatsächliche PDF-Ausgaben wurden geprüft; Print wird kontrolliert an der asynchronen Servicegrenze geprüft, ohne physischen Druckauftrag. Sieben bestehende Progress-, Preflight-, Cancel- und PDF-Rollbackgruppen bestanden zusätzlich.

Zwei absichtlich kompilierte Negativkontrollen entfernten jeweils nur den neuen Save- oder Print-Erfolgsmarker. Die Regression scheiterte jeweils am passenden erfolgreichen Handler mit tatsächlichem Exit 1. Beide Marker wurden bytegenau wiederhergestellt. Finale Kompilierung und Regression bestanden erneut mit Exit 0. Die negativen Originalresultate bleiben erhalten.

Der eingefrorene offizielle SDK 10.0.400 wurde vor und nach den Prüfungen über alle 4.906 Dateien verifiziert. Frischer isolierter NuGet-Cache und unveränderte Produkt-/Test-Locks wurden verwendet, kein AOT-/Lock-Bypass und kein ForceEvaluate. Die dokumentierte SDK-Auswahl liegt ausschließlich im ignorierten Testarbeitsverzeichnis; Produktglobal.json ist unverändert. Frühere abgewiesene Homebrew-Starts/NU1403-Restores sind lokal erhalten und werden nicht als erfolgreiche Builds gezählt. NuGet-contentHash und roher Archiv-SHA512 werden getrennt behandelt.

Die bestehenden NU1902-/NU1903-Warnungen zu System.Security.Cryptography.Pkcs 8.0.1 sind ausdrücklich unbehoben. Ihre URLs und die frischen Paketquellen stehen in `result.json`. Ein erfolgreicher Testlauf behebt diese Warnungen nicht.

Die kopierten Start-/Terminal-/Test-JSONs sind bytegleich mit den Originalen. Terminalreceipts binden zurückbehaltene Rohlogs per SHA-256; vollständige Logs, SDK-Dateimaps und Paketcache werden hier nicht mitgeliefert. Keine aktuellen Geheimwerte, Rohfaktoren, Mausaufzeichnungen, privaten Schlüssel oder Schlüsselpfade sind enthalten.

Dies ersetzt weder neue AOT-/Signatur-/Installationsnachweise noch reale Build23-GUI-/Releaseprüfungen. Build22-Artefakte und Nachweise wurden nicht verändert.
