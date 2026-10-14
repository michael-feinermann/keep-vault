# Keep Vault 5.0.3: Routingprüfung mit aktuellem REV9-Vertrag

Der von der Spezifikation vorgegebene Dateiname enthält REV7. Dieser Bericht beschreibt den aktuellen Recordappend-Pfad aus REV9; der frühere Digest-bei-Add-Pfad wurde ersetzt.

Das Produkt nimmt einen frischen little-endian 32-Bit-Kandidaten aus der OS-Zufallsquelle. Für n registrierte Zwecke wird `limit = 2^32 - (2^32 mod n)` berechnet; erst ein Kandidat kleiner limit wird modulo n auf einen Katalogslot reduziert. Für elf Zwecke sind 4294967292 bis 4294967295 ungültig. Die Auswahl erfolgt mit Zurücklegen ohne Mindestpoolpräferenz. Dieselbe gültige Rolle darf unbegrenzt aufeinanderfolgen, solange das genehmigte Speicherbudget ausreicht. 1024 ist nur die Mindestbereitschaft je Rolle, kein Aufnahmelimit.

`entropy.rev9-routing` bestand am 28.09.2026 mit n=1,2,3,5,7,11,16,17,31,64,257,65535,65536,65537,Int32.MaxValue, allen vier n=11-Verwerfungswerten, Mehrfachverwerfung und 128er-Abbruch. Reduzierte 8-/16-Bit-Quellräume werden vollständig auf gleiche Urbildanzahl geprüft. 1500 aufeinanderfolgende Records landen unverändert in derselben ausgewählten Rolle; Bereitschaft bleibt aus, solange ein anderer Pool fehlt. Fehlgeschlagene Zufallsaufnahme erhöht keinen Zähler und sperrt weitere Generierung bis Reset.

Diese Prüfung begründet die unverzerrte Reduktion unter der Annahme gleichverteilter Quellwörter. Sie quantifiziert keine Maus-Min-Entropie und zertifiziert nicht die OS-Zufallsquelle. Die neuen Shuffle- und unabhängigen Hashreferenzen stehen im REV9-Shufflebericht.
