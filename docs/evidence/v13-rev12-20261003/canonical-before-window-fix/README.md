# Kanonischer REV12-Lauf vor der Fensterrückkopplungskorrektur

Gesamtstatus: FAIL. Lauf `frozen-performance-20261003T105123Z-3a4b04a6`, gebundener managed Release-Entwicklungsbuild `20261003T102259Z` und unveränderte vertrauenswürdige signierte Nativebytes aus Build 15. Kein finaler AOT-/GUI-/Releasebeleg.

Alle zwölf Cipherprimitive bestehen den unveränderten Vergleich gegen die unabhängige passende historische Referenz mit maximal 25 Prozent Regression. Die Referenz verwendet ausschließlich abgeschlossene Primitive aus einem historischen Lauf, dessen nachgelagerter Pipelineabschnitt FAIL bleibt. Alle zwölf vollständigen 256-MiB-Containerfälle wurden mit produktiver KDF, einem vollständigen Warm-up und fünf tatsächlichen Messungen authentifiziert und hashverglichen. ZPAQ-Kompression, Recovery und Originalvergleich gehören nicht zu diesen Containerwerten.

Der abschließende fokussierte Pipelinevergleich verwendet die ausdrücklich benannte bestehende 8-MiB-KDF-Testseam. Die Produktion läuft dabei tatsächlich mit adaptivem Auto ohne Forced-Slot-Override. Alle Kandidaten erhalten einen vollständigen Warm-up sowie fünf interleaved Messrunden in vorab festgelegter Reihenfolge; jeder Output wird außerhalb des Verschlüsselungsintervalls authentifiziert und vollständig hashverglichen.

Auto erreicht 365.524317505 MiB/s, das beste feste Fenster 2 erreicht 409.239999757 MiB/s, also 89.317837 Prozent. Die unveränderte 90-Prozent-Schranke ist nicht erfüllt. Dieser Fehler wird nicht durch neue Schwellen, gelöschte Proben oder Auswahl eines günstigeren Laufs entfernt.

Die JSON-Marker sind unveränderte öffentliche Originalmarker des Logs. Ergebnis-/Zeit-/Inputinventare und vollständiges Quellinventar sind unveränderte Kopien. Der abgeleitete öffentliche Ausführungsreceipt bindet den Originalreceipt, das Originallog und sämtliche Input-/Ergebnishashes; er lässt absolute lokale CLI-Pfade aus. Originallog-SHA-256: `3e3b02ef4b208da62ae19bdfcade1530b649ae1d7ef667fffadbc32d9400025d`. `SHA256SUMS` bindet sämtliche anderen Dateien dieses Pakets. Durch Überlappung sind CPU- oder Phase-Walltimes nicht additiv.
