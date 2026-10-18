# Keep Vault 5.0.3 Build 22: ein aktueller installierter Paranoia-Profilfall

Status: NO_OVERALL_RELEASE / PENDING_OTHER_GUI. Dieses lokal vorbereitete Paket ist noch nicht veröffentlicht. Es belegt ausschließlich einen aktuellen installierten Profilfall am 18. Oktober 2026 mit 256 MiB öffentlichen synthetischen Quelldaten, Kompressionsstufe 3 und der Paranoia-Kaskade. Es ersetzt weder die übrigen vier positiven Profile und zehn Faultfälle noch die vollständigen normalen GUI-Prüfungen oder den danach letzten Structure512-Lauf. Keine stabile Releasefreigabe und keine Gesamtfreigabe.

Quellcommit: `ba9949ad1b93a89f75dd8078414371d1a1b7ad0d`. Installierter Launcher/Core84645, Auditrunner84594 und Collector87041 sind durch tatsächliche Start-/Terminalbelege mit Exit0 gebunden. Die drei Originaloperationen Generate, Create und Extract meldeten Erfolg, keine kontrollierten Faults, keine aktiven CPU-Worker oder Native-Callbacks nach Join. Vorher-/Nachher-Dateibindungen der Installation sind identisch. Extract meldet `productOriginalComparison=true`. Der getrennte Rootvergleich bestätigt genau drei Dateien, fünf Unterverzeichnisse und268435456Bytes, einschließlich leerer, verschachtelter, versteckter und Unicodepfade. Der Paketbauer hat diesen großen Baumvergleich nicht erneut ausgeführt.

## Beobachtete Zeiten

| Operation | Handler gesamt (s) | gemessene Anwendungsdialoge (s) | ausgewiesene Arbeit ohne diese Dialoge (s) | Prozess-CPU (s) |
|---|---:|---:|---:|---:|
| generate | 0.021307458 | 0.000000000 | 0.020772125 | 0.065075000 |
| create | 156.806304333 | 115.187298583 | 41.618991833 | 80.267275000 |
| extract | 48.536746834 | 15.083059542 | 33.453681667 | 19.898474000 |

Die Zähler beginnen an den tatsächlichen Operationsgrenzen. Die vorherige menschliche Entropiesammlung, PDF-Speicherung und Vorabwarnungen sind darin nicht vollständig enthalten. Die ausgewiesene Arbeit zieht die gemessenen `ShowAsync`-Dialogzeiten ab; andere Bedien- oder Pickerwartezeiten sind dadurch nicht allgemein ausgeschlossen. Quelle ist der einzelne funktionale GUI-Lauf, kein wiederholter Geschwindigkeitsbenchmark.

In `derived/operation-times.json` bezeichnet der optionale Durchsatz256MiBQuelldaten geteilt durch das jeweilige ausgewiesene Arbeitsintervall. Das ist kein Cipherdurchsatz. Die Cipherstufen verarbeiteten je67170331komprimierteBytes, ungefähr64,06MiB. KDF-Runden enthalten ihre Branches; Cipher-, Pipe-, MAC-, KPAR2-, Queue-, Join- und ZPAQ-Intervalle können sich überlappen. Ihre Summen dürfen nicht als additive Gesamtzeit ausgegeben werden. Prozess-CPU und Wandzeit sind verschiedene Größen.

## GUI- und Entropiegrenzen

Root beobachtete die vollständige Paranoia-Suite, den Erhalt des Entwurfs beim abgebrochenen Berechtigungspicker und bei fehlendem Schlüsselzettel, die getrennte Test-PDF-Speicherung, den erfolgreichen Archiv-/KPAR2-Lauf und Extract. Der Nutzer bestätigte nach automatischem Extract-Cleanup einen echten CmdZ im leeren Faktor-B-Feld; Root sah danach weiterhin leer und0/256. Das ist ein bestimmter beobachteter Bedienpfad, keine allgemeine physische RAM-Löschgarantie.

Der Generate-Klick selbst und die anfängliche Warnungsbestätigung wurden von Root nicht direkt beobachtet. Nach der menschlichen Bereitschaftsmeldung zeigte die erste Beobachtung bereits das erfolgreiche Ergebnis. Die Receiptphaseinträge belegen keine tatsächlichen Bildschirmzeichnungen. Nichtnull-LockedBytes während des noch lebenden Prozesses beweisen für sich weder ein Speicherleck noch vollständige Freigabe aller Appzustände. Die vollständige REV12-Folge Zielkollision, echte Pfadkorrektur und erneute PDF-Bindung ist in diesem festen Auditpfad nicht etabliert und bleibt separat zu prüfen.

## PDF, sichtbares Layout und begrenzte QR-Redundanz

Die bytegleichen Metadaten umfassen die automatische QA der beiden aktuellen öffentlichen Test-PDFs: jeweils zwei A4-Seiten, auf Seite1 zwei gleiche reine256Hex-Codes passend zum sichtbaren Faktor, A ungleich B, Seite2 öffentlicher Projektcode und keiner der beiden Faktoren. Der tatsächliche äußere Wait des Drivers86015 mit Exit0 liegt jetzt separat bei, ebenso die fünf tatsächlichen Analyzer-/Textextraktionskinder mit Exit0. Der frühere `narrow-original-qa-review.json` bleibt unverändert und behält seine damals ausdrücklich nicht selbst geprüfte äußere Wait-Grenze. Der spätere separate äußere Beleg ergänzt sie, ohne den früheren Inhalt umzuschreiben.

Root hat die vier tatsächlich gerenderten Seiten visuell betrachtet. Das Paket enthält nur dessen Layout- und Renderbelege, keine Bilder. Ein historischer generischer Softwarehelfer verdeckte zusätzlich den linken QR je erster Seite in Speicherbildern; der andere wurde weiter mit gleichem Inhalt erkannt. Acht Arbiterannahmen derselben verbliebenen Detection sind keine acht unabhängig dekodierten Kameraframes. Eine neue Kompilierungsbindung dieses historischen Helfers zur heutigen Scannerquelle wurde nicht bewiesen. Das belegt keine reale Kamera, kein beschädigtes Papier und keinen installierten Build22-Scannerlauf.

## Herkunft und Datenschutz

Alle Dateien unter `originals/` sind unveränderte bytegleiche Kopien ausdrücklich ausgewählter aktueller JSON-Metadaten beziehungsweise der ursprünglichen Collection-Hashliste. `ORIGIN-MANIFEST.json` verknüpft jeden Zielpfad mit dem Originalpfad, SHA256 und Byteumfang. Die drei Operationsreceipts liegen zusätzlich in der ursprünglichen Collectorfassung vor; auch diese Kopien sind gleich. Die ursprüngliche Collectiondatei `SHA256SUMS` ist unverändert als `originals/collection/SHA256SUMS.txt` aufgenommen. Das äußere `SHA256SUMS` prüft das gesamte neue Paket.

PDFs, Bilder, Rohfaktoren, rohe Passwort-/PIN-Werte, Maus-/RNG-Daten, Programmdateien, private Schlüsselpfade und fremde Logs wurden nicht kopiert. JSON-Dateien dürfen weiterhin Hash-/Pfadverweise auf absichtlich nicht enthaltene öffentliche PDF-/Bilddateien und andere unabhängige Metadatenquellen enthalten. Das ist keine Behauptung, alle transitiven Eingaben oder Systembibliotheken seien hier archiviert. Die Prüfung bewahrt die getrennten Quellen- und Beobachtungsgrenzen; sie ist kein externer Sicherheitsaudit.

Der Paketbauer startete keine Produktoperation, keine GUI, keinen neuen PDF-Test und keine Git-/GitHub-Aktion. Dieses Paket bleibt lokal bis zur späteren gemeinsamen Veröffentlichung mit weiteren tatsächlich abgeschlossenen GUI-Belegen. Die vorhandenen Releases und der unveröffentlichte Build22-Draft werden durch diese Vorbereitung nicht verändert.
