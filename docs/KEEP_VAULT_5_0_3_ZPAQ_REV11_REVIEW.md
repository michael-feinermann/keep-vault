# ZPAQ: REV11-Quellreview und isolierte Nachweise

Stand: 01.10.2026. Dieser Bericht beschreibt den geänderten Quellstand und isolierte macOS-ARM64-Entwicklungsprüfungen. Er ist kein Nachweis eines installierten, signierten oder veröffentlichten REV11-Pakets. Windows wurde nicht ausgeführt.

## Originalquellen und Phasenreihenfolge

`ZpaqBoundSources` inventarisiert Namen, Größen und gebundene Objektidentitäten. Die produktiven `AddAsync`-/`AddStreamingAsync`-Pfade kopieren keine vollständigen Quellen in einen Snapshot, Clone, SHM-Bereich oder Klartextspool. Der native Prozess erhält ausschließlich Katalogeinträge und höchstens 1 MiB große Lesefenster über den lokal gebundenen Kontrollkanal. Vor und nach dem Lesen werden Objekt, Pfadbindung und Änderungsmetadaten geprüft. Leere Ordner bleiben Katalogeinträge. Historische Snapshot-Erzeugung ist nur noch über den ausdrücklich bezeichneten Snapshot-Testhelfer erreichbar.

Der Deferred-Stream startet den nativen Producer erst nach der Source-Readiness, die der Container nach dem KDF-Cleanup meldet. Der native Extractor startet nach Destination-Readiness, die erst nach der globalen Authentifizierung gemeldet wird. Fehler vor Readiness starten kein Kind. Startfehler brechen den vorbereitenden Aufrufer ab und warten auf dessen Ende, bevor Besitzer freigegeben werden. Der neue schmale Test `v13-zpaq-phase-readiness` prüft diese Koordination ohne KDF, Schlüssel oder echten Prozess. Der isolierte Lauf aus dem gemeinsamen Managed-Build 5 bestand.

Plain-Archive werden auf beiden Plattformen über die verifizierte Read-at-Capability gelesen. Der native Prozess erhält keine Berechtigung, den ursprünglichen Archivpfad erneut selbst zu öffnen.

## CPU, Speicher und Ausgabe

Der Kontrollkanal hat einen festen 48-Byte-Header, fortlaufende Sequenzen und höchstens 1 MiB Antwortpayload. macOS bindet beide Seiten an die tatsächlichen Prozess-IDs des Parent/Child-Paares; Windows verwendet einen CurrentUserOnly-Named-Pipe-Vertrag mit Peer-PID-Prüfung. Der macOS-Sandboxvertrag erlaubt ausschließlich den exakten privaten Kontrollsocket.

Native Rechenabschnitte erwerben einzelne reale CPU-Permits. Vor blockierenden Quellen-/Pipe-/Queue-/Ausgabefensteroperationen und Joins wird das Permit zurückgegeben. Das ermöglicht CPU=1, einschließlich gleichzeitig notwendiger Parent-Rechenarbeit. Es gibt keine gesonderte Erlaubnis für unbudgetierte Kryptorechenarbeit.

Die Parent-Grundreservation deckt Laufzeit, tatsächliche Workerzahl, begrenzte Queuefenster und Quellenmetadaten ab. Die native Bibliothek fordert zusätzliche geprüfte Modell-/Preprozessor-/Compiler-Peaks vor deren Allokationen an. Die Pläne stammen aus der echten Konfiguration und enthalten den native Allocatoroverhead. Ihr Besitzer endet erst nach Freigabe des zugehörigen Modells beziehungsweise Scratchspeichers. Die harte Prozessobergrenze bleibt eine Obergrenze und wird nicht vollständig als Bedarf reserviert.

Ein Modellpeak wird ausdrücklich nicht vollständig als resident verbucht: Einige Teilallokationen überlappen nicht oder sind bereits freigegeben. Die ausstehenden Peakreservationen können deshalb zusammen mit dem gemessenen OS-Freispeicher vorübergehend konservativ doppelt wirken. Eine zusätzliche Allokation wird dann kontrolliert abgelehnt. Es gibt keinen unzutreffenden Allocated-ACK für den vollständigen Peak. Die macOS-Builds verwenden `NOJIT`; daraus folgt kein Nachweis vollständiger JIT-Abdeckung auf anderen Plattformen.

Disk-Writes erhalten höchstens 64 KiB große Ausgabefenster gegen eine endliche Autorisierung und den aktuellen gebundenen Volumezustand. Checked Writes und Flushes melden Fehler, einschließlich ENOSPC. Fensterbesitzer bleiben bis Abschluss oder bestätigtem Prozessende erhalten. Bei Plain-ZPAQ zählt der aktuelle IPC-Vertrag physisch geschriebene Bytes, einschließlich Headerumschreibung. Das ist an einer explizit eng gesetzten Ausgabegrenze konservativer als die endgültige Dateilänge.

## Zeit, Fortschritt und Fehler

Produktive Wandzeit-, CPU-Zeit- und Stillstandsabbrüche sind aus dem ZPAQ-Monitor und dem macOS-Canarybetrieb entfernt. Zeit und CPU bleiben Beobachtungen. Die verbleibenden kurzen Fristen betreffen ausschließlich den Join nach bereits eingeleiteter Fehler-/Abbruchbehandlung beziehungsweise isolierte Tests. Ein stillstehendes Kind kann ohne anderweitigen Fehler bis zum manuellen Abbruch weiter bestehen; automatische Erkennung jeder Endlosschleife wird nicht behauptet.

Native Fortschrittsmeldungen transportieren nur Phase, absolute bestätigte Bytezahl und Sequenz. Die native Quelle drosselt auf höchstens vier Meldungen pro Sekunde. Der Parent verarbeitet Telemetrie ohne pro Meldung aufgestauten Task und isoliert Beobachterfehler. Meldungen autorisieren weder Speicher/Ausgabe noch Erfolg. Terminaler Erfolg stammt weiterhin ausschließlich aus dem geprüften Operationsabschluss.

Ein expliziter Close-/ACK-Vertrag trennt beendete Autoritätsanfragen vom noch laufenden Antwort-Cleanup. Eine fehlerhafte Anfrage weckt auch den Reader einer unvollständigen nachfolgenden Headernachricht. Ein ungültiger Write-Abschluss entfernt keinen fremden Fensterbesitzer. Die drei produktiven Runner besitzen zusätzlich eine abschließende Lifetime-Schranke: Ein diagnostischer Timeout des bisherigen Fehlerkoordinators kann keinen Besitzer freigeben. Solange Kind oder Callback weiterlaufen, bleibt Cleanup sichtbar und die Operation hält ihre Besitzer. Erst positiv bestätigtes Prozessende und vollständig gejointe Tasks erlauben die Freigabe. Der neue Test `v13-zpaq-owner-lifetime` hält Kind und Callback nacheinander gezielt offen; der isolierte Lauf aus dem gemeinsamen Managed-Build 5 bestand.

## Ausgeführte isolierte Prüfungen

`native/tests/zpaq_control_rev11.py` erzeugt ausschließlich öffentliche, deterministische 2-MiB-Daten, eine Unicode-Datei, eine leere Datei und einen leeren Ordner. Default-Stufe 5 besteht für Plain-Erstellung, Plain-Read-at-Extraktion, Pipe-Erstellung und Pipe-Extraktion. Die höchste gleichzeitig erlaubte Rechenzahl war jeweils eins. Der Parent berechnet im Test SHA-256 innerhalb desselben gemeinsamen Permits. Er prüft zurückgegebene Bytes und Ordnerstruktur sowie die Freigabe sämtlicher CPU-, Modell- und Ausgabefensterbesitzer.

Fünf zusätzliche Fehlerfälle bestehen: falsche Antwortsequenz, übergroße Antwortlänge, verkürzte Quellenantwort, verweigerte Ausgabe und expliziter Abbruch während eines stillstehenden Quellenreads. Alle Kindprozesse und Testhandler wurden gejoint; kein Fehlerfall meldete normalen Erfolg. Beim Stillstandsfall bleibt das Kind vor dem ausdrücklichen Testabbruch aktiv.

Derselbe Satz wurde auf ARM64 mit AddressSanitizer und UndefinedBehaviorSanitizer ausgeführt und bestand ohne Befund. Beide Sanitizer brechen beim ersten Fehler ab. LSan ist auf diesem macOS-Host deaktiviert. Negative Tests prüfen zusätzlich explizit, dass ihre erwarteten Fehlerausgänge keinen Sanitizerfehler verbergen.

Belege liegen unter `work/rev11-zpaq-control/`: `protocol-level5-sanitized.json`, `protocol-level5-sanitized.log` und `source-binding.json`. Das Bindungsdokument enthält Compiler, SDK, genaue Kommandos, Binaryhash und die ausdrücklich als nachträglich erfasst bezeichneten Quellhashes. Der frühere Shutdownfehler bleibt unter `protocol-roundtrip-first-shutdown-failure.log` erhalten: ein Mutex mit problematischer globaler Destruktionsreihenfolge wurde durch einen trivialen atomaren Gatezustand und einen expliziten kontrollierten Kanalabschluss vor globalem Cleanup ersetzt.

Die unabhängigen Bibliotheks-Modelltests des Ressourcenreviews decken zusätzliche Allokationsfehler, Mehrblockbetrieb und Header-only-Scan ab. Der vollständige Produktnachweis `v13-zpaq-cpu-one` mit Default-Stufe 5, aktuellem Managed-Code, Sandbox und neuem root-geschütztem Native-Anker bleibt bis zum frisch gebauten und installierten Kandidaten offen. Bestehende signierte Nativebytes wurden durch diese isolierten Prüfungen nicht verändert.

Die vier Managed-Gruppen `v13-zpaq-phase-readiness`, `v13-zpaq-owner-lifetime`, `v13-progress-native-ipc` und `v13-zpaq-bound-source` bestanden am 01.10.2026 jeweils separat. Logs und unmittelbar gesicherte Ergebnis-JSONs liegen mit ihren Test-IDs unter `work/rev11-zpaq-control/`; `managed-final5-summary.json` und `managed-final5-binding.json` binden Aufrufe, Exitcodes, Assemblies und Quellen. Die private Stage behielt vorhandene signierte Nativebytes unverändert. Zwei reine Aufruffehler vor den echten Testläufen sind separat erhalten: zunächst ein relativer DLL-Pfad trotz Wrapper-CWD-Wechsel, danach eine vom Runner nicht unterstützte kommaseparierte Auswahl. Kein Test wurde dabei ausgeführt oder als bestanden gezählt.
