# Keep Vault 5.0.3: adaptive Ressourcenfenster und Skalierungsprüfung (REV12)

Stand: 3. Oktober 2026. Quellreview sowie gezielte managed Release-Regressionen sind ausgeführt. Native Eingaben stammen aus der signierten installierten Build-15-Basis; eine neue installierte Produktfreigabe ist damit nicht belegt.

## Bestätigte Fehler

`CipherSuitePerformanceTests.RunPipelineSlotScalingAsync` bestimmte einen einzelnen Wert `ProductionPipelineWorkerCount` und maß ausnahmslos alle Kandidaten unter `UsePipelineWorkerCountForTests(slots)`. Damit wurde auch der als Produktion markierte Kandidat fest erzwungen. In der aktuellen Produktion starten Encrypt und Decrypt dagegen jeweils mit einem Slot und rufen nach einer wirklich abgeschlossenen Batchgrenze `ResolveNextChunkWindow` auf. Sie verwenden den statischen Wert `ProductionPipelineWorkerCount` nicht als ausgeführte Produktionsstrategie. Der bisherige Test war deshalb kein Nachweis der adaptiven Auto-Strategie. Die historische Meldung Fixed 2 gegenüber Fixed 10 bleibt ein echter historischer Testfehler und wird nicht nachträglich in Auto-Erfolg umbenannt.

Der reine Planner setzte bei normalem Speicherdruck und längerer Restarbeit sein Fenster zunächst stets auf zwei. Nur drei aufeinanderfolgende Steigerungen von jeweils mindestens fünf Prozent ließen den bisherigen Aufrufer mehr gesunde Samples melden. Ein gewachsenes Fenster konnte deshalb schon bei der folgenden stabilen Rate auf zwei zurückfallen. Drei aufeinanderfolgende Fünfprozent-Steigerungen verlangen zusammen mindestens 15,7625 Prozent, obwohl eine stabile gesunde Rate keine solche fortlaufende Beschleunigung benötigt.

Außerdem lag das ermittelte CPU-Limit zwar im Plan, begrenzte aber bislang nicht die tatsächliche Anzahl zugelassener Chunkslots. Das ist nun bei Auto und Manual eine bindende Obergrenze. Alle echten Bufferallokationen unterliegen weiterhin der getrennten dynamischen RAM-Admission.

## Korrektur des Planners

- Kleine oder erschöpfte Restarbeit erhält einen Slot. Ein langes Fenster beginnt nach tatsächlicher bereitstehender Arbeit mit maximal zwei Slots und erstellt keine Puffer pro erkanntem Kern.
- Ein bereits gemessenes Fenster bleibt bei normalem Druck erhalten. Seine Größe wird vor jeder Entscheidung an aktuelle CPU-, Queue-, verbleibende Chunk- und RAM-Grenzen gebunden.
- Die neue getrennte Eingabe `ThroughputRegressed` erlaubt eine schrittweise Rücknahme eines Slots; sie hat Vorrang vor einem widersprüchlichen Verbesserungsflag. Der Druckfall oder weniger erlaubte Ressourcen drosseln unmittelbar bis auf einen Slot.
- Wachstum benötigt unverändert mindestens drei gesunde Samples und eine ausdrücklich gemeldete Verbesserung. Es erfolgt höchstens um einen Slot, nachdem alle Zulassungsgrenzen berechnet wurden. Große öffentliche Zähler können deshalb nicht mehr durch `PreviousSlots + 1` überlaufen.
- Verpflichtende Bytes werden vor optionalen Slots abgezogen. Mehr verpflichtende Bytes vergrößern das Fenster niemals. Keine OS-Beobachtung ist eine Allokationszusage; die tatsächlichen gesperrten Speicherleases bleiben verbindlich.
- Der öffentlich beschreibende `PlannerRevision` ist 12. Produkt- und Archivversion ändern sich dadurch nicht.

`ReadyWorkers` war schon zuvor ohne Auswirkung. Dieser Teilpatch bindet die unabhängige Arbeit an reale `ReadyBytes` und den CPU-/Queue-/RAM-Rahmen. Eine zusätzliche strikte ReadyWorkers-Grenze würde die vorhandenen Range-/ZPAQ-Aufrufer mit Defaultwert eins verändern und verlangt erst deren gesonderte konkrete Jobplanung. Hier wird keine höhere Zahl von Phantomjobs eingeführt.

## Für die Containerintegration festgelegte Rückmeldungen

Encrypt und Decrypt müssen dieselbe Zustandsfolge an der bestehenden vollständig gejointen Batchgrenze verwenden. Es werden ausschließlich öffentliche Nutzbytezahlen und monotone Gesamtzeiten gemessen, keine Credential- oder KDF-Matrixdetails.

Das gemeinsame begrenzte `AdaptiveChunkWindow` hält angenommenes Fenster und dessen gemessene Vergleichsrate während einer Probe getrennt. Drei vollständige gesunde Batches begründen eine angrenzende größere Probe. Bei mindestens zehn Prozent Verlust gegenüber der angenommenen Rate wird sofort zurückgenommen; sonst verlangen genau drei vollständige Probebatches mindestens fünf Prozent Medianvorteil. Ohne Vorteil bleibt das vorherige Fenster angenommen. Ein abgelehntes Nachbarfenster wird unter unveränderten Rahmenbedingungen nicht durch gewöhnliche Schwankungen erneut probiert. Eine tatsächliche Änderung des angenommenen Ressourcenfensters kann die alte Ablehnung aufheben.

Unvollständige Tailbatches sind keine Scalingbelege. Nichtpositive oder nicht endliche Raten dürfen keine Erweiterung freigeben. Der erste tatsächliche Auto-Batch bleibt ein Slot; nur konkret bekannte längere Restarbeit erlaubt anschließend das erste Zweierfenster unter frischer Admission. Der kalte Ein-Slot-Durchsatz wird dabei nicht als reife Zweierbaseline übernommen. Für unbekannte nicht seekbare Pipes entfällt der frühere erfundene 32-MiB-Ready-Wert: ohne überprüfte Read-ahead-Schnittstelle bleibt ein äußerer Slot, mit unveränderter nativer Parallelität auf disjunkten Blockbereichen des tatsächlichen Chunks.

Der frühere `ObserveChunkThroughput`-Stand setzte Vergleichsrate bei jedem Fensterwechsel zurück und konnte dadurch eine stabil langsamere Probe als neue Baseline annehmen. Die kanonische Schema-2-Messung verfehlte das Gate tatsächlich mit 89,32 %. Dieser alte FAIL bleibt erhalten. Die aktuelle Regression prüft retained baseline, begrenzte Probe, genaue 10-%-/5-%-Grenzen, fehlenden Nutzen, 40 verrauschte Samples ohne Retryloop, profitable Drei-/Vier-/Fünfslotfenster sowie Druckreduktion und spätere echte Erholung. Die Ressourcen-/CPU-/RAM-/Queue-/Restarbeitszulassung bleibt in jedem Fall verbindlich.

## Ehrliche Skalierungsprüfung

Die Benchmarkintegration erfasst jetzt einen eigenen Kandidaten `Auto` ohne `UsePipelineWorkerCountForTests` zusätzlich zu den bisherigen festen Kandidaten. Auto verwendet frische normale ResourcePreferences und echte OS-Beobachtung. Jeder Kandidat einschließlich Auto erhält genau einen vordefiniert ausgeschlossenen Warm-up und dieselben fünf vorher geplanten, interleavierten Messrunden. Keine nachträgliche Wahl weiterer Runden, kein Verwerfen ungünstiger Samples und kein als Auto etikettierter fester Wert.

Der Median des echten Auto-Kandidaten muss weiterhin mindestens 90 Prozent des besten Medians der zulässigen festen Kandidaten erreichen. Eine dynamische Strategie besitzt keinen einzelnen Produktionsslotwert; JSON und Chatbericht müssen Auto, feste Slotwerte, sämtliche Rohsamples, die jeweilige Datenmenge und die gemessene Operation richtig benennen. Wenn Auto diese Schwelle verfehlt, bleibt das ein offenes Gate und verlangt weitere gemessene Produktanalyse. Dieser Plannerpatch senkt die 90-Prozent-Schwelle nicht. Schema 3 legt zudem für alle festen Kandidaten und Auto dieselbe frische OS-Beobachtung und reine Planung am initialen und jedem vollständig gejointen Boundary fest. Feste Testwerte sind gewünschte Fenster innerhalb der aktuellen Zulassung, keine Umgehung von Druck oder fehlender Arbeit. Die begrenzte interne Pipelinebeobachtung ist für alle Kandidaten gleich; ohne Testobserver entstehen dort keine zusätzlichen Uhren oder Collections.

## Tests und Status

`KeepVaultMac.Tests/AdaptiveWindowRev12Tests.cs`, Harness-ID `resources.rev12-adaptive-window`, prüft:

- Erhalt eines vier-/fünfslotigen Fensters bei stabilen Samples und ohne erneute Verbesserung;
- keine Erweiterung vor drei gesunden Samples, danach höchstens ein zusätzlicher Slot;
- getrennte Regression und deren Vorrang;
- sofortige Drossel bei Elevated/Critical MemoryPressure;
- echte Remaining-Byte-Grenzen um 16 und 32 MiB;
- bindende manuelle CPU-, Memory- und Queue-Grenzen;
- genaue RAM-Admission nach OS-Reserve und verpflichtenden Kosten, monotone Reduktion bei mehr Pflichtbytes;
- große Int64-/Int32-Zähler ohne Overflow und kontrollierte Ablehnung ungültiger Zustandswerte oder unzuverlässiger Beobachtung.

Die vorhandenen `resources.rev11-auto-planner`-Tests bleiben bestehen. Im vollständig gebundenen Entwicklungsbuild `build-20261003T102259Z` sind `resources.rev12-adaptive-window` und `resources.rev12-kdf-minimum-admission` bestanden. Ergebnisdateien: `work/v13-evidence/rev12-development-20261003/build-20261003T102259Z/run-20261003T102713Z-661dde70/test-results.json` und `run-20261003T102713Z-49b0f0bd/test-results.json`. Kompilierung und Quellinventur sind stabil; `git diff --check` ist sauber. Diese früheren PASSs prüfen ihren damaligen Stand. Die fortgeschriebene Controllergruppe besteht zusätzlich in Build `113438`, Lauf `run-20261003T113614Z-82e64813`, sowie Build `114217`, Lauf `run-20261003T114340Z-c89e6b98`. Der neue vollständige gezielte Pipelinevergleich besteht mit Auto 393,18 MiB/s gegenüber best fixed 1 mit 423,28 MiB/s, also 92,89 %. Die unveränderte 90-%-Schranke, ein Warm-up und fünf vorab geplante Messrunden je Kandidat sind erhalten; jeder Ciphertext wird authentifiziert und vollständig per Klartext-SHA-256 geprüft. [Vollständiges Paket](evidence/v13-rev12-20261003/pipeline-after-window-fix/README.md). Diese Zahlen stammen aus einem 256-MiB-Pipelinefixture mit ausdrücklich isolierter Test-KDF, nicht aus produktiver End-to-End- oder installierter AOT-Leistung. Der danach tatsächlich abgeschlossene [kanonische Gesamtvergleich](evidence/v13-rev12-20261003/canonical-after-window-fix/README.md) ist PASS in 622,194 s: zwölf Primitive innerhalb der unveränderten 25-%-Schranke, zwölf vorkomprimierte Produktions-KDF-Container und separates Test-KDF-Pipelinegate mit Auto 389,24 / best fixed2 408,11 MiB/s, entsprechend 95,37 %. Die Controllergruppe ist erneut PASS in Build154322. Vollständige Kompressions-/Recovery-/Originalvergleichsworkflows und abschließende Gesamtregression bleiben offen; die neue zwölfteilige 1-GiB-Matrix hat begonnen. Die historische Fixed-2-Abnahme wird dadurch nicht rückwirkend bestanden.

## Reale kleine Ausgabekapazität

`zpaq.small-volume-capacity` ist im selben Build bestanden: eigener echter 256-MiB-APFS-Datenträger, 64 MiB öffentliche Quelldaten, normale und gestreamte Extraktion mit vollständigem Struktur-/Hashvergleich. Beide Ausgaben passen trotz weniger als 256 MiB freiem Platz. Anschließend wurde ausschließlich dieser eigene Datenträger tatsächlich gefüllt; die fehlgeschlagene Extraktion veröffentlichte keinen Teilbaum und ließ Quelle sowie beide vorhandenen Ausgaben unverändert. Ergebnis: `work/v13-evidence/rev12-development-20261003/build-20261003T102259Z/run-20261003T102704Z-331b05b8/test-results.json`. Der Image-Mount wurde vor der eigenen Fixturebereinigung entfernt. Das ist ein realer Dateisystemnachweis der beseitigten starren Extraktionsgrenze, kein Mehr-TB- oder installierter GUI-Nachweis.
