# Keep Vault 5.0.3 v13: Optimierung und Skalierungsgrenzen (REV9)

Die nativen Produktadapter verwenden ein gemeinsam budgetiertes, persistentes Executor-Team. Der bevorzugte 256-KiB-Claim ist keine feste Workergrenze mehr: bei großem gewährtem Budget wird er blockausgerichtet verkleinert. 16-MiB-Chunks, Cipherreihenfolge, volle Runden-/Keybreiten, AEAD-/MAC-Transcripts und der Argon2id-Vertrag bleiben erhalten.

Stand: 28.09.2026, uncommittete REV9-Änderungen auf `305da05a123779a7c00dede97337c6c5773a4c30`. Hashgebundene endgültige Quellen und vor Signierung atomar publizierte Nativebinaries: `docs/evidence/v13-native-rev9-20260928/provenance-release-source.json`. Der frühere Messstand ist zusätzlich in `provenance-adaptive.json` erhalten. Ergebnisse in diesem Bericht sind Entwicklungs-/Funktionsnachweise und werden von der abschließenden Signierungs-, Paket- und Installationsprüfung getrennt.

## Tatsächliche Messumgebung und Methode

Erneut erfasst: Apple M5, 10 logische und 10 physische CPUs, 16 GiB RAM, macOS 26.6.2 (25G83), Apple clang 21.0.0 (clang-2100.3.34.2), .NET 10.0.11. Die Messung erfolgte auf Batterie, Energiesparmodus aus. Keine Energie-, Cache- oder Sicherheitseinstellung wurde verändert. GUI- und normale Systemprozesse blieben aktiv; kein Echtzeit-/Labormessaufbau und keine Thermal- oder Taktfixierung. Keine NUMA-/4096-CPU- oder Windows-Hardwaremessung.

Build: `-O2 -DNDEBUG -fstack-protector-strong -fvisibility=hidden -fno-common`, C++17, Deploymentziel macOS14. Kein globales `-march=native`. Vendor-ISA-Flags gelten nur für geprüfte SIMD-Übersetzungseinheiten, mit dem zugehörigen öffentlichen CPU-/OS-Dispatch. ARM-AES- und NEON-Auswahl sind durch KAT/Providerprüfung und den ausgeführten Codepfad belegt. x64 unter Rosetta wählte bei diesem Lauf C++; physisches Intel-AES-NI/AVX2 ist NOT RUN.

`native/tests/native_benchmark` bindet die tatsächlichen Produkt-Exports und den tatsächlichen `NativeCipherExecutor` ein. Für jede Suite und jeden Grant 1/2/5/10: ein vollständiger Warmup, fünf Messungen à 256 MiB, jeweils 16 Aufrufe à 16 MiB. Wiederverwendete private Puffer, Inputkopie vor jedem Chunk in der Zeit enthalten, alle Stufen in-place in der vorgeschriebenen Reihenfolge. Ausgabe und Tag wurden zwischen Grants und den beiden Executorvarianten exakt verglichen. Die synthetischen Keys/IVs sind vorgegeben; KDF, aktive Nonceableitung, globale MACs, Archiv-I/O und ZPAQ fehlen absichtlich in dieser Primitiveebene. Die gesamte Datenmenge liegt in begrenzten RAM-Puffern, nicht als 24-GiB-Dateisatz auf Disk.

`CipherSuitePerformanceTests` wurde zusätzlich für die Freigabe angepasst: Die unveränderten 256 MiB Gesamtmenge laufen über 16 echte 16-MiB-Aufrufe; verschiedene vorab definierte Noncepräfixe für jede Stufe und alle 16 Chunk-Tags werden geprüft. Chunkkopien zählen zur gemessenen Zeit. Die bisherige 512-MiB-Pipelineprobe wurde entsprechend direkter Benutzeranweisung auf 256 MiB reduziert. Eine neu erzeugte v13-Baseline ist ein Stabilitätsvergleich desselben Algorithmusstands; alte v12-Zahlen mit zehn Suites oder sechsstufiger Paranoia sind dafür kein gültiger Nenner.

## Gemessene native Ergebnisse

Median in MiB/s des geprüften adaptiven Cipherstands vor der abschließenden REV9-Wiederverwendung des Key-Schedules. Die Binärhashes binden diese Zahlen an genau diesen Zwischenstand:

| Suite | Seriell, Grant 1 | Persistenter Executor, Grant 10 | Begrenzte kurzlebige Native-Teams, Grant 10 | Executor gegenüber Native-Teams |
|---|---:|---:|---:|---:|
| Camellia-256 | 58,39 | 382,87 | 384,96 | −0,5% |
| Serpent-256 | 144,61 | 832,22 | 852,55 | −2,4% |
| Standard: AES/Kalyna/Threefish/XChaCha | 123,85 | 722,99 | 686,21 | +5,4% |
| Paranoia: acht festgelegte Stufen | 25,56 | 160,33 | 160,20 | +0,1% |

Die kleinen negativen Unterschiede werden nicht als Verbesserung umgedeutet. Der gemeinsame Executor ist vor allem der geforderte gemeinsame Ownership-/Budgetvertrag; im Standard ergibt sich zusätzlich ein gemessener Vorteil. Fünf Wiederholungen ohne thermische Fixierung erlauben keine präzise Aussage über Unterschiede im niedrigen einstelligen Prozentbereich. Einzelzeiten, CPU-Zeiten, verwaltete Allokationszahlen, Binaryhashes und Ausgabehashes stehen in `native-benchmark-shared.json` und `native-benchmark-standalone.json`. Native Malloc-Aufrufzahlen wurden nicht gesondert instrumentiert. Die verwendete macOS-.NET-Abfrage `PeakWorkingSet64` lieferte durchgehend 0; diese Rohwerte sind kein RSS-Nachweis. Das zusammengefasste JSON kennzeichnet Prozess-Peak-RAM deshalb als nicht verfügbar.

Der abschließende Gegenlauf mit der geforderten Wiederverwendung des Key-Schedules verwendet dieselben öffentlichen Inputs, Grant 10, einen vollständigen Warmup und fünf 256-MiB-Messungen. Alle vollständigen Ausgabe-/Taghashes stimmen mit dem vorherigen Stand überein. Dieser finale Stand ist bytegleich zum universellen Gesamtbuild:

| Suite | Final mit Worker-Schedule, MiB/s | Gegen vorherigen gemeinsamen Executor |
|---|---:|---:|
| Camellia-256 | 380,15 | −0,7% |
| Serpent-256 | 865,95 | +4,1% |
| Standard | 733,46 | +1,4% |
| Paranoia mit acht Stufen | 156,18 | −2,6% |

Rohdaten und finale Binaryhashes: `native-benchmark-shared-reuse.json`. Die kleinen positiven und negativen Unterschiede stehen unter denselben Einschränkungen hinsichtlich thermischer Last und Hintergrundprozessen. Der endgültige Vertrag ist durch Quellreview, 61.498 unabhängige ARM64-Checks, 247 Executorchecks, 1.296 x64-Korpuschecks sowie jeweils 1.296 ASan/UBSan- und TSan-Checks bestätigt. Die vollständigen Paket-KATs bestehen nach dem abschließenden ZPAQ-/Cipher-Gesamtbuild auf beiden Slices.

## Tatsächlicher MAC-Root und verbleibende Walltime

Der separate Test `performance.mac-root-phases` misst den unveränderten kryptografischen `ParallelContainerAuthenticator.ComputeAsync`-Pfad. Ein optionaler AsyncLocal-Beobachter speichert ausschließlich Phasenzeiten. Die Kontrolle ohne Beobachter und sämtliche Worker-/Wiederholungsvarianten liefern exakt dieselben beiden Tags. Öffentliche 64 MiB Ciphertext plus 59 Byte Präfix bilden 65 Blätter. Pro Workerwahl: ein vollständiger Warmup und fünf Läufe; kein äußerer CPU-Lease, der die tatsächlichen Leaf-/Root-Leases blockieren würde.

| Worker | Gesamte Walltime, Median | Root einschließlich Initialisierung/finaler Tags | Walltime außerhalb der Leaf-Batches | Median des Root-Anteils |
|---|---:|---:|---:|---:|
| 1 | 223,892 ms | 0,0651 ms | 5,715 ms | 0,0292% |
| 10 | 53,120 ms | 0,0576 ms | 5,512 ms | 0,1062% |

Die Leaf-Intervalle enthalten Scheduling, Permit-Wartezeit, beide Leaf-MAC-Familien und Join. Die übrige Walltime umfasst Keyvorbereitung, MemoryStream-Lesen/Kopien, Root, Cleanup und nicht separat gemessenen Verwaltungs-/Warteaufwand. Sie ist deshalb kein allgemeiner unvermeidbarer serieller CPU-Anteil und kein Disk-I/O-Nachweis. Es werden weder sequenzielle Rootabhängigkeiten entfernt noch ein Many-Core-Speedup aus ihrem kleinen Anteil extrapoliert. Der einzelne Test bestand in 2,269 s; der Runner beobachtete 460 MiB Prozess-Peak-RSS. Vollständige fünf Messreihen, CPU-/Allokationswerte, beobachtete Hostdaten sowie exakte Assembly-/Quellhashes stehen in `mac-root-phases.json`.

## Untersuchte Kandidaten und Entscheidung

| Hotspot / Kandidat | Änderung und Plattform | Nachweis / Messung | Entscheidung |
|---|---|---|---|
| Zweifache ChaCha-Keyinitialisierung je Bereich | Redundantes SetKeyWithIV entfernt; das folgende SetKey setzt Key, IV, 20 Runden und Startcounter vollständig | Voruntersuchung 21.09.: sieben Wiederholungen, 64 B etwa +1,8%, 4096 B etwa +1,2%, 16 MiB etwa +4,5%; endgültiger Algorithmus zusätzlich gegen vollständige libsodium-/Go-AEAD geprüft | Übernommen; kleine frühere Mikrogewinne sind kein v13-Ende-zu-Ende-Speedup |
| Key-Schedule einmal je exklusivem CTR-Worker statt je Claim | Gemeinsamer AES/MARS/SHACAL/Camellia/Serpent-Treiber hält Cipher und SetKey innerhalb genau eines Workeraufrufs; neuer CTR-Zustand mit vollständigem absolutem Counter pro Claim | Der Vendorvertrag trennt Blockcipher und CTR-Zustand. Früherer Vor-REV9-Prototyp: AES etwa +10,8%, SHACAL etwa +2,2%, MARS etwa −12,7%. Dieser historische Befund ist keine Messung der finalen Fassung | Für den ausdrücklich geforderten REV9-Lebensdauervertrag übernommen; unabhängiger Quellreview, komplette Primitive-/Executor-Gegenprüfung und erneute Sanitizerläufe. Kalyna verwendet ebenfalls einen exklusiven Schedule pro Worker |
| Threadneuerzeugung je DLL und Aufruf | Alle acht produktiven Cipher registrieren denselben synchronen Managed-Executor; .NET-Threadpool persistent, Jobkontexte operationsgebunden | Tabelle oben; 247 Tests mit Fehler-Injektion und realen 16-MiB-Cipherteams bis 4096 logischen Jobs | Übernommen; keine Keys in persistenten Pools und keine erneute Permit-Anforderung durch Kinder |
| Verdecktes 64er-Cap aus 256-KiB-Claims | Claimgröße adaptiv aus Blockanzahl und Grant, etwa vier Claims pro Worker, vollständiger Primitiveblock als Minimum; dynamische Job-/Polysegmente | Grants 65/128/1024/4096 fordern in allen acht tatsächlichen Cipherpfaden genau diese Teamgrößen an; Ergebnisse bytegleich. Kein physischer 4096-Core-Speedup behauptet | Übernommen; kleine Inputs bleiben unter der gemessenen Parallelitätsschwelle seriell |
| Camellia-Tabellenzugriffe auf geheimnisabhängigen Adressen | Schedule und 24 Runden verwenden öffentlichen Volltabellenload plus Register-TBL auf ARM64; portable volatile-Volltabellenauswahl auf x64 | RFC/BC-Blockanker, 61.498 unabhängige Checks, x64-Korpus, instrumentierte Adapter, Disassembly und unabhängiger Review | Sicherheitskorrektur übernommen. Ursprünglichen unsicheren Tabellenpfad nicht wegen Geschwindigkeit als Produktfallback behalten |
| Exklusive In-place-Stufen | Bestehende sichere In-place-Verarbeitung erhalten, Alias-/Endbereichsvalidierung erweitert | Einzelbyte-/Block-/Claim-/Chunkgrenzen, Disjunktheit und Bytegleichheit gegen externe Referenzen | Übernommen/beibehalten; keine restrict-Annahme und keine Keystream-Dateien |
| Alternative SIMD-Kerne, parallele CTR-Stufen mit privaten Keystreams, GPU | Kein neuer Camellia-/Serpent-SIMD-Mehrblockkern und keine GPU-Offload-Lebensdauer eingeführt | Sichere vorhandene Vendorpfade und öffentliche NEON-Auswahl nutzen; zusätzliche parallele CTR-Stufen würden private Puffer/Joinbarrieren benötigen | Keine unbewiesene Implementierung übernommen; keine erfundenen Beschleunigungsbehauptungen |

Ein zusätzlicher Vergleich vor der abschließenden Worker-Schedule-Änderung prüfte bevorzugte Claimgrößen von 64/128/256/512/1024 KiB bei Grant 10, je einem Warmup und fünf 16-MiB-Messungen. Alle 25 Cipher-/Größenkonfigurationen liefern identische Ausgaben. Der Median bei 64 gegenüber 256 KiB beträgt für MARS 1717,53 gegenüber 1374,61 MiB/s, für Camellia 416,49 gegenüber 390,81 MiB/s; AES erreicht seinen höchsten Median bei 128 KiB. Diese kurzen geordneten Durchläufe haben keine Thermalkontrolle und zeigen keinen gemeinsamen Gewinner. Die adaptive Präferenz 256 KiB bleibt erhalten; ein pauschaler Optimierungsgewinn wird daraus nicht abgeleitet. Die vollständigen Werte, Reihenfolge und Kandidatenhashes stehen in `claim-grain.json`. Oberhalb der adaptiven Grenze können unterschiedliche Präferenzen dieselbe reale Claimgröße erzeugen.

Historische Mikroexperimente stehen unverändert in `docs/evidence/v13-native-20260921/{xchacha-initialization,ctr-reuse-rejected}.json`. Sie sind vor REV9 entstanden und ausdrücklich keine finale Camellia-/Paranoia-8- oder Containerbenchmarkevidenz.

## Sicherheits- und Parallelitätsvertrag

Das CPU-Lease umfasst den aufrufenden Thread. Native Teams können nur dieses geliehene Budget nutzen. Bei zwei gleichzeitig aktiven Pipelinechunks verteilt der gemeinsame Scheduler die Permits; es gibt keine Multiplikation „äußere Worker × volle innere Teams“. Crypto++-Schedules bleiben in bereinigten SecBlocks pro Operation/Worker. Eine durchgehende Heap-Lockgarantie für diese Bibliotheksallokationen wird nicht behauptet. Lokale CTR-Counter besitzen zusätzlich einen `noexcept`-Scope-Wipe für normale und außergewöhnliche Ausgänge. Der normale native Loader installiert nach erfolgreichem Trust-Load einen unveränderlichen gemeinsamen Callback; andere spätere Callbackadressen werden verweigert. Isolierte Native-KATs können weiterhin ohne Managedhost begrenzte eigene Teams aufrufen, was separat von der Produktkonfiguration gekennzeichnet ist.

Ein Submitfehler oder ein fehlgeschlagener Worker kehrt erst nach Join aller gestarteten Jobs zurück. Stackbasierte Kontexte, Subkeys und Polysegmente bleiben bis dahin gültig und werden anschließend gelöscht. Tests erzwingen Fehler nach 0/1/2/7 Submissions und anschließend erfolgreiche neue Operationen. Primitive-Sanitizer decken Adapter/CTR-/Camellia-Code ab, nicht sämtliche vorgebauten Vendorobjekte. ThreadSampler und Quellprüfung ergänzen sich; Sampling allein beweist keine vollständige Racefreiheit.

| Produktabschnitt | Parallelisierbar | Verbleibende Grenze / getrennte Evidenz |
|---|---|---|
| Pool-/Credentialvorbereitung | Unabhängige Pooljobs nach atomarem Cut | Fisher-Yates-/Replay-Reihenfolge pro Pool; separate Entropietests/-messung |
| Rollen nach Argon2 | Unabhängige Domainrollen, getrennte Worker-Schedules | Credential-KDF-Transcripts und Rundenreihenfolge unverändert |
| Nonceroute | Ausschließlich aktive Blockhashes verschiedener Chunks | Ein SHA3 bleibt sequenziell; Reserveblöcke erhalten keine Jobs; separate Noncegoldens |
| Acht CTR-/AEAD-Stufen | Disjunkte vollständige Counterranges, danach korrekte geordnete Stufenanwendung | Jede nächste Stufe desselben Puffers benötigt die vorige; genau eine vollständige äußere AEAD |
| XChaCha/Poly1305 | HChaCha einmal pro Chunk; unabhängige Streambereiche und exakte geordnete Feldsegmentreduktion | Transcript/Padding/Längen, finale Tagentscheidung vor Decryptausgabe |
| Globale MACs | Unabhängige Blätter und beide Familien | Kanonische inkrementelle Rootreihenfolge bleibt serialisiert; keine XOR-Tagkombination |
| ZPAQ | Bereits spezifizierte unabhängige Frames/Dateien, explizites reserviertes Kinderbudget | Parser-/Modellabhängigkeiten, gemessene Child-RSS und neue Gesamtallokationsgrenze; separate IO-Evidenz |
| Verifikation/Spool/Read-at | Begrenzte verifizierte Fenster und unabhängige Bereichschecks | Objekt-/Versionsbindung und volle globale Verifikation vor Klartext bleiben Barrieren |
| KPAR2 | Stripes/Shards und begrenzte Metadatenfenster | Feste RS-Parameter, EOF/Locator-/Manifestordnung; separate Recoverytests |
| Extraktion/Originalvergleich | Freigegebene Dateien/Bereiche | Pfadschutz, tatsächlicher Writeabschluss, Durability und atomare Publikation |
| Argon2id | Nur bestehender p=4-Unterbau; Ausführungsthreads aus gewährtem Budget | t=4, p=4, Speicher und abhängige Paranoiarunden unverändert, kein Vollauslastungsversprechen |
| Signierung/Installation | Unabhängige Artefakte bis zum gemeinsamen Gate | Exakte Paketbytes, Trustchain, monotone Buildnummer und finale atomare Entscheidung |

Die vollständige OS-Topologie-/Affinity-/Policy-Erfassung und die Prozessbaum-RAM-Koordination sind gemeinsame Integrationsbestandteile; die nativen Tests bestätigen für sich allein nur korrekte Nutzung eines erhaltenen Grants. Staging-Slots, CPU-Teamgröße und I/O-Fenster sind getrennte Größen. Kein Ergebnis behauptet beliebige Archivgrößen, unbegrenzte Skalierung, universelle Konstantzeit oder eine externe Sicherheitsfreigabe.
