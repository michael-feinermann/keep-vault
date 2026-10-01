# Keep Vault 5.0.3: REV9-Testnachweis

## Aktueller REV11-Stand, 1. Oktober 2026

Kleine öffentliche Entwicklungsbelege sind zusätzlich dauerhaft unter
[`evidence/v13-rev11-20261001/development/inventory.json`](evidence/v13-rev11-20261001/development/inventory.json)
abgelegt. Dazu gehören 30 GUI-, zwölf Fortschritts-, drei Spec- und der
schreibgeschützte Golden-Test aus Build5, die konkreten Binärhashes, der
unabhängig instrumentierte native ZPAQ-Lauf und der Quellabgleich der
kryptografischen Kernpfade. Der dort dokumentierte Entwicklungsstand ist
ausdrücklich von den nachfolgenden Eigentümerkorrekturen und der finalen
signierten Installation getrennt.

REV11 wird neu geprüft. Zwölf Fortschrittsgruppen, Ressourcen-/GUI-Neustarttests und schreibgeschützte Golden-Negativtests sind im Entwicklungsharness bestanden. Native Integration, vollständiger Release-Testlauf und final installierte GUI-Abnahme stehen noch aus. Die untenstehenden Ergebnisse stammen aus REV9 und werden nicht als REV11-PASS übernommen.

Siehe [Auto-Ressourcen](KEEP_VAULT_5_0_3_AUTO_RESOURCES_REV10_REVIEW.md), [Fortschritt und Zeitverhalten](KEEP_VAULT_5_0_3_PROGRESS_ETA_REV11_REVIEW.md) und [Golden-Verifier](KEEP_VAULT_5_0_3_GOLDEN_VERIFIER_REVIEW.md).

## Historische REV9-Dokumentation

Stand 29.09.2026, macOS auf Apple M5, arm64, 10 logische CPUs und 16 GiB RAM. Der neue vollständige Kandidatenlauf aus `536d7c2afc47a27397f5a611b7ca4a0127067c82` läuft noch; seine Gesamt- und Performanceergebnisse sind PENDING. Dieser Bericht trennt die nachfolgend datierten Entwicklungsprüfungen, den früheren fehlerhaften Kandidaten und den neuen Lauf. Windows und reale TiB-Datenläufe sind auf ausdrückliche Benutzeranweisung nicht Teil dieses Durchgangs.

## Abgegrenzte Datenmengen

Reguläre Datenläufe verwenden höchstens 256 MiB Eingabe je Durchlauf. Der ausdrücklich angeforderte zusätzliche Paranoia-Strukturtest enthält einen 256-MiB-Baum plus eine weitere einzelne 256-MiB-Datei. Leere, verschachtelte, versteckte und Unicode-Verzeichnisse werden als Struktur verglichen; reine Dateihashes reichen nicht aus. Logische Größen-/Overflowtests verwenden kleine Seams oder virtuelle Längen, keine realen TiB-Dateien. Argon2id-Matrizen behalten ihre unveränderten produktiven Parameter unabhängig von dieser Quelldatenbegrenzung.

## Kern- und Entropietests vom 28.09.2026

Nach den Header-, Hashcleanup- und Ressourcenänderungen bestanden 28 gezielt ausgeführte Kern-/Entropie-/CPU-/Nonce-/Usage-/Lintgruppen. Die einzelnen Gruppenprotokolle liegen unter `work/v13-evidence/<Test-ID>.log`. Umfang:

| Bereich | Konkreter Nachweis |
|---|---|
| Routing | Elf Rollen; alle geforderten Selektorgrößen; alle vier n=11-Rejectwerte; 128er-Fehlergrenze; vollständige reduzierte Quellräume; nicht zusammenhängende Katalog-IDs; Aufnahme mit Zurücklegen über 1024 hinaus |
| Fisher-Yates | 46.234 vollständige kleine Wahlfolgen, 15.018 vollständige Zweirundenpaare, 154 zweite Identitätsfälle; 32-/64-Bit-Bounds ohne riesige Allokation |
| Unabhängige Records | 13.299 öffentliche Originalrecords in elf verschieden großen Pools; Python-Hashlib-Goldens gegen tatsächliche C#-Produktstores, Permutationen und SHA3-/SHA512-Replay; seriell, rückwärts und parallel |
| Unveränderte Finalisierung | 22 feste P1/P2-Finalisierungen und zwei feste 320-Byte-XOR-Ausgaben; eingefrorene Erwartungen mit gepinntem Datei-Hash und schreibgeschütztem Verifier |
| Ausgabe und Lebenszyklus | Alle elf SingleRound-Suites; DualRound; korrekte Zufallsrollen und Breiten; einmalige Entnahme; kein Upgrade nach gelöschten Pools; Originalsequenz-/Epochgrenzen; Budget-/RNG-/Unlockfehler; Reset-/Abbruchbarrieren; volle Kapazitätsnullung vor Freigabe |
| Nonce | 84 unabhängig eingefrorene ActivePrefix-v3-Basiswerte; aktive und Reserveänderungen; beide Basen; Stufenslices und Chunkgrenzen |
| Header | Drei positive unabhängige Header und 210 Ablehnungen über beide Reader-APIs, darunter Base64-Mehrdeutigkeit, doppelte/unbekannte Felder, falsche Profile, alte Kennungen und falsches Tweakformat |
| Hashcleanup | 112 HMAC-Schlüssel-/Nachrichtenkombinationen jeweils mit drei Splits/Resets gegen BC; eigene Pads und konkrete Providerarrays nach Dispose/Reset; SHA3-/SHA512-Regression |
| Kryptografisches Budget | Separate 64-TiB-Nutzlastgrenze; modellierte Wahrscheinlichkeitsbudgets; Writer-/Reader-Ablehnung vor großem Payloadzugriff/KDF |
| CPU | Gemeinsame Permits, Parent-Headroom, Warteschlangenabbruch, niedrigere aktive Policy; rein rechnerische große Workerzahlen; Topologieverkleinerung und spätere Vergrößerung an Join-Grenzen |

Die Public-Fixture-Verifier schreiben keine Erwartungen um. Die Python-Shuffleprüfung verwarf zusätzlich 77 mutierte Felder und bestätigte unveränderte Fixturebytes. Diese Ergebnisse quantifizieren weder Maus-Min-Entropie noch OS-CSPRNG-Sicherheit.

## Native, Ressourcen und GUI

Die nativen Cipher-Referenzen und Sanitizer sind mit ihren konkreten Binary-/Quellbezügen im [Cipherbericht](KEEP_VAULT_5_0_3_CIPHER_REFERENCE_REPORT.md) dokumentiert. Rosetta-Ausführung ist von physischer Intel-Hardware und Windows getrennt. Die Leistungsdaten einschließlich Warmup, Mediane, Speichergrößen und JIT-Grenzen stehen im [Optimierungsbericht](KEEP_VAULT_5_0_3_OPTIMIZATION_REPORT.md). Eine Primitivekaskadenmessung enthält weder KDF noch globale MACs, Kompression oder Datenträger-I/O.

`resources.shared-memory-budget` und `resources.shared-runtime-budget` bestanden mit gemeinsamem Parent-/Child-Budget, tatsächlicher additiver Child-/Argon-Matrixreservierung, Kontention, Abbruch, Wandzeit, Prozess-/Child-CPU und Fortschrittspulsen. Der native ZPAQ-Speicher-Selbsttest bestand mit zwölf Checks sowohl arm64 als auch x86_64, ebenso die geordnete Pipe-Speicherprüfung. Diese Entwicklungsbelege gelten für ihren damaligen Stand. Die späteren Capture-/Read-Pool-Änderungen und Kandidatenläufe sind unten getrennt dokumentiert.

Der echte MainWindow-Headless-Test `gui.entropy-rev9-phases-cancel` bestand erneut nach dem Kernreview in 8,0 Sekunden. Er prüft reale Mausereignisaufnahme bis zur Bereitschaft, elf sichtbare Zähler, Single-/Dual-Phasen, vollständige Faktorausgabe und den tatsächlichen Abbruchbutton während eines angehaltenen Replay. Details und noch separate Installationsnachweise stehen im [GUI-Bericht](KEEP_VAULT_5_0_3_GUI_REPORT.md).

## Integration mit signierten Entwicklungs-Natives

Der damalige vollständige ARM64-Nativesatz wurde in ein eigenes Testverzeichnis kopiert, dort mit Developer ID und anschließend mit den neuen RSA-/ML-DSA-Schlüsseln signiert. Die versionierten Buildausgaben wurden dafür nicht umsigniert. Signierlog und Binärmanifest liegen unter `work/v13-evidence/rev9-dev-trust-staging.log` und `rev9-dev-trust-binary-manifest.json`. Dies ist ein Entwicklungsnachweis, kein bereits installiertes oder notarisiertes App-Paket.

Alle 19 zusätzlichen Eingabe-/Recovery-Metadaten-/Ressourcengruppen sind damit bestanden. Zwei Recordtable-Testhelper scheiterten zunächst am reflektierten Zugriff auf eine interne Eigenschaft. Nach typisiertem Zugriff bestanden beide Wiederholungen einschließlich unabhängiger HMAC-/Skein-Orakel und aller elf Manipulationsfälle. Der ursprüngliche Fehlversuch bleibt in `rev9-dev-io-results.json` erhalten, der ergänzte Stand in `rev9-dev-io-results-with-reruns.json`.

Der anschließende vollständige V13-Kategorienlauf zeigte fünf Testfixtures mit dem macOS-Symlinkalias `/var` und einen fehlenden Empty-Array-Vertrag der älteren nativen CTR-Wrapper. Die Fixtures erhielten kanonische Testpfade; die strikte Produktprüfung von Symlinkkomponenten bleibt erhalten. Null-Längen werden erst nach vollständiger Argument- und Native-Trust-Prüfung als leere Operation behandelt. Die anschließenden V13-Läufe bestätigten die korrigierten Wrapper und Fixtures; der abschließende Headerfuzz-Rerun bestand nach Korrektur doppelter kurzer Testpräfixe ebenfalls. Der neue Kandidatenlauf aus `536d7c2` wiederholt die betroffenen Gruppen erneut. Der erste Performanceversuch zeigte außerdem eine fehlende CPU-Kontextmarkierung im Testharness; die zusätzliche Markierung verhindert eine zweite Permit-Anforderung beim verschachtelten Trust-Hash. Dieser abgebrochene Versuch liefert keine Leistungsdaten.

## Zusätzlicher Altpfad- und Integrationsabgleich

Der weitere Entwicklungsabgleich bestand mit 24 von 25 Smokegruppen. Die verbleibende Gruppe benötigte den damals noch nicht installierten rootgeschützten v13-ZPAQ-Anker. Die späteren Prüfungen am installierten Kandidaten sind unten ausgewiesen. Der Sicherheitslauf umfasste 40 Gruppen, davon zunächst 38 PASS und zwei alte Testannahmen; die Quell-/Spezifikationsgruppe hatte zunächst zwei PASS und eine veraltete Lock-Inventarerwartung. Die ursprünglichen Fehlerprotokolle bleiben erhalten und werden nicht nachträglich als erfolgreiche Gesamtläufe bezeichnet.

Der Mehrfach-Chunk-Test deckte einen produktiven parallelen Handle-Zugriff auf: Der Getter `FileStream.SafeFileHandle` kann den internen Lesepuffer zurücksetzen und den Dateizeiger bewegen. `VerifiedArchiveInput` bindet alle Handles nun vor dem Workerstart und verwendet für Magic, Längen, Bereiche und EOF ausschließlich positionsgebundene `RandomAccess`-Operationen. Der neue Capturetest prüft dreimal 32 MiB plus 37 Byte über Ciphertext-/Originalmodi, vollständige Bereichsverifikation, bytegenaue Reads und Freigabe. Er bestand in 3,162 Sekunden. Der ursprüngliche Mehrfach-Chunk-Test über alle Suites bestand anschließend in 51,609 Sekunden.

Alle acht gezielten Integrationswiederholungen bestanden am korrigierten Build ohne Warnungen/Fehler: Capture, Chunknonces, Zwei-Runden-Vorbereitung, Pipeline-Speicherpolitik, tatsächliche native CPU-Permits, unabhängige v13-Credentialcodierung, vollständiges Lock-Inventar und exakt elf produktive Trust-Komponenten. Der Zwei-Runden-Test prüft jetzt ausschließlich Paranoia positiv sowie alle elf SingleRound-Suites negativ vor Poolverbrauch. Credentialwerte wurden zuerst gegen die sechs alten v12-Referenzen nachvollzogen und anschließend mit einem unabhängigen Pythonencoder für die neue v13-Domäne eingefroren. Das Lock-Inventar erhält den bereits integrierten Windows-.NET-10-Stand und alle zusätzlichen Testprojekte; dies ist kein ausgeführter Windows-Build.

Die [Integrationsbelege](evidence/v13-integration-rev9-20260928/manifest.json) enthalten ursprüngliche Fehlversuche, gezielte Ergebnisse und exakte Assembly-/Nativehashes. Der finale Releasebuilder sichert die tatsächlich abgeschlossenen Ergebnisse seiner zwölf geplanten Testphasen getrennt außerhalb seines weggeräumten SDK-Arbeitsverzeichnisses. Ein isolierter Shellnachweis bestätigt erfolgreiche und fehlgeschlagene Phasen sowie die Ablehnung fehlender Ergebnisdateien ohne Wiederverwendung alter Resultate. Die Sicherung einer Phase belegt nicht den Abschluss späterer Phasen.

## Releasegrenze

Das macOS-Release-Preflight bestand mit der vorgesehenen Apple-Identität, unveränderten gepinnten Paket-Lockhashes und den geschützten externen Schlüsseldaten. Das Notarisierungsprofil `Keep Vault v13` war bei einer zwischenzeitlichen Wiederaufnahme am 29.09. nicht verfügbar; deshalb wurde damals auf Benutzerwunsch ein Kandidat für einen späteren Apple-Schritt vorbereitet. Nach Freigabe des Profils wurde der Kandidat `253b5fa` tatsächlich notarisiert und installiert. Sein Gesamtlauf scheiterte anschließend an den unten erhaltenen zwei Fehlern. Der neue vollständige Lauf verwendet `536d7c2`; sein Abschluss bleibt offen. Die Apple-Signieridentität bleibt im Apple-Schlüsselbund, RSA-/ML-DSA- und Wrapping-Schlüssel verbleiben im VeraCrypt-Speicher. Ein früherer Preflight oder Kandidat ersetzt keinen Nachweis für spätere Paketbytes.

Der vollständige Testlauf gegen die endgültig signierten Dateien, die produktiven Archiv-/KPAR2-Läufe, finale Installation, reale GUI, Paketverifikation und Veröffentlichungsabgleich werden im [Releasebericht](KEEP_VAULT_5_0_3_RELEASE_REPORT.md) mit ihren tatsächlichen Ergebnissen ergänzt. Ein Zwischenstand oder eine einzelne bestandene Gruppe ist keine Freigabe.

## Ergänzende Prüfungen am 29.09.2026

Alle vier KDF-Gruppen sind nach gezielter Wiederholung bestanden: feste 1-GiB-Argon2id-Referenz, Credential-/PMI-/Rundenbindung, 512/512-Faktorsplit sowie Peak-RSS und Verzicht auf abgeleitete Kosten im Header. Der letzte Test erwartete zunächst ein Feldinventar ohne das neue öffentliche `NonceDerivationMode`. Die korrigierte vollständige Feld-/Profilprüfung besteht in 11,1 Sekunden; `Argon2MemoryKiB` bleibt zwingend 0. Es wurden keine produktiven KDF-Kosten verändert.

Zusätzlich wurden 25 Container-/Recovery-/Löschgruppen ohne installierten ZPAQ-Anker seriell ausgeführt. Zunächst bestanden 24, darunter alle zwölf Recovery-Suites, Container-Worker-Äquivalenz, vier Löschgruppen und physische EIO-Reparatur. Der adversariale KPAR2-Test enthielt noch eine positive Kontrolle mit Locator-Version 12. Sie wurde auf 13 korrigiert; negative v12-Fälle sind ausdrücklich ergänzt. Der gezielte Wiederholungslauf bestand in 21,2 Sekunden. Der verwandte Container-Downgrade-Test mutiert nun zwingend 13 auf alte Versionen einschließlich 12; seine ZPAQ-abhängige Wiederholung stand zu diesem Zwischenstand noch aus. Die späteren Kandidatenresultate sind unten getrennt zugeordnet. Ein zusätzlicher Quellabgleich fand in den Recovery-Lesern keinen zweiten bestätigten gepufferten Handle-Race: Die betrachteten Original-/Sidecar-Dateien werden dort bereits ab ihrem ersten Zugriff positionsgebunden gelesen.

Fünf Schlüssel-/Packaginggruppen sind ebenfalls bestanden: USB-Wrapping-Reader, private Directory-Lease, Keychain-argv-Quellgate, Installer-Lock-Cleanup mit vier PTY-Fällen und Hybrid-Key-Separation. Die Hybridgruppe scheiterte zunächst bei direktem Aufruf aus `work/` am Windows-SDK-Pin. Mit unveränderter Assembly aus dem regulären macOS-Arbeitsverzeichnis bestand sie in 95,629 Sekunden. Keine echten Release-Schlüssel wurden dafür verwendet, kein SDK-Pin geändert und keine nativen Signaturen neu geschrieben.

[Ergebnisdateien, ursprüngliche Fehler und Hashbezüge](evidence/v13-integration-20260929/manifest.json) sichern diese Entwicklungsprüfungen. Endgültiger Paketsatz, reale GUI und die besonderen Paranoia-Läufe bleiben davon getrennt.

## Abschlusshärtung vor dem Releasebuild am 29.09.2026

Der erneute Review ergänzte echte Kernel-Lesehandles nach Capture, korrigierte die Darwin-ARM64-Descriptorvererbung und ersetzte die 32-Bit-Platzabfrage durch descriptorgebundenes 64-Bit-fstatfs. Build 3 bestand mit null Fehlern und Warnungen. Vier zunächst im Angriffshelper fehlgeschlagene Prüfungen wurden nach dessen ABI-Korrektur erfolgreich wiederholt; die ursprünglichen Fehler bleiben erhalten. Zusammen mit den ergänzten Speicher-, CPU-, Lockfile-, MAC-, Mehrchunk-, Entropie- und Headless-GUI-Prüfungen bestanden zuletzt 30 unterschiedliche Gruppen. 34 aufgezeichnete Ausführungen enthalten vier ursprüngliche Helperfehler und deren erfolgreiche Wiederholung.

Die neuen nativen QoS-Scopes bestanden 113 Checks, der in den bestehenden Managed-Executor integrierte QoS-/Fehlerharness 153 Checks und der Cipherexecutor 247 Checks. Letzterer prüft alle acht Cipher mit tatsächlichen Produkt-Exports, exakte Bytes/Tags und große logische Grants. Dieser damalige Lauf nutzte unveränderte Entwicklungs-Natives; er ist nicht nachträglich dem neuen Nativebuild zugeordnet. Der spätere Neubau und dessen eigene Slice-KATs stehen unten. Kleine öffentliche Nachweise stehen im [Hashmanifest](evidence/v13-final-hardening-20260929/manifest.json).

Der anschließende Build 4 für die getrennte Recovery-/Extraktionsvolumebindung bestand ebenfalls ohne Warnungen und Fehler. Die fünf gezielten Wiederholungen (Volume-/Kapazitätsplan, adversarialer KPAR2-Test, physische EIO-Reparatur und beide Quell-/Spezifikationsgates) bestanden. Die Testbinärdateien blieben während aller fünf Läufe unverändert. Ein verbleibender Testhelper verwendet jetzt ebenfalls die zentrale Repositoryerkennung einschließlich Git-Worktrees und der expliziten Release-Quellwurzel.

## Korrekturprüfung nach dem installierten Kandidaten, 29.09.2026

Der vollständig installierte und notarisierte Kandidat aus `253b5fa` bestand 225/227 Gruppen, darunter den 512-MiB-Paranoia-Baum mit Beschädigung und KPAR2-Reparatur. Zwei Fehler wurden behoben: unabhängige GUI-Gesamt-/Einzeldateibudgets im Test explizit setzen und den sachlichen `InvalidDataException`-Vertrag für beschädigte unverschlüsselte ZPAQ-Archive im macOS-Adapter erhalten. Die zusätzliche Gruppe `io.plain-manifest-rejection` prüft eine gültige Kontrolle sowie SHA3-only-, Skein-only- und Archivbyte-Manipulation; jeder Fehler wird beim Prüfen, beim Lease-Erwerb und vor der Extraktion abgewiesen. Kein Lease/Output und vollständige Capture-Freigabe werden geprüft. Die beiden konstantzeitlichen Hashvergleiche und das gemeinsame Freigabegate bleiben erhalten. Drei veraltete `--changed`-Testnamen wurden ebenfalls auf die registrierten v13-IDs korrigiert.

Ein frischer isolierter Release-Testharness mit unveränderten installierten Native-Dateien bestand danach sieben gezielte Gruppen einschließlich beider ursprünglichen Fehler und der neuen Negativprüfung. `zpaq.full-matrix` erreichte dabei alle nachgelagerten Untertests. Details, Buildlogs, Kommandos, Dateihashes und Einzel-JSONs: `work/v13-postfix-check-rgngbcfz/evidence/`. Der nachfolgende vollständige Releasebuild und die reale finale GUI bleiben erforderlich; diese sieben Ergebnisse sind keine erneute Gesamtfreigabe.

Der ergänzte Koordinatornachweis für die öffentliche Paranoia-Ergebniszeile bestand im neu gebauten Harness (`infra.runner-invariants`, `work/v13-postfix-check-58cp34m8/evidence/`). Er schützt zugleich den Ausschluss anderer Nicht-Performance-Diagnosen und des privaten Workerumschlags. Der native Locale-Regressionsnachweis und vollständige Neubau bestanden ebenfalls; alle 39 finalen Native-Dateien sind bytegleich zum erfassten Vorbestand des ursprünglichen Abschlusslaufs. Details und Originalprotokolle liegen unter `work/v13-evidence/native-locale-rebuild-20260929/run-vwmxvn7e/`. Diese Nachprüfungen ändern den dokumentierten historischen Gesamtstatus 225/227 nicht.

## Eingefrorener Kandidat 536d7c2

Der neue vollständige Build läuft aus dem unveränderten Releaseworktree bei `536d7c2afc47a27397f5a611b7ca4a0127067c82`. Nach dem nativen Neubau und erneut nach beiden Slice-KATs stimmten alle 1.931 erfassten versionierten Dateien einschließlich sämtlicher 39 Native-Dateien mit dem eingefrorenen Ausgangsbestand überein. Der tatsächliche Builder bestand den ARM64-KAT und danach den x86_64-KAT unter Rosetta. Logpräfix, Architekturzuordnung, Harnessquellen/-binärdateien und Native-Eingaben sind in `work/v13-evidence/native-freeze-536d7c2-20260929/kat-association.json`, `harnesses-after-kats.json` und den drei Vorher-/Nachherinventaren gebunden. Das ist ein frischer Slice-Nachweis, kein physischer Intel- oder Windowslauf.

Die sieben vor diesem Freeze ausgeführten Korrekturgruppen sind unverändert unter `work/v13-evidence/postfix-check-20260929/` gesichert: `trust.native-tools`, `io.plain-manifest-rejection`, `io.verified-original`, `io.verified-input-state`, `gui.resource-policy`, `zpaq.full-matrix` und `infra.runner-invariants`, jeweils mit Seed `0x5EED0313`. `context.json` und `reviewed-source-diff.patch` binden den damaligen verwalteten Korrekturstand auf Basis `253b5fa`; die Native-Dateien gehörten zum vorherigen installierten Kandidaten. Diese gezielten PASS-Ergebnisse werden nicht als vollständiger Testlauf von `536d7c2` ausgegeben.

Aktueller Status des neuen Gesamt- und Performanceablaufs: RUNNING/PENDING. `work/v13-evidence/finish-5.0.3.z9wGjkRO/build.log` und die getrennten Phasenkopien unter `work/v13-evidence/final-run-536d7c2-20260929/` sind die vorgesehenen Ist-Belege. Erst nach Abschluss werden automatische Gruppen, sechs funktionale Wiederholungen und fünf manuelle Performancephasen getrennt zusammengeführt. Der 512-MiB-Test muss seine neue öffentliche E2E-Zeile tatsächlich liefern; die beim historischen Lauf nicht erhaltenen Detailzahlen werden nicht rekonstruiert. Reale finale GUI, Paket-/Downloadabgleich und Veröffentlichung bleiben eigene Nachweise.
