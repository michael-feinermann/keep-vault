# Keep Vault v12 für macOS: normative Releaseanforderungen

Deutsch | [English](KEEP_VAULT_V12_MACOS_RELEASE.en.md)

Status: verbindliche Spezifikation und Releasecheckliste für die macOS-Ausgabe von Keep Vault 5.0.2, Build 13. Windows ist nicht Bestandteil dieses Releases und wird in einem eigenen Arbeitsschritt aktualisiert.

Der [Prüfbericht für 5.0.2](KEEP_VAULT_5_0_2_MACOS_AUDIT.md) hält den
tatsächlich nachgewiesenen Stand und verbleibende Grenzen fest. Die technische
Abnahme des endgültigen macOS-Kandidaten ist am 8. September 2026 abgeschlossen;
der letzte reguläre installierte Komplextest besteht in 70,532 Sekunden.
Die öffentliche Freigabe wurde am 9. September 2026 separat bestätigt;
siehe den [Veröffentlichungsnachweis](KEEP_VAULT_5_0_2_MACOS_AUDIT.md#öffentliche-veröffentlichung-am-9-september-2026).

## Formatgrenze

Diese Anwendung schreibt und liest ausschließlich Container mit der Magic `KZPAQ2\0` und `Version = 12`. `KZPAQ1\0` sowie jede andere Magic werden vor Headerverarbeitung und KDF abgewiesen. Alle produktiven Krypto-, Rollen-, Tweak-, Nonce- und Authentifizierungsdomains tragen `/v12/`. Es gibt weder einen v11-Leser noch eine automatische Migration, eine Legacy-Domain oder einen Fallback auf ältere Formate. Ein Container mit einer anderen Versionsnummer muss vor KDF, Authentifizierung, Entschlüsselung und Ausgabe abgewiesen werden.

KPAR2 bleibt ein eigenständiges Format der Version 4. Bei verschlüsselten Archiven ist im Locator und in der authentifizierten Metadatenhülle `ContainerVersion = 12` gebunden. KPAR2 v4 darf keine Container anderer Generationen reparieren. Ein unverschlüsseltes KPAR2-Fehlerkorrekturprofil verwendet weiterhin `ContainerVersion = 0` und stellt keine Authentizitätsbehauptung auf.

## Passwort- und PIN-Annahme

Der [v12-Vertrag für Passwort und PIN](KEEP_VAULT_V12_CREDENTIAL_POLICY.md) ist
verbindlicher Bestandteil dieser Fassung. Alle bestehenden und neuen Auswahl-
und Stärkeregeln gelten nur beim Erstellen. Entpacken, Auflisten und Recovery
benötigen keine Modelldaten und keine erneute Qualitätsprüfung. Der Rohbyte-,
Header- und KDF-Vertrag bleibt unverändert. 5.0.2 muss die korrigierte Bewertung,
Paar-/Datumsregeln, Offline-Erststart sowie DE/EN-Versionsanzeige und statische
kompatible v12-Testarchive zusätzlich zu sämtlichen bisherigen Gates prüfen.

## KDF und Speichergrenze

Die zwei Argon2id-Zweige und bei Paranoia die beiden Runden werden strikt nacheinander ausgeführt. Jeder Argon2id-Aufruf verwendet unverändert `t = 4` und `p = 4`. `p = 4` ist die interne Argon2-Lanezahl und keine Erlaubnis, zwei Argon2-Matrizen gleichzeitig zu halten. Vor dem nächsten Zweig oder der nächsten Runde muss die vorherige Matrix freigegeben und ihr sensibles Material gelöscht sein. Der Peak darf deshalb eine Matrix zuzüglich klar begrenzter Puffer nicht überschreiten.

Die v12-KDF benötigt alle vier Faktoren und verwendet ausschließlich die v12-Domains aus `V12MasterKdf`, den Rollenkontext `LE32(12)` und im Produktionspfad den nativen Export `keepvault_argon2id_v12`. Statische Known-Answer-Tests müssen die Credential-Zwischenwerte, beide Argon2-Zweige, die 1024-Bit-Masterwerte und die abgeleiteten Rollenschlüssel unabhängig vom Container-Roundtrip prüfen.

Der getrennte native Export `keepvault_argon2id_v12_kat` ist ausschließlich über einen internen, asynchron begrenzten Test-Scope erreichbar. Er akzeptiert genau `m = 8192 KiB`, weiterhin `t = 4` und `p = 4`, damit der Produktions-Worker-KAT alle zehn Suites zweimal durchlaufen kann. Der Produktionsexport muss diesen reduzierten Speicherwert ablehnen. Es gibt dafür keine Benutzer-, Umgebungs- oder Headeroption, und außerhalb des KAT-Scopes darf kein damit erzeugter Container lesbar sein.

## Parallele Produktionspipeline

Container-Verschlüsselung und -Entschlüsselung, die beiden Container-MAC-Bäume sowie ZPAQ-Kompression und -Entpacken dürfen parallel arbeiten. Dabei gelten folgende unveränderliche Grenzen:

1. Die Workerzahl ist positiv, hardwarebegrenzt und hart gedeckelt. Warteschlangen und gleichzeitig gehaltene Chunks sind begrenzt. Es gibt keinen unbeschränkten Task-Fanout.
2. Chunks werden mit stabilen Indizes verarbeitet und ausschließlich in kanonischer Reihenfolge geschrieben. Header, Nonces, Associated Data, Tags und Containerbytes dürfen nicht vom Scheduling abhängen.
3. Abbruch oder Fehler beendet alle Producer, Worker, Writer und ZPAQ-Prozesse. Alle Tasks werden beobachtet und zusammengeführt, sensible Puffer werden genullt, und kein Teilziel wird veröffentlicht.
4. Vor der Entschlüsselung in einen sichtbaren Ausgabestrom werden beide globalen v12-Container-Tags verifiziert. Bei ChaCha20-Poly1305 wird zusätzlich jeder Chunk vor Nutzung seines Klartexts authentifiziert.
5. ZPAQ erhält beziehungsweise liefert einen geordneten, begrenzten Stream. Fehler, Traversal, manipulierte Archive und vorzeitiges Prozessende dürfen weder eine teilweise Ausgabe noch einen erfolgreichen Commit hinterlassen.
6. Ein Produktions-KAT muss mit identischer vorbereiteter Entropie und identischem Klartext die echten Produktionspfade mit einem Worker und mit der produktiven Workerzahl ausführen. Für jede der zehn Cipher Suites müssen die kompletten Container bytegleich sein, beide Varianten denselben Klartext und Hash liefern und eine Manipulation vor jeder Klartextausgabe scheitern. Eine bloße Parallelisierung des Test-Runners erfüllt dieses Gate nicht.

Die Containerpipeline erlaubt einen 16-MiB-Slot je vier logische Prozessoren, abgerundet, mindestens einen und höchstens 64. Zusätzlich begrenzt ein konservatives Speicherbudget die Slotzahl: pro Slot werden zwei Chunkpuffer samt kleinem Overhead gerechnet, insgesamt höchstens ein Sechzehntel des verfügbaren GC-Speicherbudgets, soweit mindestens ein Slot hineinpasst. Bei unbekanntem oder zu kleinem Budget wird ein Slot versucht; eine fehlgeschlagene sichere Allokation bricht den Vorgang ab. Slots werden erst bei Bedarf angelegt. Die Implementierung verarbeitet begrenzte Batches und schreibt nach deren Join in kanonischer Reihenfolge. Sie überlappt den Writer nicht mit dem nächsten Batch.

Das Verhältnis 1:4 weist keine Kerne zu. Native Transformationen verwenden intern höchstens 64 Worker. Eine prozessweite Semaphore begrenzt gleichzeitig aktive Chunk-Transformationen auf `clamp(floor(2 * max(1, CPUs) / min(max(1, CPUs), 64)), 1, 64)`. Damit wächst verschachtelte Chunk-/Native-Parallelität nicht quadratisch mit der CPU-Zahl. Ein Abbruch wartet auf alle bereits gestarteten Teams und gibt deren Permits frei. Die tatsächliche Performance ist auf dem Zielhost zu messen; die Policy ist keine Garantie universell optimaler Skalierung.

Der parallele Container-MAC verwendet 1-MiB-Blätter und höchstens 64 Worker. Poly1305 wechselt ab 1 MiB auf höchstens 64 blockausgerichtete Worker und behält einen seriellen Differenzpfad. ZPAQ-Worker sind ebenfalls auf 64 begrenzt. Für den Pipe-Pfad gelten pro Frame 24 MiB komprimiert, 32 MiB unkomprimiert und 128 MiB Modellgröße sowie insgesamt höchstens 512 MiB wartende komprimierte Frames. Der gemeinsame native Verarbeitungsrahmen beträgt 6 GiB; ein Kompressionsjob reserviert 384 MiB, ein regulärer Job 592 MiB. Reguläre Jobs sind auf 64 MiB Ausgabe und 512 MiB Modellgröße begrenzt. Ein bereits authentifiziertes reguläres Archiv auf stdin darf höchstens 512 GiB groß sein. Für Entpackziele gelten 500 GiB insgesamt, 500 GiB pro Datei, 500.000 Einträge, 512 MiB Index und höchstens 2^26 Fragmente. Diese Werte sind Format- beziehungsweise Ressourcengrenzen und dürfen nicht durch unbeschränkte Queues oder stilles Resynchronisieren umgangen werden.

Reguläre verifizierte ZPAQ-Eingaben tragen ausschließlich auf der internen Pipe einen 16-Byte-Rahmen (`KV12VM` mit zwei Nullbytes und Big-Endian-64-Bit-Länge). Der native Prozess prüft Magic, Größenobergrenze, exakte Länge und EOF. Er hält die Daten in anonymem privatem VM-Speicher und senkt vor dem Parserzugriff sowohl aktuellen als auch maximalen Speicherschutz auf nur Lesen. Benannte POSIX-SHM-Objekte sind in allen Sandboxprofilen verboten. Diese Änderung betrifft kein gespeichertes Containerformat und behauptet weder unbeschränkte RAM-Kapazität noch einen Ausschluss von Betriebssystem-Swap.

KPAR2-Parität, Shardprüfsummen, Verifikation und Rekonstruktion verteilen unabhängige Stripes beziehungsweise Shards auf höchstens 64 Worker. Jeder Worker schreibt ausschließlich in disjunkte Bereiche; Manifest, Locator und reparierter Container bleiben kanonisch geordnet. Der Ein-Worker-Pfad und der Produktionspfad müssen byteidentische Parität und Rekonstruktion liefern.

## Pflichtgates

Vor einem Release müssen auf echter Apple-Hardware mit dem durch `global.json` exakt festgelegten offiziellen SDK 10.0.400 alle folgenden Gates erfolgreich sein. Das macOS-arm64-SDK-Archiv ist zusätzlich auf SHA-512 `e440e9a58d4ff7741c8342ac3e086fa9ee2dadc25e01c0449a88317a74cfbd63625b8092c3b2a131ae14b16ab3401e9cc470e578e4c65a72a0b5786bd2308cde` festgelegt und vor sowie nach dem Entpacken zu prüfen. Restore, Build, Publish und Testausführung müssen einen frisch erzeugten, auf Besitzer, Modus und Geräte-/Inodenummer gebundenen privaten NuGet-, SDK- und Artefaktbaum verwenden. Weder `obj` noch `bin` aus dem Repository dürfen in einen Releaseprozess einfließen. Ein normaler Restore muss `--locked-mode` und `-p:RestoreForceEvaluate=false` verwenden; `--force-evaluate` ist dabei verboten, weil es den gesperrten Modus überschreibt. Geprüfte Lockdatei-Hashes müssen vor und nach Restore/Build identisch sein.

1. Locked Restore, Release-Build und Native-Build für arm64 und x86_64 beziehungsweise Universal. Die Test-Natives werden erst nach dem letzten Projektbuild in das Testausgabeverzeichnis gestaged. Danach laufen die Tests mit `--no-build --no-restore`.
2. Spec-Lint ohne aktive v11-Produktionsklasse, v11-Domain, Versionskonstante oder v11-Native-Export.
3. Statische KATs und unabhängige Referenztests für KDF, MACs, alle Cipher und die zehn Suite-Kompositionen.
4. Der vollständige Testlauf erfolgt parallel mit einer sicher ermittelten Workerzahl und den CPU-, Speicher- und Exklusivitätsreservierungen des Testkoordinators. Ein zusätzlicher serieller Volltest ist auf ausdrücklichen Projektauftrag vom 05.09.2026 nicht vorgesehen. Interne 1-gegen-N-Differenztests bleiben Bestandteil der vollständigen Testmenge.
5. Der ausdrücklich ausgewählte Produktions-KAT `containers.v12-production-worker-equivalence`.
6. Der manuelle Performance-Lauf `performance.cipher-suites` misst alle zehn Cipher Suites und Kaskaden als 256-MiB-Rohprimitive sowie je dreimal über den vollständigen v12-Containerpfad für Verschlüsselung und Authentifizieren-vor-Klartext plus Entschlüsselung. Die Containerwerte verwenden das reale Produktions-Argon2id und werden als Median ausgegeben. Zusätzlich muss `performance.paranoia-256mib-e2e` exakt 256 MiB mit Kompressionsstufe 5, Paranoia und dem realen Produktions-Argon2id vollständig archivieren, verschlüsseln, KPAR2 prüfen, entschlüsseln und entpacken. Beide laufen mit `--performance --parallel 1` auf einem sonst ruhenden Host und dürfen keine Sicherheitsprüfung auslassen.
7. KPAR2-v4-Commit-, Reparatur-, Fault-Injection- und Objektbindungstests sowie Container/ZPAQ-End-to-End-Tests für Erstellen, Authentifizieren, Entschlüsseln und Entpacken.
8. Bundle-, Native-Slice-, Entitlements-, Hybrid-Signatur-, QR-Companion- und Installationsprüfung. Private Schlüssel, Passwörter und Wrapping Keys werden weder ausgegeben noch protokolliert oder in das Repository kopiert.
9. Ein öffentliches Release benötigt für Keep Vault, QR-Scanner und Keep Vault Installer eine gültige Developer-ID-Application-Signatur, erfolgreiche Apple-Notarisierung, lokale gestapelte Tickets und erfolgreiche Build-Prüfungen mit `stapler validate` sowie `spctl`. Beide Notarisierungswege müssen alle drei Apps umfassen. Eine Apple-Development-Signatur ist kein veröffentlichbares Ergebnis.

Der letzte funktionale Releasegate ist `performance.paranoia-complex-tree-e2e`: eine heterogene tiefe Ordnerstruktur mit leeren, versteckten und Unicode-Pfaden sowie stark unterschiedlichen Dateigrößen wird mit Kompressionsstufe 5, Paranoia und realem Produktions-Argon2id verarbeitet. Anschließend wird ein authentifizierter KPAR2-Schaden repariert und die vollständige Pfad-, Typ-, Größen- und SHA-256-Menge nach Entschlüsselung und Entpacken verglichen. Nach diesem Gate dürfen nur noch unverändernde Paket-, Git- und Veröffentlichungsprüfungen stattfinden; jede Code- oder Artefaktänderung macht den Gate ungültig.

Der Build darf erst als öffentlich veröffentlicht bezeichnet werden, wenn der signierte und notarisierte Inhalt exakt dem geprüften Archiv entspricht, der Tag `v5.0.2` auf dem geprüften Commit liegt und das öffentliche Release genau diese Artefakte enthält. Ein GitHub-Entwurf ist keine öffentliche Freigabe. Die technisch abgeschlossene und notarisierte Version 5.0.1, Build 12 bleibt als GitHub-Entwurf erhalten; die aktuelle Zielversion ist 5.0.2, Build 13. Eine bereits öffentlich verteilte identische Versions-/Buildkombination darf nicht nachträglich überschrieben werden.

## Selbständiger macOS-Installationssatz

Das ZIP enthält drei Apps, zehn externe Sidecars des App-Paars,
`INSTALLATION.txt` und ein vollständiges `installation-manifest.json` mit fünf
eigenen Sidecars. Die äußere Veröffentlichung bleibt ein ZIP mit fünf
Signatur-/Hashdateien. Der signierte native Einstieg `Keep Vault Installer.app`
enthält den Universal-NativeAOT-Verifier, einen vorkompilierten objektgebundenen
Löschhelfer und die versiegelten Installationsskripte. Der Ziel-Mac benötigt
für diesen Paketmodus weder .NET-SDK noch Compiler, Xcode oder Quellworkspace.
Der erforderliche root-eigene ZPAQ-v12-Anker wird durch die vorhandene
privilegierte Installation eingerichtet; ein beschreibbarer Bundle-Fallback
ist weiterhin ausgeschlossen.

Ein Erststart darf nicht davon abhängen, dass Paketnachbarn relativ zu
`Bundle.main` sichtbar bleiben. [Apple DTS](https://developer.apple.com/forums/thread/724969)
beschreibt, dass App Translocation diese Annahme aufheben kann. Fehlt das
vollständige Paket am automatisch ermittelten Ort, soll eine native Auswahl
des vollständigen Paketordners angeboten werden. Die gewählte Quelle muss
sämtliche normalen Authentifizierungs- und Kopierprüfungen durchlaufen.
Die native Ordnerauswahl ist inzwischen umgesetzt. Vor der unveränderten
Authentifizierung werden die festen 20 Paketobjekte mit `lstat` auf ihre
erwarteten Typen und Links geprüft. Beide Architektur-Slices kompilieren mit
Warnungen als Fehler; je zwölf Dateisystemproben bestehen unter ARM64 und
Rosetta-x86_64. Der tatsächliche Installer-GUI- und Administrator-Durchlauf
dieses Auswahlpfads ist für den finalen Kandidaten unter PID 46797 bestanden;
der [Prüfbericht](KEEP_VAULT_5_0_2_MACOS_AUDIT.md) bindet ihn an die unveränderten
installierten App-/Sidecar- und Ankerbytes. Dies belegt die Ordnerauswahl und
behauptet keine tatsächliche App Translocation.

Das Inventar muss vor seiner Auswertung mit beiden festen Signaturpins und
allen fünf Sidecars verifiziert werden. Es bindet jede erwartete Datei und
jedes Verzeichnis einschließlich Typ, Pfad, Modus und bei Dateien Größe und
SHA-256 sowie die übereinstimmenden Release-Metadaten aller drei Apps. Fehlende,
zusätzliche, doppelte, mehrdeutige, verlinkte und spezielle Objekte scheitern.
Die sechs Manifestdateien sind separat vollständig authentifiziert; sie
bilden die einzige Ausnahme von ihrer eigenen Inhaltsliste.

Vor operativer Ausführung kopiert der native Einstieg die festen 20
Paketeinträge in ein privates root-eigenes Verzeichnis. Eingehende ACLs werden
entfernt. Erst nach Apple-Signatur-, aktiver Prozess-CDHash- und vollständiger
Inventarprüfung erhält der angemeldete Benutzer ausschließlich lesende,
durchsuchende und ausführende ACLs. Eine erneute Prüfung bestätigt diesen
Zustand. Skripte und native Hilfen werden danach aus dieser gegen Änderungen
desselben Benutzers geschützten Kopie ausgeführt. Der aktive CDHash darf bei
Universal-Binaries nur an die aktive Architektur gebunden werden; die
Apple-Anforderung für alle Slices bleibt zusätzlich erforderlich.

Der Build muss alle drei Apps stapeln und mit `stapler validate` prüfen,
anschließend das Inventar neu erzeugen und hybridsignieren. Die endgültigen
Ticketbytes sind Teil dieses Inventars. Auf dem Zielgerät prüft
`syspolicy_check distribution` die aktuelle Apple-Verteilungsrichtlinie;
zusätzlich müssen die lokalen Ticketbytes der Ziel-App mit dem authentifizierten
Releaseinventar übereinstimmen. `syspolicy_check` allein wird nicht als
kryptografische Ticketvalidierung oder als Ersatz mit identischer Semantik
für `stapler validate` bezeichnet.

Ein Rollback bindet die zuvor authentifizierte alte App einschließlich ihrer
alten Notice- und Ticketbytes. Vorher-/Nachher-Fingerabdruck, ursprüngliche
Objektidentität und erneute Apple-/Hybridprüfung müssen übereinstimmen.
Anforderungen, die ausschließlich den neuen Kandidaten kennzeichnen, dürfen
diesen Altzustandsvergleich weder ersetzen noch verfälschen. Die bestehenden
Anker-, Paar-, Entitlement- und Transaktionskontrollen bleiben erhalten.

ARM64- und x86_64-Systemaufrufe sind gegen die tatsächlich verwendete ABI zu
prüfen. Für die verwendete Darwin-Statstruktur gilt `fstat`/`lstat` unter
ARM64 und `fstat$INODE64`/`lstat$INODE64` unter x86_64. Rosetta-Proben, native
Slice-Kompilation, tatsächliche Installation und Tests auf anderer Hardware
werden als unterschiedliche Nachweise dokumentiert. Ein nicht ausgeführter
Test auf einem separaten Intel-Mac wird nicht als bestandener Nachweis
ausgegeben.

Die Umsetzung und gezielte Komponentenprüfungen sind im 5.0.2-Prüfbericht
belegt. Die vollständige aktuelle Abnahme von Build, GUI, Installation,
Notarisierung und stabilem öffentlichem Release ist dadurch nicht vorweggenommen.

## Aktueller Abnahmestand und GUI-Abschlusszustand

Der frühere vollständige Development-Lauf endet mit 151 von 152 bestandenen
Gruppen in 492,8 Sekunden. Der einzige Fehler betrifft die veraltete
SDK-/`xcrun`-Erwartung in `packaging.hybrid-key-separation`. Die Assertion
wurde auf die festen absoluten Systemwerkzeuge des SDK-freien
Metadatenprüfers angepasst; die echte feindliche `PATH`-Gegenprobe bleibt
verbindlich. Der gesonderte Nachlauf dieser Gruppe bestand mit 1 von 1
Gruppen in 79,0 Sekunden. Sein Ergebnis liegt in
`build/audit/5.0.2-20260906/sdk-free-metadata-targeted-evidence/results.json`,
SHA-256 `b0bde7f61f03e712cf26e1d6478c2d791f0f7784629dfcf261cc3ca1debd1de6`.
Die früheren 152/152-Ergebnisse belegen nur die damaligen Quellstände.

Die sichtbare App-Prüfung unter PID 81532 bestätigt für 5.0.2, Build 13 die
Versionsanzeige in DE/EN, den Sprachwechsel der Analyse-/Ablehnungsanzeigen
und die gezielte Löschung eigenständiger Kopien bei unveränderten Originalen.
Ein nachträglich zugestelltes `TextChanged` überschreibt jedoch die
Abschlussanzeige nach dem deutschen Erfolgsdialog. Die minimale Korrektur
erhält den Abschluss nach dem programmgesteuerten Leeren und setzt bei einem
neuen Pfad die Bestätigung und Analyse weiterhin zurück. Zusätzlich wurden
vier Pfadplatzhalter für Archivierung, Entpacken und Löschung lokalisiert.

Die neue Regression `gui.erase-completion-status` muss die echte verzögerte
Ereigniszustellung sowie DE/EN-Sprachwechsel abdecken. Der frische gezielte
GUI-Lauf besteht mit 24 von 24 Gruppen in 21,2 Sekunden, einschließlich
dieser Regression mit 1,390 Sekunden. Der anschließend gestartete
Development-Durchlauf mit 153 erwarteten Gruppen wurde am 7. September 2026
gegen 14:04 Uhr durch einen Mac-Neustart unterbrochen. Für diesen Versuch
liegt kein JSON-Ergebnis vor; `final-gui-development-build.log` ist kein
Nachweis einer bestandenen Testmenge.
Der frühere 151/152-Development-Build enthält
außerdem noch den Installerstand vor der späteren Ordnerauswahl. Deren
separate Architektur- und Dateisystemprüfungen ersetzen keinen neuen
Gesamtbuild oder tatsächlichen Installerlauf. Artefaktpfade und Quellhashes
sind im [aktuellen Audit](KEEP_VAULT_5_0_2_MACOS_AUDIT.md) zugeordnet.

Die Wiederholung in `restart-development-build.log` besteht mit 153 von
153 Gruppen in 405,4 Sekunden, ohne Fehler oder blockierte Gruppen. Die
summierten Gruppenlaufzeiten betragen 921,4 Sekunden. Der Ergebnisbeleg
`restart-development-results/001-test-results.json` hat SHA-256
`343a5bac41eda92892e1958a1c0e40acc3d0a548c96883ef820f69a763cbd049`.
Alle 1.319 Quelleingaben stimmen zwischen Vorher-/Nachher-Snapshot überein;
die installierte Development-App ist byteidentisch mit dem neuen Bundle.
Der Paketnachweis bestätigt 20 Wurzelobjekte und 19 Mach-O-Dateien mit
38 Slices; beide NativeAOT-Slices prüfen das Manifest erfolgreich, ARM64
nativ und x86_64 unter Rosetta.

Der sichtbare Nachtest am 7. September 2026 ab 15:19:35 Uhr unter PID 34669
bestätigt für Version 5.0.2, Build 13 die lesbare Versionsnummer unter dem
Untertitel und alle vier Pfadplatzhalter in DE/EN. Die echte kryptografische
Löschung entfernt nur die Testkopien von Container und KPAR2; Originale und
Kontrolldatei bleiben unverändert. Der Abschlussstatus bleibt nach OK und
DE/EN/DE erhalten; ein neuer Pfad setzt Status und Bestätigung zurück. Die
App wurde danach mit Cmd-Q beendet. Beleg ist
`gui-completion-retest-result.json` im selben Auditverzeichnis.

Der endgültige Developer-ID-Kandidat ist inzwischen von Apple akzeptiert:
Job `672ab61e-4909-4fe9-a9e2-1685ea774e09`, `statusCode = 0`,
`issues = null`. `final-developer-id-build.log` bestätigt Stapling,
`stapler validate` und Gatekeeper-Annahme aller drei Apps. Die 76
Apple-Ticketzeilen sind durch Bundlealiase und Duplikate vollständig den
38 ursprünglichen Architektursignaturen zugeordnet. Der abschließende
Paketvergleich besteht für 20 Wurzelobjekte, 19 Mach-O-Dateien und
38 unveränderte Slices. Ausschließlich drei Ticketdateien kamen hinzu;
sechs Manifest-/Signaturdateien wurden erneuert. Alle anderen Bytes und
Modi sind unverändert. Der native Verifier prüft die 149 Inventareinträge
erfolgreich auf ARM64 und unter Rosetta-x86_64.

Das endgültige ZIP mit 43.678.062 Bytes hat SHA-256
`cac58f018ab60734e4565aea601d590e390d6640419eabe41e62a66f8e9c7484`.
Es ist zusammen mit seinen fünf Sidecars zur Veröffentlichung vorbereitet.
Die originale Apple-Einreichung, das Service-Log und sämtliche Prüfbelege
sind im [aktuellen Audit](KEEP_VAULT_5_0_2_MACOS_AUDIT.md) getrennt gebunden.
Alle 1.319 Quelleingaben bleiben unverändert; ein abschließender 5.0.2-Commit
und Release-Tag liegen für diesen Arbeitsstand noch nicht vor.
App-Installation und Authentifizierung für den Root-ZPAQ-Anker sind
abgeschlossen. Der vollständige Testlauf des notarisierten Developer-ID-
Kandidaten besteht mit 153 von 153 Gruppen in 405,5 Sekunden, ohne Fehler
oder blockierte Gruppen; die summierte Gruppenlaufzeit beträgt 918,9 Sekunden.
`final-developer-id-results/001-test-results.json` hat SHA-256
`8ec5a2d0a5b28c5b40f3e0ba7054cea27c46bb99c4b25a1a3e26c3e44c1db93d`.
Die zusätzlich einzeln gestarteten Releaseprüfungen bestehen ebenfalls:
Produktions-Worker-Gleichheit, paralleler MAC-KAT, v12-/KPAR2-Rundlauf,
KPAR2-Worker-Gleichheit, physische EIO-Reparatur und vollständige ZPAQ-Matrix.
Ihre Gesamtlaufzeiten und Einzelbelege sind im aktuellen Audit zugeordnet.
Die Performance-Matrix aller zehn Cipher-Suiten besteht in 195,0 Sekunden,
der 256-MiB-Paranoia-Lauf in 75,4 Sekunden und der komplexe Paranoia-Lauf mit
KPAR2-Reparatur in 73,7 Sekunden. Die Ergebnisdateien `015`, `017` und `019`
mit dem Suffix `-test-results.json` sind samt SHA-256 im aktuellen Audit
gebunden. Der Releasebuild vom 7. September 2026 ist mit
`release_publish_swap=complete` abgeschlossen; die endgültigen Artefakte
liegen unter `dist/Keep Vault-macOS/`. Der native Installer-GUI-Lauf, der
letzte komplexe Lauf nach finaler Installation und die stabile
Veröffentlichung bleiben offen.

Der anschließende tatsächliche native Installer-GUI-Test am 8. September
2026 schlug fehl. Die getrennte Argumentform `codesign -R <Anforderungstext>`
wurde als Verweis auf eine Anforderungsdatei interpretiert und mit
`invalid requirement specification` abgewiesen. Für Anforderungstext ist
`-R=<Anforderungstext>` erforderlich. Die Installation stoppte an dieser
Prüfung. Die vorherigen Build- und Apple-Ergebnisse gelten deshalb nur für
den überholten Kandidaten und erlauben keine Veröffentlichung. Die Korrektur
erfordert erneute Signierung, Notarisierung, vollständige Releaseprüfungen,
den tatsächlichen Installer-GUI-Nachtest und den letzten komplexen Lauf nach
finaler Installation. Ziel bleibt vor der öffentlichen Freigabe 5.0.2, Build 13.

Die Korrekturen sind inzwischen umgesetzt. Zusätzlich zum Codesign-Argument
wurde die fehlgeschlagene ACL-Vergabe mit numerischem UID-Text durch einen
auf UID und Kontonamen zurückgeprüften Systembenutzer ersetzt. Die ACLs
werden vor Richtlinienprüfung und nativer Ausführung vergeben. Der native
Verifier prüft Signaturbytes direkt aus gehaltenen Deskriptoren, weil erneutes
Öffnen über `/dev/fd` an Rootdateien mit Lese-ACL scheiterte. Die bisherigen
Signatur- und Identitätsprüfungen bleiben erhalten. Echte Codesign-/ACL-
Gegenproben, 15 Signaturregressionen und beide neuen NativeAOT-Slices gegen
dieselbe unveränderte Root-/ACL-Zwischenkopie bestehen. Diese Komponenten-
belege ersetzen keinen vollständigen neuen Installerlauf.

Genau neun Quell-/Test-/Buildpfade wurden geändert; 1.320 Quelleingaben
sind für den neuen Developer-ID-Build eingefroren. Passwort-/PIN-Regeln
und Archivkryptografie bleiben unverändert. Der Installereinstiegstest ist
jetzt ein automatisches Gate vor der Signierung. Die Belege liegen unter
`build/audit/5.0.2-20260908/`; `corrected-developer-id-build.log` dokumentiert
den laufenden Build. Die neue Apple-Annahme des korrigierten Kandidaten ist
inzwischen mit Job `c4d7f3a5-3a54-4954-af83-d003bc194824`, `Accepted`,
`statusCode = 0` und `issues = null` belegt. Das originale Einreichungs-ZIP
hat SHA-256 `72de4c27b7271fa264447d535826afb425f5c7ce0c5a07538eb25113478ac76b`.
Alle 38 ursprünglichen Architektursignaturen sind gebunden;
`source-after-apple.json` bestätigt 1.320 unveränderte Quelleingaben.
Stapling, Ticketvalidierung und Gatekeeper-Annahme aller drei korrigierten
Apps sind inzwischen bestanden. Der endgültige Paketvergleich bestätigt
20 Wurzelobjekte, 19 Mach-O-Dateien und 38 unveränderte Slices; die hybride
Prüfung des Inventars mit 149 Einträgen und des ZIP mit allen Sidecars besteht
auf ARM64 und unter Rosetta. Das endgültige ZIP mit 43.681.703 Bytes hat
SHA-256 `820863042b5cfacb6643b1696c8fbf8412c9529d82d921d3bb7174db3dedf81d`.
Die sechs neuen Dateien sind in `final-release-assets.json` gebunden.

Der vollständige Testlauf des korrigierten notarisierten Kandidaten besteht
mit 153 von 153 Gruppen in 410,1 Sekunden, ohne Fehler oder blockierte Gruppen;
die summierte Gruppenlaufzeit beträgt 932,8 Sekunden. Der Beleg
`corrected-developer-id-results-resumed/001-test-results.json` hat SHA-256
`c9ddc29c752b5c451fd6e1a9d4c30770a368b248463ddcd6c157f34746f58147`.
Alle zusätzlichen einzelnen Releaseprüfungen und manuellen Produktions-
messungen sind inzwischen bestanden. Die Testzeiten betragen 194,6 Sekunden
für die Performance-Matrix, 81,6 Sekunden für 256-MiB-Paranoia und
78,3 Sekunden für den komplexen Paranoia-Baum mit KPAR2-Reparatur; die
Gesamtlaufzeiten sind 194,7, 81,7 und 78,4 Sekunden. Der komplexe Lauf
verarbeitet 18 Dateien, 20 Verzeichnisse und 221.327.790 Eingabebytes und
repariert eine beschädigte Einheit. Alle 20 Ergebnis-/Zeitdateien stimmen
mit dem Ergebnisindex überein. Der korrigierte Releasebuild ist mit
Exitcode 0 abgeschlossen; `source-after-build.json` bestätigt 1.320
unveränderte Quelleingaben. `published-dist-assets.json` bestätigt die sechs
lokal bereitgestellten Dateien bytegleich mit den gesicherten finalen Assets.
Die zusätzlichen tatsächlichen GUI-Gegenproben für Startdialog-Abbruch,
unvollständiges Paket und Ordnerauswahl-Abbruch sind inzwischen bestanden.
Nach jedem Fall bleiben alle 129 geprüften Einträge der installierten Apps,
Sidecars und Root-Anker byte-, metadaten- und inodegleich; atime ist ausgenommen.
`gui-installer-negative-cases.json` und die drei zugeordneten Nachvergleiche
belegen dies. Der Abbruch des macOS-Administratordialogs wurde nicht geprüft;
die separate Ordnerauswahl belegt keine tatsächliche App Translocation.
Die normale Installation des vollständigen Kits unter PID 9073 scheiterte
anschließend an einer falschen Identitätsablehnung. Die folgende Korrektur
benötigt einen neuen Build und eigene Freigabenachweise. Neue und überholte
Kandidaten sowie Einreichungs- und endgültiges ZIP bleiben getrennt gebunden.

## Erneute Installerkorrektur am 8. September 2026

Der oben dokumentierte Kandidat mit Apple-Job
`c4d7f3a5-3a54-4954-af83-d003bc194824` bestand 153 Testgruppen und alle
zusätzlichen Releaseprüfungen, scheiterte jedoch anschließend bei der
tatsächlichen GUI-Installation mit Exitcode 2. Die vorhandene Installation
blieb in allen 129 geprüften Einträgen unverändert. Dieser Kandidat ist
nicht veröffentlichbar; seine Ergebnisse bleiben historische Nachweise.

`installer-identity-trace/finding.json` isoliert die Ursache der falschen
Identitätsablehnung: Unmittelbar nach der erfolgreichen Prüfung aller 149
Inventareinträge änderte sich ausschließlich ctime des Installer-App-
Verzeichnisses. Der konkrete Betriebssystemprozess oder Xattr-Auslöser ist
nicht bewiesen. Die Korrektur nimmt nur dieses Feld bei der länger gehaltenen
Installer-Verzeichnisbindung aus. Alle übrigen Identitätsfelder und die
Symlink-/Schreibschutzprüfungen bleiben erhalten; Paketwurzel und reguläre
Helfer binden ctime weiterhin. Die native Prüfung je Verifier-Aufruf sowie
Signaturen, Inventar und geschützte Zwischenkopie bleiben unverändert.

19 Regressionen bestehen. Eine Gegenprobe mit wiederhergestelltem altem
ctime-Verhalten schlägt gezielt fehl; eine unabhängige Quellprüfung bestätigt
den begrenzten Umfang und die fortbestehenden Negativfälle. Lange Meldungen
verwenden jetzt einen begrenzten, scrollbaren, auswählbaren und
schreibgeschützten Detailbereich. 18 Darstellungstests bestehen. Die
synthetische GUI-Prüfung bestätigt DE/EN-Langtexte bis zur letzten Markierung,
den englischen Kurztext visuell und per Accessibility sowie den deutschen
Kurztext per Accessibility. Sie ersetzt keine tatsächliche Installation.

Genau fünf Quell-/Test-/Buildpfade wurden erneut geändert; Passwort-/PIN-
Regeln und Archivkryptografie bleiben dabei unverändert. 1.320 Quelleingaben
sind für den erneuten Build in
`build/audit/5.0.2-20260908/installer-ctime-fix/` eingefroren und vor der
Notarisierung unverändert bestätigt. Der neue Einreichungskandidat ist
vorbereitet: ZIP mit 43.679.426 Bytes, SHA-256
`6bd960726f41189635343d5e47f0b509297ca4d17de06eb1038412ac0ba0aa74`.
`notary-candidate/submission-input-audit.json` bestätigt 5.0.2, Build 13 für
alle drei Apps, 20 Wurzelobjekte, 19 Mach-O-Dateien und 38 Slices.
Apple hat diese Einreichung inzwischen unter Job
`de8618c3-7404-4b7f-b35e-591fd5fd92c2` mit `Accepted`, `statusCode = 0`
und `issues = null` angenommen. Der Apple-Dienstbeleg hat SHA-256
`3fb3e3a2dfaab7b0f15f9321a07a6effe887ef866f826367c5389efa628ffc1d`;
`apple-submission-bound-audit.json` bindet ihn an das originale ZIP und alle
38 ursprünglichen Slices. `source-after-apple.json` bestätigt 1.320
unveränderte Quelleingaben. Der Build wurde nach einmaliger Übergabe von
`NOTARIZED` fortgesetzt. Der neue vollständige Testlauf besteht mit 153 von
153 Gruppen in 396,2 Sekunden, ohne Fehler oder blockierte Gruppen; die
summierte Gruppenzeit beträgt 910,3 Sekunden. Der Beleg
`corrected-developer-id-results/001-test-results.json` hat SHA-256
`b7f068c25e9be40612fa869b2b88437dbf21f267ad5c6c3cf52924b522c89a6f`.
Alle sechs zusätzlichen Einzelprüfungen bestehen ebenso wie die drei
Produktionsmessungen: Performance-Matrix 196,1 Sekunden, 256-MiB-Paranoia
81,8 Sekunden und komplexer Paranoia-Baum 75,4 Sekunden Testzeit. Der
komplexe Lauf umfasst 18 Dateien, 20 Verzeichnisse, 221.327.790 Eingabebytes
und eine erfolgreiche KPAR2-Reparatur. Der Build ist mit Exitcode 0 beendet.
Alle drei Apps bestehen Stapling, `stapler validate` und Gatekeeper. Das
endgültige ZIP hat 43.685.318 Bytes und SHA-256
`c4f069e0091259a0c6a1f76d880879facec689625b059e5d5659b70e5af112e1`.
`final-notarized-package-audit.json` bindet alle 38 unveränderten Slices an
Apple; die zulässige Differenz umfasst nur drei Ticket- und sechs
Manifestdateien. Der native Verifier bestätigt 149 Manifest-Einträge und
ZIP samt allen Sidecars jeweils für arm64 und x86_64/Rosetta, vier Aufrufe
mit Exitcode 0. `final-release-assets.json` und `published-dist-assets.json`
binden die sechs endgültigen Dateien an den lokalen Distributionsordner.
`source-after-build-independent.json` bestätigt 1.320 unveränderte Eingaben.
Diese Belege liegen unter `build/audit/5.0.2-20260908/installer-ctime-fix/`;
sie bestätigen keine öffentliche GitHub-Freigabe oder separate Intel-Hardware.

Die drei erneuten tatsächlichen GUI-Gegenproben des neuen signierten
Installers bestehen: Startdialog-Abbruch, unvollständiges Paket vor der
Authentifizierung und Ordnerauswahl-Abbruch. Alle 129 geprüften installierten
Einträge bleiben nach jedem Fall einschließlich Bytes, ctime und Inodes
unverändert. Die deutsche Paketfehlermeldung ist im Bildschirmbild
vollständig lesbar. `installer-ctime-fix/gui-installer-negative-cases.json`
und seine drei Zustandsvergleiche belegen dies. Administrator-Abbruch und
tatsächliche App Translocation sind dadurch nicht belegt. Der normale
Prozess PID 34713 ist beendet, ohne beobachteten Installationsabschluss.
`gui-normal-resume-state.json` bestätigt danach 129 vollständig unveränderte
Einträge. Der neue normale Start PID 37155 ist in
`gui-normal-resumed-start.json` zunächst vor lokaler macOS-Authentifizierung
erfasst. Nach lokaler Bestätigung ist seine normale tatsächliche Installation
bestanden: `gui-normal-success.json` belegt das per AX und Bildschirmbild
beobachtete vollständige Fenster „Installation abgeschlossen“.
`gui-normal-installed-audit.json` bestätigt beide App-Bäume in Version 5.0.2,
Build 13, zehn externe Sidecars und den root-eigenen ZPAQ-Anker bytegleich
mit dem endgültigen Paket. Physisch ist nur die kanonische Haupt-App
installiert; 21 zusätzliche LaunchServices-Einträge stehen bei dieser
Erfassung noch zur Bereinigung an. Auch die tatsächliche separate
Ordnerauswahl-Installation unter PID 46797 ist inzwischen bestanden:
`gui-fallback-success.json` dokumentiert die sichtbare vollständige
Abschlussmeldung, `gui-fallback-installed-audit.json` erneut den bytegleichen
installierten Inhalt. Tatsächliche App Translocation ist damit nicht belegt.
Die finale installierte GUI PID 56850 besteht danach die sichtbaren DE/EN-
Prüfungen von Version unter Untertitel, PIN 6 bis 16, Integrität und
Archivpfadplatzhalter. Deutsch ist wiederhergestellt und die App beendet;
Beleg `gui-main-final-de-en.json`. Die 21 zusätzlichen eigenen Haupt-App-
Registrierungen wurden gezielt entfernt. `final-registration-after.json`
bestätigt genau `/Applications/Keep Vault.app` und null weitere Registrierungen.
`final-physical-app-inventory.json` liest alle 82 unmittelbaren App-Bundles
beider Programmordner unabhängig vom Namen fehlerfrei und findet nur diese
Keep-Vault-Haupt-App in Version 5.0.2, Build 13. Der vollständige
Offline-Produktionslauf ist inzwischen bestanden. Auch der letzte
installierte Komplextest ist mit dem unveränderten regulären Starter,
frischem SDK/Restore/Build und exakt installierten Nativebytes bestanden:
Exitcode 0, 70,532 Sekunden, 18 Dateien, 20 Verzeichnisse, 221.327.790 Bytes
und eine KPAR2-Reparatur. `final-installed-test-summary.json` und
`final-installed-test-evidence/results.json` binden das Ergebnis;
SHA-256 der Ergebnisdatei ist
`905fff24578fa1db1ae3ae0019c712b5705429f644e386bfdf85d9a37fb28f96`.
`source-after-last-functional.json` bestätigt 1.320 unveränderte Eingaben,
`final-after-last-test-readonly.json` weiterhin nur die kanonische Haupt-App
mit null weiteren Registrierungen. Die technische macOS-Abnahme ist damit
im beschriebenen Umfang abgeschlossen und zur Veröffentlichung vorbereitet.
Commit, Tag und öffentliche GitHub-Freigabe werden anschließend separat
vollzogen und bestätigt; dieser Stand behauptet keine bereits erfolgte
öffentliche Veröffentlichung.
Der Offline-Nachweis wird nach dem präzisierten Credential-Vertrag getrennt
von der tatsächlichen GUI-Abnahme geführt: frischer Produktions-Core-Prozess,
eingefrorene lokale Modelle, installierte signierte Nativebytes und während
des gesamten Rundlaufs gesperrtes externes Netzwerk. Der neue Lauf
`offline-e2e-prepared/run-xdf2p6l8/` besteht mit Exitcode 0 in 79,562 Sekunden:
18 Dateien, 20 Verzeichnisse, 221.327.790 Bytes, eine authentifizierte KPAR2-
Reparatur und vollständiger Struktur-/Größen-/SHA-256-Vergleich. 77 periodische
Netzkontrollen begleiten den Lauf; positive IPv4-/IPv6-Proben bestehen davor
und danach. WLAN wird wiederhergestellt, der Watchdog hat nicht ausgelöst.
`result.json` hat SHA-256
`1c15da13a461236e81eaab8ab9bc683c3cc042503c3a84701a752ff3b44d400d`.
Der unabhängige Nachaudit `offline-e2e-independent-audit.json` besteht mit
2.814 Prüfungen und 79 Offline-Snapshots einschließlich Vor-/Nachkontrolle.
Periodische Messungen sind kein Paketmitschnitt; prozessübergreifende
Zeitordnung wird mit UTC und einer Spanne derselben Orchestrator-Uhr belegt,
nicht mit unterschiedlichen prozesslokalen Monotonic-Werten.
Die Faktorgeneration des Core-Tests verwendet synthetische Test-Samples.
Ein vollständiger Offline-GUI-Rundlauf wird nicht behauptet; die Pflicht
zum vollständigen Offline-Betrieb bleibt unverändert. Einzelbelege und Grenzen stehen im
[aktuellen macOS-Prüfbericht](KEEP_VAULT_5_0_2_MACOS_AUDIT.md).

## Vertraulicher Ausdruck

Die korrigierte DE/EN-Gestaltung wurde am 7. September 2026 ausdrücklich mit
„Sieht gut aus. Setzt das um“ freigegeben. Sie verwendet die tatsächliche
App-Version im sichtbaren und im PDF-Titel, mindestens drei volle
Passwort-Schreibzeilen, den Hinweis `PIN nicht eintragen` beziehungsweise
`Do not write down the PIN` sowie fette Metadatenbezeichnungen einschließlich
Doppelpunkt bei normal gesetzten Werten. Die Freigabe gilt für die konkret
geprüfte Vorschau; eine Layoutänderung und die Abnahme des endgültigen
signierten Produkts sind davon getrennt zu behandeln.


Der physische Schlüsselzetteldruck schreibt keine App-PDF. Trotzdem können CUPS, Drucker, Netzwerk-Druckserver oder Gerätespeicher den geheimen Auftrag zwischenspeichern. Vor dem Spoolen muss die App ausdrücklich warnen und eine Bestätigung verlangen. Gedruckt werden darf nur an einen vertrauenswürdigen, physisch kontrollierten Drucker. Keep Vault kann Kopien außerhalb des eigenen Prozesses nicht löschen.
