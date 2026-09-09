# Keep Vault v12: Recheck mit GPT-5.6-sol

Deutsch | [English](KEEP_VAULT_V12_GPT56SOL_RECHECK.en.md)

Historisches Protokoll des Auftrags vom 2. September 2026. Die folgenden
Statusangaben und Auftragsgrenzen beziehen sich auf diesen damaligen Lauf.
Für die Ausgabe 5.0.2 gelten die aktuellen
[macOS-Releaseanforderungen](KEEP_VAULT_V12_MACOS_RELEASE.md), der
[Passwort- und PIN-Vertrag](KEEP_VAULT_V12_CREDENTIAL_POLICY.md) und der darauf
aufbauende [Windows-Portierungsauftrag](KEEP_VAULT_V12_WINDOWS_UPDATE.md).
Diese Verweise erklären keine damals offene Prüfung nachträglich für bestanden.
Die spätere technische Abnahme des endgültigen macOS-5.0.2-Kandidaten ist am
8. September 2026 im [aktuellen Prüfbericht](KEEP_VAULT_5_0_2_MACOS_AUDIT.md)
abgeschlossen dokumentiert: 153/153 Gruppen, zusätzliche Releasegates,
tatsächliche Installer-/App-GUI, vollständiger Offline-Core-Lauf und letzter
regulärer installierter Komplextest. Öffentliche Veröffentlichung und
Tagzuordnung folgen getrennt. Die Zwischenstände dieses historischen
Recheck-Protokolls sind keine gegenteilige aktuelle Statusmeldung.

Stand des damaligen Auftrags: 2026-09-02. Dieser Prüfauftrag war absichtlich
kein Veröffentlichungsauftrag. Sein Durchlauf durfte bauen, testen, committen
und pushen, aber weder ein GitHub-Release noch eine öffentliche ZIP oder eine
Notarisierungsveröffentlichung erzeugen.

## Spätere Einordnung vom 7. September 2026

Der ursprüngliche Auftrag vom 2. September und seine damaligen Befunde bleiben
historisch unverändert. Der spätere Auftrag für 5.0.2 umfasst ausdrücklich den
vollständigen Test-, Notarisierungs-, Upload- und stabilen öffentlichen
Release-Durchlauf. Die damalige Beschränkung auf einen nichtöffentlichen
Recheck ist deshalb keine aktuelle Veröffentlichungssperre dieses Auftrags.
Die endgültige DE/EN-Schlüsselzettelvorschau mit Versionsnummer, drei
Passwortzeilen, PIN-Hinweis und fetten Feldbezeichnungen wurde inzwischen
mit „Sieht gut aus. Setzt das um“ freigegeben. Das ist keine vorweggenommene
technische Abnahme des neuen Releaseartefakts.

Seitdem wurde der fehlende selbständige Installationssatz im Produkt- und
Packagingcode ergänzt: native Installer.app, Universal-NativeAOT-Verifier,
vorkompilierter Löschhelfer, vollständiges dual signiertes Inventar und eine
root-eigene Kopie, die der angemeldete Benutzer nur lesen und ausführen darf.
Die tatsächlich laufende Codeidentität wird an den aktiven CDHash gebunden;
alle Universal-Slices werden zusätzlich geprüft. Das endgültige Inventar
entsteht nach dem erfolgreichen Stapeln aller drei Apps und bindet auch deren
lokale Ticketbytes. Der Zieladapter kombiniert diese Bytebindung mit der
aktuellen Apple-Verteilungsrichtlinie. Gegenproben zeigen ausdrücklich,
dass `syspolicy_check distribution` allein beschädigte vorhandene Tickets
nicht zuverlässig abweist.

Der Paketrollback wurde auf die genaue Wiederherstellung des zuvor
Apple-/hybrid-authentifizierten alten Zustands ausgerichtet. Dessen gültiges
altes Ticket und seine versionsabhängigen Notices werden nicht mit den neuen
5.0.2-Bytes gleichgesetzt. Außerdem korrigiert eine architekturspezifische
Darwin-Stat-Anbindung den x86_64-ABI-Fehler; ARM64- und Rosetta-x86_64-Proben
bestätigen die unterschiedlichen benötigten Exporte. Diese Ergebnisse
belegen keinen Lauf auf einem separaten physischen Intel-Mac.

Die Ordnerauswahl bei durch App Translocation getrennten Paketnachbarn ist
inzwischen implementiert. Sie prüft genau 20 Paketobjekte mit ihren Typen
und Links; jede ausgewählte Quelle durchläuft denselben geschützten Kopier-
und Authentifizierungsweg. Dieser spätere `InstallerMain.swift`-Stand hat
SHA-256 `74b4e6ecb612a5b81d24569a4ee78a7e4c35453d03a98b540fd7d4a9022bbde1`.
Kompilation beider Architekturen mit Warnungen als Fehler und je zwölf
Dateisystemfälle unter ARM64 beziehungsweise Rosetta-x86_64 sind belegt in
`build/audit/5.0.2-20260906/installer-translocation-review/results.json`.
Diese Komponentenprüfungen führten keine tatsächliche GUI- oder
Administratorinstallation aus. Der tatsächliche Installer-GUI- und
Erststartdurchlauf bleibt gesondert zu prüfen.

Der getrennte Development-Build in
`build/audit/5.0.2-20260906/approved-installer-development-build.log` endete
mit 151 bestandenen und einer fehlgeschlagenen Gruppe von 152 in
492,8 Sekunden. Seine Vorher-/Nachher-Quellsnapshots binden
`InstallerMain.swift` an
`fbe13c7ea165e7d4f860b422dbf711c18a05870d1ce4511237ac7ae326861406`,
also noch ohne die spätere Ordnerauswahl. Die fehlgeschlagene Gruppe
`packaging.hybrid-key-separation` enthielt eine veraltete Erwartung an
SDK-/`xcrun`-Suche im absichtlich SDK-freien Metadatenverifier. Diese Annahme
ist auf feste Systemwerkzeuge ohne `xcrun` korrigiert; die echte feindliche
`PATH`-Probe bleibt bestehen. Der gezielte Nachlauf der Gruppe bestand mit
1 von 1 Gruppen in 79,0 Sekunden. Der Ergebnisbeleg
`build/audit/5.0.2-20260906/sdk-free-metadata-targeted-evidence/results.json`
hat SHA-256 `b0bde7f61f03e712cf26e1d6478c2d791f0f7784629dfcf261cc3ca1debd1de6`.
Dieser Nachlauf ersetzt keinen vollständigen neuen Testlauf. Historische
152/152-Ergebnisse werden nicht auf diese neuen Quellen übertragen.

Die tatsächliche App-GUI mit PID 81532, Version 5.0.2 und Build 13 bestätigt
die DE/EN-Versionsanzeige und Sprachwechsel der Analyse-/Ablehnungsstatus.
Die ausgewählten Container-/KPAR2-Kopien wurden gelöscht, Originalcontainer,
ursprüngliche KPAR2-Datei und Kontrolldatei blieben unverändert. Der deutsche
Erfolgsdialog, der geleerte Pfad und die zurückgesetzte Bestätigung wurden
ebenfalls bestätigt. Danach überschreibt jedoch ein verzögert zugestelltes
`TextChanged` den Abschlussstatus mit `eraseNotAnalyzed`. Dieser konkrete
GUI-Befund steht in
`build/audit/5.0.2-20260906/approved-layout-gui-first-erase-result.json`.
Ein Minimalfix und die neue Gruppe `gui.erase-completion-status` sind
implementiert; erwartet werden dadurch 153 Gruppen. Der frisch gebaute
gezielte Lauf `Test-KeepVault --category GUI --parallel 1` bestand danach
mit 24/24 Gruppen in 21,2 Sekunden. Die neue Statusgruppe bestand in
1,390 Sekunden. Vor dem Lauf wurden 1319 Quelleingaben in
`build/audit/5.0.2-20260906/gui-fixes-source-before.json` gebunden; der
Ergebnisbeleg ist `gui-fixes-targeted-evidence/results.json` im selben
Auditverzeichnis, SHA-256
`b92cb9e4d435a3bf5449d28bb49f878aa12f7810600f41da78e0bd8cff8c3922`.
Der anschließend gestartete Development-Durchlauf mit 153 erwarteten
Gruppen wurde am 7. September 2026 gegen 14:04 Uhr durch einen Mac-Neustart
unterbrochen. Der Versuch ist in `final-gui-development-build.log`
protokolliert, lieferte aber kein JSON-Ergebnis und gilt nicht als bestanden.
Die nachfolgende Wiederholung in `restart-development-build.log` besteht
mit 153 von 153 Gruppen, null Fehlern und null blockierten Gruppen in
405,4 Sekunden; die summierte Gruppenlaufzeit beträgt 921,4 Sekunden.
`restart-development-results/001-test-results.json` hat SHA-256
`343a5bac41eda92892e1958a1c0e40acc3d0a548c96883ef820f69a763cbd049`.
Alle 1.319 Quelleingaben stimmen vor und nach dem Lauf überein; die
installierte Development-App ist byteidentisch mit dem frisch gebauten
Bundle. Das neue Paket besteht die Prüfung von 20 Wurzelobjekten,
19 Mach-O-Dateien und 38 Slices. Beide NativeAOT-Slices führten die
authentifizierte Manifestprüfung erfolgreich aus, ARM64 nativ und x86_64
unter Rosetta. Die Belege sind `restart-development-kit-audit.json` und
`restart-development-native-aot-architectures.json` im Auditverzeichnis.

Der sichtbare GUI-Nachtest ab 15:19:35 Uhr unter PID 34669 bestätigt für
5.0.2, Build 13 die Versionsanzeige unter dem Untertitel und alle vier
Pfadplatzhalter in DE/EN. Nach echter kryptografischer Löschung der
Testkopien bleibt der Abschlussstatus nach OK und DE/EN/DE erhalten.
Originalcontainer, Original-KPAR2 und Kontrolldatei bleiben unverändert;
ein neuer Pfad setzt Status und Bestätigung zurück. Die App wurde danach
mit Cmd-Q beendet. `gui-completion-retest-result.json` dokumentiert diese
Prüfung. Die Regression muss beim späteren Windows-Port unabhängig einschließlich
verzögerter Ereignisse, Sprachwechsel und erneuter Pfadwahl geprüft werden.
Diese macOS-Belege ersetzen das ebenso wenig wie einen separaten
Intel-Hardwaretest.

Die nachfolgende Apple-Abnahme des endgültigen Developer-ID-Kandidaten ist
belegt: Job `672ab61e-4909-4fe9-a9e2-1685ea774e09`, `Accepted`,
`statusCode = 0`, `issues = null`. Alle drei Apps bestehen Stapling,
`stapler validate` und Gatekeeper. Die originale Einreichung ist an sämtliche
38 Architektursignaturen gebunden; die 76 Apple-Rohzeilen sind durch
Bundlealiase und Duplikate vollständig erklärt. Der endgültige Paketvergleich
besteht mit 20 Wurzelobjekten, 19 Mach-O-Dateien und 38 unveränderten Slices.
Er weist ausschließlich drei neue Ticketdateien und sechs erneuerte
Manifest-/Signaturdateien aus. Die tatsächliche hybride Inventarprüfung
besteht mit 149 Einträgen auf ARM64 und unter Rosetta-x86_64.

Die sechs vorbereiteten Releaseassets enthalten das ZIP mit 43.678.062 Bytes
und SHA-256 `cac58f018ab60734e4565aea601d590e390d6640419eabe41e62a66f8e9c7484`.
Belege sind `final-release-assets.json`, `final-notarized-package-audit.json`
und `final-native-installation-verifier.json`; die originale Apple-Einreichung
und das Service-Log sind im aktuellen 5.0.2-Audit separat gebunden.
Die 1.319 Quelleingaben bleiben unverändert. App-Installation und
Authentifizierung für den Root-ZPAQ-Anker sind abgeschlossen. Der
vollständige Testlauf des notarisierten Developer-ID-Kandidaten besteht
mit 153 von 153 Gruppen in 405,5 Sekunden, ohne Fehler oder blockierte
Gruppen; die summierte Gruppenlaufzeit beträgt 918,9 Sekunden.
`final-developer-id-results/001-test-results.json` hat SHA-256
`8ec5a2d0a5b28c5b40f3e0ba7054cea27c46bb99c4b25a1a3e26c3e44c1db93d`.
Auch die zusätzlichen einzelnen Releaseprüfungen für Produktions-Worker,
parallelen MAC-KAT, v12-/KPAR2-Rundlauf, KPAR2-Worker, physische EIO-Reparatur
und vollständige ZPAQ-Matrix bestehen. Die Performance-Matrix aller zehn
Cipher-Suiten besteht in 195,0 Sekunden, der 256-MiB-Paranoia-Lauf in
75,4 Sekunden und der komplexe Paranoia-Lauf mit KPAR2-Reparatur in
73,7 Sekunden. Die Ergebnisdateien `015`, `017` und `019` mit dem Suffix
`-test-results.json` und ihre SHA-256-Werte stehen im aktuellen Audit.
Der Releasebuild vom 7. September 2026 ist abgeschlossen; die endgültigen
Artefakte liegen unter `dist/Keep Vault-macOS/`. Der tatsächliche native
Installer-GUI-Lauf, der letzte komplexe Lauf nach finaler Installation und
die stabile Veröffentlichung sind noch offen. Der abschließende
5.0.2-Commit, Tag und Uploadabgleich stehen ebenfalls aus.

Der anschließende tatsächliche native Installer-GUI-Test am 8. September
2026 schlug wegen der Codesign-Argumentform fehl. Die Form `-R` mit
getrenntem Anforderungstext verweist auf eine Datei; Anforderungstext benötigt
`-R=<Anforderungstext>`. Der Installer brach bei dieser Prüfung ab. Damit ist
der zuvor getestete, signierte und von Apple akzeptierte Kandidat überholt
und nicht zur Veröffentlichung freigegeben. Seine PASS-Ergebnisse bleiben
historisch belegt. Die Korrektur erfordert erneute Signierung, Notarisierung,
vollständige Releaseprüfungen, den tatsächlichen Installer-GUI-Nachtest und
den letzten komplexen Lauf nach finaler Installation.

Die anschließenden Korrekturen sind umgesetzt: Codesign-Anforderung als
Textargument, Kontoname mit systemseitiger UID-Rückprüfung statt numerischem
UID-Text für ACLs, ACL-Vergabe vor Richtlinienprüfung und nativer Ausführung
sowie Signaturprüfung aus gehaltenen Bytes statt erneutem Öffnen über
`/dev/fd`. Bestehende Signatur- und Identitätsprüfungen bleiben erhalten.
Die echten Codesign-/ACL-Gegenproben und 15 Signaturregressionen bestehen.
Neu gebaute NativeAOT-Verifier bestehen auf ARM64 und unter Rosetta gegen
dieselbe unveränderte alte Root-/ACL-Zwischenkopie, an der der alte Verifier
mit Zugriffsfehler abbricht. Dieser gezielte Vergleich belegt keinen neuen
Gesamtinstallerlauf.

`build/audit/5.0.2-20260908/correction-source-delta.json` weist neun geänderte
Quell-/Test-/Buildpfade und 1.320 eingefrorene Quelleingaben aus. Passwort-/PIN-
Regeln und Archivkryptografie bleiben unverändert. Der Einstiegstest ist
automatisch vor Signierung im Paketbau vorgeschrieben;
`installer-entry-release-gate.log` besteht. Der neue Developer-ID-Build läuft
in `corrected-developer-id-build.log`. Die korrigierte Einreichung wurde
inzwischen von Apple unter Job `c4d7f3a5-3a54-4954-af83-d003bc194824` mit
`Accepted`, `statusCode = 0` und `issues = null` angenommen. Ihr originales
ZIP hat SHA-256 `72de4c27b7271fa264447d535826afb425f5c7ce0c5a07538eb25113478ac76b`.
Alle 38 ursprünglichen Architektursignaturen sind gebunden;
`source-after-apple.json` bestätigt 1.320 unveränderte Quelleingaben.
Stapling, Ticketvalidierung und Gatekeeper-Annahme aller drei korrigierten
Apps bestehen inzwischen. Der endgültige Paketvergleich bestätigt
20 Wurzelobjekte, 19 Mach-O-Dateien und 38 unveränderte Slices. Die hybride
Prüfung des Inventars mit 149 Einträgen und des ZIP mit allen Sidecars besteht
auf ARM64 und unter Rosetta. Das endgültige ZIP mit 43.681.703 Bytes hat
SHA-256 `820863042b5cfacb6643b1696c8fbf8412c9529d82d921d3bb7174db3dedf81d`.
`final-release-assets.json` bindet genau sechs neue Dateien.

Der korrigierte notarisierte Kandidat besteht mit 153 von 153 Testgruppen
in 410,1 Sekunden, ohne Fehler oder blockierte Gruppen; die summierte
Gruppenlaufzeit beträgt 932,8 Sekunden. Der Beleg
`corrected-developer-id-results-resumed/001-test-results.json` hat SHA-256
`c9ddc29c752b5c451fd6e1a9d4c30770a368b248463ddcd6c157f34746f58147`.
Alle zusätzlichen einzelnen Releaseprüfungen und manuellen Produktions-
messungen sind inzwischen bestanden: Testzeiten 194,6 Sekunden für die
Performance-Matrix, 81,6 Sekunden für 256-MiB-Paranoia und 78,3 Sekunden
für den komplexen Paranoia-Baum mit KPAR2-Reparatur; Gesamtlaufzeiten
194,7, 81,7 und 78,4 Sekunden. Der komplexe Lauf umfasst 18 Dateien,
20 Verzeichnisse und 221.327.790 Eingabebytes und repariert eine beschädigte
Einheit. Der korrigierte Releasebuild ist mit Exitcode 0 abgeschlossen;
alle 20 Ergebnis-/Zeitdateien stimmen mit dem Index überein.
`source-after-build.json` bestätigt 1.320 unveränderte Quelleingaben,
`published-dist-assets.json` alle sechs lokal bereitgestellten Dateien
bytegleich mit den privat gesicherten finalen Assets. Die tatsächlichen
GUI-Gegenproben für Startdialog-Abbruch, unvollständiges Paket und
Ordnerauswahl-Abbruch sind inzwischen bestanden. Alle 129 geprüften
Einträge der installierten Apps, Sidecars und Root-Anker bleiben nach jedem
Fall byte-, metadaten- und inodegleich; atime ist ausgenommen.
`gui-installer-negative-cases.json` und die drei Nachvergleiche belegen dies.
Der Abbruch des macOS-Administratordialogs ist nicht geprüft; die separate
Ordnerauswahl ist kein Nachweis tatsächlicher App Translocation. Die normale
Installation des vollständigen Kits unter PID 9073 scheiterte anschließend
an einer falschen Identitätsablehnung. Die folgende Korrektur benötigt einen
neuen Build und eigene Freigabenachweise. Alte PASS-Ergebnisse und Apple-Jobs
werden nicht auf den erneut geänderten Kandidaten übertragen.

Gezielte Komponenten-, Negativ-, ABI- und private Rollbackprüfungen sowie die
Kompilation beider Installer-Einstiegsslices sind dokumentiert. Der vollständige
aktuelle Build-/GUI-/Installationsdurchlauf, der letzte
komplexe Paranoia-Lauf und die stabile öffentliche Veröffentlichung sind erst
mit ihren neuen Artefakten und Ergebnissen abgeschlossen. Aktuelle Nachweise
und offene Punkte stehen im [5.0.2-Prüfbericht](KEEP_VAULT_5_0_2_MACOS_AUDIT.md).
Die unveränderliche Installationskopie ist dabei kein nachträglicher Beweis
für den getrennten historischen Befund zur Absicherung des Build-Quellbaums.

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

Die drei erneuten tatsächlichen GUI-Gegenproben des neuen signierten
Installers bestehen: Startdialog-Abbruch, unvollständiges Paket vor der
Authentifizierung und Ordnerauswahl-Abbruch. Alle 129 geprüften installierten
Einträge bleiben nach jedem Fall einschließlich Bytes, ctime und Inodes
unverändert. Die deutsche Paketfehlermeldung ist im Bildschirmbild
vollständig lesbar. `installer-ctime-fix/gui-installer-negative-cases.json`
und seine drei Zustandsvergleiche belegen dies. Administrator-Abbruch und
tatsächliche App Translocation sind dadurch nicht belegt. Die normale
Installation unter PID 34713 wartet auf lokale macOS-Authentifizierung.
Ihr positiver Abschluss, letzter installierter Komplextest und öffentliche
Freigabe stehen noch aus. Einzelbelege und Grenzen stehen im
[aktuellen macOS-Prüfbericht](KEEP_VAULT_5_0_2_MACOS_AUDIT.md).

## Zweck des ursprünglichen Rechecks

GPT-5.6-sol soll den vollständigen v12-Quellbaum unabhängig erneut lesen und
die nachstehenden Punkte mit reproduzierbaren Ergebnissen bestätigen. Ein
Roundtrip allein gilt bei kryptografischen Änderungen nicht als unabhängiger
Nachweis. Für jede primitive Änderung ist ein Known-Answer-Test gegen eine
zweite Implementierung erforderlich.

## Verbindliche Nachprüfungen

| Bereich | Nachweis, der erneut erbracht werden muss | Status dieses Laufs |
| --- | --- | --- |
| v12-Grenze | Kein v11-Reader, keine Migration, keine alten Magic-/KDF-/KPAR2-Pfade; alle Parser lehnen ältere Versionen ab | bestätigt durch `spec.no-legacy-source` und `spec.normative-v12-docs` |
| Kalyna | Lizenzierte Quelle, v12-Exportliste, skalare und parallele KATs, In-place-/Null-Längen-/Counter-Grenzen, Create- und Join-Fehler-KAT | Native Slice-KATs für arm64 und x86_64 bestanden; deterministischer Create-Failure-KAT bleibt offen |
| Threefish | Referenzvektoren, paralleler CTR gegen skalare Gegenprobe, Completion-Lebensdauer bei Create-/Join-Fehler, Windows-Pfad | Native Slice-KATs sowie Create-/Join-Abdeckung vorhanden; ASan/TSan-Lauf bleibt offen |
| Argon2id | PHC- und unabhängiger Bouncy-Castle-Vergleich; unveränderlich `t=4`, `p=4`; alle Worker bei Create-/Join-Fehler sicher abgeschlossen | Lifecycle-Fix kompiliert und Low-Memory-KAT bestanden; deterministischer Fault-Injection-KAT bleibt offen |
| Poly1305 | RFC-8439-KAT, paralleler und serieller Bytevergleich inklusive Tail, Overflow- und Fehlerpfade, kein Puffer-Reuse vor Worker-Ende | Native parallele KATs einschließlich 256-MiB-Lauf bestanden; frischer vertrauenswürdiger Release-Sidecar-Lauf bleibt offen |
| Containerpipeline | Archivieren, Kompression, Verschlüsseln, Entschlüsseln und Entpacken bounded und parallel; Authentifizierung vor Klartextausgabe | Implementierung und Worker-Gleichheit vorhanden; vollständige Release-Suite durch fehlenden Root-Anker bzw. vertrauenswürdige Testartefakte blockiert |
| Integrität/KPAR2 | SHA3-/Skein-Blätter, KPAR2-v4 RS(20,3), duale Authentifizierung und deterministische Fehleraggregation parallel geprüft | KPAR2-v4-KATs bestanden; vollständige Container-/Recovery-Suite wegen derselben Artefakt- und Root-Anker-Gates offen |
| ZPAQ | v12-Streaming, `--`-Argumentgrenze, FD-/Umgebungsvererbung, Seatbelt/Containment, kill/join und 6-GiB-Normrahmen | Prozess-Ressourcen-, CPU- und Stall-Gate bestanden; Root-Anker und vollständige Matrix bleiben offen |
| Source-TOCTOU | Build/Packaging aus einem privilegiert verankerten, unveränderlichen Commit-/Tree-Snapshot; kein Live-Repo-Fallback; ABA-, Detach- und Mount-Swap-Negativtests | release-blockierend, noch offen |
| Secrets | Keine privaten Schlüssel, Passwörter oder Keychain-Ausgaben in argv, Logs, temporären Artefakten oder Git; nur Keychain-Prompts mit „Erlauben“ | USB-Public-Key-Abgleich und PFX-Dateiprüfung bestanden; Schutz-ACLs verifiziert; keine Geheimnisse protokolliert |
| Toolchain | Gepinnter .NET-10-SDK, Locked Restore, native Compiler-/Linkerflags, Lizenz- und Provenienzmanifest unverändert zum geprüften Commit | Native arm64/x86_64/Universal-Builds, Locked-Restore-Gate und Toolpfad-Selbsttests bestanden |
| Release-Verifier | Jede EXE, DLL, jedes Manifest, ZIP und Companion-Artefakt in einem frischen Zielverzeichnis verifiziert; absichtliche Mutation wird blockiert | Nichtöffentlich vorbereitet; vollständiger vertrauenswürdiger App-/Sidecar-Lauf bleibt wegen fehlendem Root-Anker offen |

## Ausführungsprotokoll 2026-09-02

Der Lauf fand auf echter Apple-Hardware statt. Hostdaten: Apple-Silicon
`arm64`, macOS `26.6.2` (Build `25G83`), Xcode `26.6` (Build `17F113`),
Clang `21.0.0`, zehn logische Prozessoren. Der geprüfte Ausgangsstand war
`master` bei Commit `26cd3fba4bcb0b233d65009377a9e350c50663f6`; die Änderungen
dieses Laufs waren zu diesem Zeitpunkt noch nicht committed.

Nach Abschluss der Prüfungen wurde der geprüfte v12-Stand als Commit
`0dd3acc0e8e4254d345bfd9d9a6b487f8a0dbc19` mit Tree-Hash
`404c2fa03983db73b69ccecc8bf534befa84ee6d` auf `origin/master` gepusht.

Ausgeführte Gates und Ergebnisse:

| Kommando bzw. Test-ID | Ergebnis | Artefakt oder Hinweis |
| --- | --- | --- |
| `./tools/Build-Native-macOS.sh` | PASS | arm64, x86_64 und Universal; native Mach-O-Ausgaben erzeugt |
| `NativeKats.c` je Slice | PASS | `Native per-slice cryptographic KATs passed` für arm64 und x86_64 |
| `./tools/Build-Native-macOS.sh --verify-sources` | PASS | Manifest mit 431 Quellen |
| `./tools/Build-Native-macOS.sh --self-test-atomic-publish` | PASS | Vorab-Fehler, Hard-Link-Schutz und atomarer Austausch bestanden |
| `./tools/Build-KeepVault-macOS.sh --tool-path-self-test` | PASS | Release-Toolpfade verifiziert |
| `./tools/Provision-VerifiedDotnet-macOS.sh --tool-path-self-test` | PASS | Gepinnter .NET-10-Pfad verifiziert (`10.0.400` im Provisioner) |
| `./tools/Stage-TestNatives-macOS.sh --tool-path-self-test` | PASS | Test-Native-Stagingpfade verifiziert |
| `./tools/Protect-HybridKeys-macOS.sh --verify-only` | PASS | beide Keychain-ACLs und getrennte Wrapping-Rollen verifiziert |
| `spec.no-legacy-source` | PASS | `/private/tmp/keep-vault-test-runner.S8hQD8lG/artifacts/bin/KeepVaultMac.Tests/release_osx-arm64/.test-results.json` |
| `spec.normative-v12-docs` | PASS | `/private/tmp/keep-vault-test-runner.aaYaKEDN/artifacts/bin/KeepVaultMac.Tests/release_osx-arm64/.test-results.json` |
| `packaging.keychain-secret-not-in-argv` | PASS | `/private/tmp/keep-vault-test-runner.B08SE34D/artifacts/bin/KeepVaultMac.Tests/release_osx-arm64/.test-results.json` |
| `zpaq.process-resource-limits` | PASS | CPU-, RSS-, Wall-Time-, Prozesszahl- und Stall-Gates bestanden |
| `./tools/Test-KeepVault.sh --full --no-smoke --parallel 2` | 51 PASS, 50 FAIL | Ergebnisbaum `/private/tmp/keep-vault-test-runner.Etk0mTNo/artifacts/bin/KeepVaultMac.Tests/release_osx-arm64/.test-results.json`; die 50 Fehler sind fehlende signierte Sidecars, fehlender finaler `dist`-Stand oder der absichtlich erforderliche root-eigene ZPAQ-v12-Anker, nicht stillschweigend übersprungene Tests |

Der vollständige Ergebnisbaum des letzten Laufs wurde nach der Auswertung
recoverbar unter
`/Users/michael/.Trash/keepvault-full-run.LCaUD8/keep-vault-test-runner.Etk0mTNo`
archiviert. Es wurde nichts endgültig gelöscht.

Der USB-Stick wurde ausschließlich für die direkte, speicherinterne
Authentifizierung verwendet. Der ML-DSA-Public-Key-Abgleich war erfolgreich
(`usb_mldsa_public_match=true`), die PFX-Datei war eine reguläre geschützte
Datei. Private Schlüssel, Passwörter und Keychain-Inhalte wurden weder
ausgegeben noch in das Repository übernommen. Die absichtlich prompt-only
gesetzten Keychain-ACLs wurden nicht abgeschwächt.

Die Performance- und End-to-End-Gates `performance.cipher-suites`,
`performance.paranoia-256mib-e2e` und `performance.paranoia-complex-tree-e2e`
konnten in diesem nichtöffentlichen Lauf nicht als Release-Nachweis ausgeführt
werden: Vor ihrem Start verweigert die Testumgebung die untrusted oder nicht
sidecar-signierten nativen Bibliotheken und den fehlenden root-eigenen ZPAQ-
Anker. Es werden deshalb keine Geschwindigkeitswerte als gemessen ausgegeben.

## Pflichtläufe auf echter Apple-Hardware

Die Ergebnisse sind mit Host, macOS-Version, Architektur, Commit-/Tree-Hash,
Toolchain, Workerlimit, Dauer und Exit-Code zu protokollieren:

1. Alle Smoke- und Comprehensive-Gruppen.
2. Alle zehn Cipher-/Kaskaden-Messungen mit denselben Eingabedaten und
   reproduzierbaren Warm-up-/Medianregeln.
3. Der exakte 256-MiB-Lauf mit Kompressionsstufe 5, Paranoia und vollständigem
   Argon2id.
4. Als letzter funktionaler Lauf ein komplizierter Ordnerbaum mit leeren,
   sehr kleinen, großen, zufälligen und stark komprimierbaren Dateien,
   Unicode-Namen und tiefen Verzeichnissen. Danach keine weitere funktionale
   Mutation des geprüften Quellstands vor dem Commit.

## Sicherheitsentscheidung

Solange der Build nicht aus einem unveränderlichen, gegen denselben Benutzer
verankerten Source-Snapshot erfolgt, darf GPT-5.6-sol keinen öffentlichen
Release als reproduzierbar oder sicher ausgeben. Gleiches gilt für einen
offenen Argon2-Worker-Lifecycle-Fehler oder fehlende Poly1305-KATs. Die
Entscheidung muss als „Release blockiert“ mit Fundstelle und Testkommando
notiert werden, nicht durch eine abgeschwächte Testauswahl umgangen werden.

## Abschlussformat

Das Recheck-Ergebnis enthält:

* geprüften Commit und Tree-Hash,
* jede ausgeführte Test-ID mit Ergebnis und Artefaktpfad,
* alle offenen Befunde mit Priorität, Datei/Zeile und reproduzierbarem
  Kommando,
* eine klare Entscheidung `bereit für separates Release-Gate` oder
  `Release blockiert`.

Private Schlüssel und App-spezifische Passwörter gehören nicht in dieses
Protokoll.
