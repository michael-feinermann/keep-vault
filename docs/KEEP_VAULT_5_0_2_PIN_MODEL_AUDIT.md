# Keep Vault 5.0.2: PIN-Modell und Annahmemenge

Stand: 6. September 2026. Modellversion `keep-vault-pin-patterns-2026-09-v1`. Diese Regeln gelten für die Archivierung. Sie liefern keine empirischen Rateversuche, keine Entropiezusage für menschliche Auswahl und keinen zusätzlichen Bit-Schwellenwert.

Die technische macOS-Abnahme des endgültigen 5.0.2-Kandidaten ist am
8. September 2026 abgeschlossen. Der [macOS-Prüfbericht](KEEP_VAULT_5_0_2_MACOS_AUDIT.md)
trennt Quellen-/Policybelege, tatsächlich ausgeführte GUI-Prüfungen, den
Offline-Core-Lauf und den letzten installierten Komplextest von der
anschließenden öffentlichen Veröffentlichung.

## Regeln und technische Grenze

Alle bisherigen Regeln einschließlich der vollständigen Sperrliste bleiben unverändert. Neue harte Regeln betreffen die vollständige PIN als wörtlichen Teilstring des unveränderten Passworts, die vier heutigen Datumsformate sowie vollständige plausible Daten. Fehlende oder syntaktisch noch unvollständige Eingaben bestätigen kein Paar. Das lokale Tagesdatum wird beim endgültigen Aufruf erneut erfasst; der Testzugang erlaubt ein festes Datum ohne globale Uhränderung.

Das zusätzliche Modell erkennt vollständige zyklische Ziffernfolgen, größere Wiederholungsperioden, periodische Konstruktionen mit abweichender letzter Ziffer, Palindrome, Jahresverkettungen und Datum/Jahr-Verbindungen. Die kuratierte Konstantenliste enthält die ersten 16 Ziffern einschließlich Ganzzahlteil von pi, e, goldenem Schnitt und Quadratwurzel aus 2. Telefonanordnung und Ziffernblock haben getrennte Nullpositionen; nur vollständige Nachbarwege mit höchstens zwei Richtungswechseln treffen. Beliebige Nachbarwege oder einzelne Datumssegmente allein sperren keine lange PIN. Dies sind dokumentierte Produktheuristiken, keine kalibrierten Angriffsränge.

Das Datumsmodell prüft gültige Kalendertage einschließlich Schaltjahren in `DDMMYY`, `MMDDYY`, `YYMMDD`, `DDMMYYYY`, `MMDDYYYY` und `YYYYMMDD`. Der feste Modellbereich ist 1900 bis 2056. Für zweistellige Jahre werden beide Jahrhunderte 1900 und 2000 innerhalb dieses Bereichs geprüft. Mehrdeutige Werte gelten als Datum, sobald eine dieser Interpretationen gültig ist. Die unabhängige heutige Datumssperre verwendet genau `DDMMYY`, `DDMMYYYY`, `MMDDYY`, `MMDDYYYY`, ausschließlich als Gesamtwert.

Die KDF-Eingabeprüfung erlaubt bis zu 1.048.576 UTF-16-Codeeinheiten je Geheimnis. Sie fordert keine bisherigen oder neuen Auswahlregeln. Die PIN bleibt ASCII-Ziffernfolge; beim Passwort werden keine Normalisierung oder neuen Unicode-Anforderungen eingeführt. Leere Zeichenfolgen sind technisch darstellbar und bleiben auf dieser Ebene zulässig. `ValidatePinSyntax` bleibt ausschließlich die historische Syntaxprüfung für die Auswahl neuer PINs. Die v12-KDF-Datei ist unverändert.

## Reproduzierbare Annahmemenge

Gemessen mit SDK 10.0.400, festem Datum 2026-09-06 und einem unveränderten Passwort ohne Ziffern. Daher löst die Paarregel in dieser Mengenmessung keinen Treffer aus. Sechs Stellen wurden vollständig einschließlich führender Nullen enumeriert. Für jede Länge von 7 bis 16 wurden 10.000 numerische Werte mit `Random(0x5020609)` in festgelegter Reihenfolge gezogen. Der alte Prüfer wurde aus dem tatsächlichen Quellbestand unverändert übernommen. Kein im alten Prüfer abgelehnter Wert wurde im gesamten erfassten Korpus neu angenommen.

| Stellen | Umfang | Angenommen neu | Angenommen vorher | Anteil neu | 95%-Intervall |
|---:|---:|---:|---:|---:|---:|
| 6 | 1.000.000 | 732.438 | 803.723 | 73.2438 % | exakt |
| 7 | 10.000 | 8.064 | 8.070 | 80.6400 % | 79.85 bis 81.40 % |
| 8 | 10.000 | 7.835 | 7.853 | 78.3500 % | 77.53 bis 79.15 % |
| 9 | 10.000 | 7.539 | 7.541 | 75.3900 % | 74.54 bis 76.22 % |
| 10 | 10.000 | 7.191 | 7.208 | 71.9100 % | 71.02 bis 72.78 % |
| 11 | 10.000 | 6.933 | 6.933 | 69.3300 % | 68.42 bis 70.23 % |
| 12 | 10.000 | 6.761 | 6.761 | 67.6100 % | 66.69 bis 68.52 % |
| 13 | 10.000 | 6.435 | 6.435 | 64.3500 % | 63.41 bis 65.28 % |
| 14 | 10.000 | 6.224 | 6.224 | 62.2400 % | 61.29 bis 63.19 % |
| 15 | 10.000 | 5.913 | 5.913 | 59.1300 % | 58.16 bis 60.09 % |
| 16 | 10.000 | 5.671 | 5.671 | 56.7100 % | 55.74 bis 57.68 % |

Die sechsstellige Diversitätsregel allein lässt exakt 932.400 Werte zu. Unter allen bisherigen Regeln bleiben 803.723 Werte; unter dem erweiterten Modell bleiben 732.438. Die zusätzlichen Regeln schließen somit weitere 71.285 vollständige Werte aus.

Die Intervalle für die Stichproben sind Wilson-Intervalle mit z = 1,959963984540054 unter einem Modell gleichverteilter numerischer Ziehungen. Sie beschreiben ausschließlich die geschätzte Größe der angenommenen Zahlenmenge. Der festgelegte Pseudozufallskorpus bildet keine menschliche Auswahlverteilung ab; aus Annahmequote, Länge oder fehlendem Mustertreffer folgt keine menschliche Guessability. Seltene zusätzliche Muster können in den langen Stichproben ausbleiben; gezielte Testvektoren prüfen sie separat.

## Nachweise und Grenzen

Die drei reinen Policy-Testgruppen bestehen im isolierten Harness: wörtliche Paarregel und offene Paarprüfung, lokale Daten/Zeitzonen/Mitternacht, Muster und monotone Erhaltung alter Ablehnungen. Neun bisherige unregelmäßige positive PIN-Fixtures bestehen ohne Ausnahmebehandlung. Die getrennte technische Eingabeprüfung wird bis einschließlich der Obergrenze von 1.048.576 UTF-16-Codeeinheiten geprüft. Eine vierte integrierte Testgruppe enthält sechs unabhängig mit Python hashlib.sha3_512 berechnete v12-Bytevektoren für leere, kurze und über den alten Grenzen liegende Eingaben, führende Nullen und verschiedene Unicode-Darstellungen. Diese vier Gruppen bestanden bereits im früheren integrierten 5.0.2-Wiederholungslauf mit 152/152 erfolgreichen Volltestgruppen; der später abgeschlossene notarisierte Developer-ID-Kandidat besteht mit 153/153. Die historischen und aktuellen Ergebnisse sind im [macOS-Prüfbericht](KEEP_VAULT_5_0_2_MACOS_AUDIT.md) getrennt belegt.

Der gezielte abschließende Recheck bestätigt zusätzlich: Fehlende, zu kurze, zu lange oder nicht aus ASCII-Ziffern bestehende PINs melden keine abgeschlossene Paarprüfung. Bei vorhandenem Passwort entsteht dabei keine irreführende Meldung über ein fehlendes Passwort. Eine syntaktisch vollständige, qualitativ abgelehnte PIN bleibt getrennt davon ein vollständig geprüftes Paar. Diese Status- und Testpräzisierung verändert die zuvor enumerierte Annahmemenge nicht.

Ein unabhängiger Quellvergleich gegen den abgeschlossenen 5.0.1-Stand bestätigt die identische bisherige PIN-Analyse, Passwort-Auswahlvalidierung und Entropieschätzung. Nach Entfernen des zusätzlichen Modellaufrufs und seiner Ergebnisfelder ist auch die bisherige Passwortanalyse identisch. `V12MasterKdf`, `RecoveryService`, `SuiteKeySchedule`, `KdfPrimitives`, `KdfSalts` und `EncryptionSuite` sind bytegleich. Im macOS-Entpack-, List- und Recovery-Pfad sind ausschließlich die technischen Credential-Validatoren verdrahtet; die Paar- und Qualitätsprüfung steht am Core-Erstellungsstart. Dieser statische Befund belegt die Trennung im Quellcode, ersetzt aber nicht den integrierten Nachweis mit unabhängigen KDF-Vektoren und statischen v12-Archiven. Die spätere Windows-UI-Portierung ist ausdrücklich getrennt dokumentiert.

Der ergänzende lesende Fixture-Review bestätigt alle sechs Archiv-/Sidecar-Hashes, den Manifestpin und die 13 Provenienzdateihashes. Die dokumentierten drei entfernten Auswahlprüfungen reproduzieren aus Commit `e52159e7a569a8b77fe7732006388c4401c4009f` exakt die privaten Builder-Quellhashes; die beiden Snapshots der 87 Build-Eingaben sind identisch. Alle sechs eingefrorenen SHA3-Credential-Vektoren stimmen zusätzlich mit einer eigenen LE-Längenrahmung und Python `hashlib.sha3_512` überein. Der Builder verwendet für SHA3 dieselbe Digestbibliothek wie die Produktion, aber eigene Rahmung; die Python-Gegenprobe ist deshalb ein ergänzender unabhängiger Digestnachweis. Das Skein-Orakel verwendet Bouncy Castle gegenüber dem nativen macOS-Pfad. Die vorgesehenen integrierten Read-Tests prüfen einen wirksamen Modellzugriffsfehler, fehlende Klartextausgabe bei Manipulation sowie exakte KPAR2-Rekonstruktion bei unverändert beschädigter Quelle. Diese Tests wurden in diesem lesenden Review nicht ausgeführt; die Fixtures stammen aus einem privaten 5.0.1-Quellsnapshot und belegen für sich keinen bestandenen 5.0.2-Read- oder Release-Lauf.

Der isolierte Harness enthält die unveränderte neue Policy-Datei und einen automatisch extrahierten PIN-Abschnitt der aktuellen ContainerKeyDerivation.cs. Die KDF-Bytevektoren werden im vollständigen Testprojekt gegen die echte Implementierung ausgeführt. Der isolierte Lauf ersetzt keine Prüfung von GUI, finaler Core-Verdrahtung, Entpackkompatibilität oder signiertem Release.

Lokale Evidenz: `build/audit/5.0.2-20260906/pin-policy/` mit `acceptance.json`, Quellhashes, Erhaltungsprüfung, extrahiertem Quellcode und ausführbarem Konsolenprojekt. Testquellen: `KeepVaultMac.Tests/PinCreationPolicyTests.cs`. Es wurde kein HIBP-Bestand importiert; die kleine bestehende numerische Sperrliste und die dokumentierten Muster dürfen nicht als umfassende Leak-Abdeckung bezeichnet werden.


Ergänzung nach dem integrierten Wiederholungslauf: Alle acht Credential-Kompatibilitätsgruppen, einschließlich der sechs eingefrorenen Archive, bestehen. Damit sind die oben zunächst nur beschriebenen List-, Extraktions-, Authentifizierungs- und Reparatureigenschaften unter dem wirksamen Modellzugriffswächter tatsächlich geprüft. Der historische Fixture-Restore enthielt eine Locked-Mode überschreibende Option; ein zusätzlich archivierter strikter Restore mit `RestoreForceEvaluate=false` besteht mit unveränderten Lockdateien und 87 Quell-/Projekteingaben.

Der endgültige Developer-ID-Kandidat besteht inzwischen mit 153 von 153
Testgruppen in 405,5 Sekunden, ohne Fehler oder blockierte Gruppen.
`final-developer-id-results/001-test-results.json` im Auditverzeichnis hat
SHA-256 `8ec5a2d0a5b28c5b40f3e0ba7054cea27c46bb99c4b25a1a3e26c3e44c1db93d`.
Die zusätzlichen einzelnen Releaseprüfungen, die Performance-Matrix in
195,0 Sekunden, der 256-MiB-Paranoia-Lauf in 75,4 Sekunden und der komplexe
Paranoia-Lauf mit Reparatur in 73,7 Sekunden bestehen ebenfalls. Der lokale
Releasebuild vom 7. September 2026 ist abgeschlossen.

Die tatsächliche DE/EN-GUI-Prüfung des vorherigen Development-Kandidaten
bestätigt Versionsanzeige, PIN-Hinweis 6 bis 16, alle vier Pfadplatzhalter
sowie den Abschlussstatus nach Löschung eigener Testkopien. Die
Apple-Notarisierung des endgültigen Kandidaten ist mit Job
`672ab61e-4909-4fe9-a9e2-1685ea774e09`, `Accepted`, `statusCode = 0` und
`issues = null` belegt. Alle drei Apps bestehen Stapling, Ticketvalidierung
und Gatekeeper. Der tatsächliche native Installer-GUI-Lauf, der letzte
komplexe Lauf nach finaler Installation und die öffentliche stabile Freigabe
bleiben bis zu ihren eigenen Nachweisen offen. Diese macOS-Ergebnisse
belegen keine Windows-GUI-Prüfung und keinen Test auf separater Intel-Hardware.

Im anschließenden tatsächlichen Installer-GUI-Test am 8. September 2026
scheiterte der Installer an der Codesign-Argumentform: Getrenntes `-R` erwartet
eine Datei, während Anforderungstext als `-R=<Anforderungstext>` übergeben
werden muss. Die Installation wurde abgebrochen. Der zuvor getestete und
notarisierte Kandidat ist dadurch überholt; seine Ergebnisse sind keine
Freigabe für das zu korrigierende Artefakt. Neue Signierung, Notarisierung,
vollständige Releaseprüfungen und der tatsächliche Installer-GUI-Nachtest
wurden deshalb für den Korrekturzyklus erforderlich; dessen aktueller Stand
folgt unten. Die dokumentierten Passwort-/PIN-Auswahlregeln werden durch
diesen Installerbefund nicht geändert.

Die Installerkorrekturen sind inzwischen umgesetzt und auf neun Quell-/Test-/
Buildpfade begrenzt. Sie betreffen das Codesign-Textargument, die kontonamen-
gebundene ACL-Vergabe, ihre Reihenfolge vor nativer Ausführung und die
Signaturprüfung direkt aus gehaltenen Bytes statt über `/dev/fd`. Die
Passwort-/PIN-Regeln und Archivkryptografie bleiben unverändert; die gemeinsame
hybride Signatur-API erhält ihre bisherigen Prüfungen. Echte Codesign-/ACL-
Gegenproben, 15 Signaturregressionen und neue NativeAOT-Verifier gegen dieselbe
unveränderte alte Root-/ACL-Zwischenkopie bestehen auf ARM64 und unter Rosetta.
Dies sind Komponentenbelege, keine vollständige neue Installerabnahme.

Der neue Developer-ID-Build läuft mit 1.320 eingefrorenen Quelleingaben in
`build/audit/5.0.2-20260908/corrected-developer-id-build.log`. Die korrigierte
Einreichung ist inzwischen von Apple unter Job
`c4d7f3a5-3a54-4954-af83-d003bc194824` mit `Accepted`, `statusCode = 0`
und `issues = null` angenommen. Der originale Einreichungs-ZIP-Hash lautet
`72de4c27b7271fa264447d535826afb425f5c7ce0c5a07538eb25113478ac76b`.
`source-after-apple.json` bestätigt alle 1.320 Quelleingaben unverändert.
Stapling, Ticketvalidierung, Gatekeeper und endgültiger Paketvergleich des
korrigierten Kandidaten bestehen inzwischen. Das neue ZIP hat 43.681.703
Bytes und SHA-256
`820863042b5cfacb6643b1696c8fbf8412c9529d82d921d3bb7174db3dedf81d`.
Der neue vollständige Testlauf besteht mit 153 von 153 Gruppen in
410,1 Sekunden, ohne Fehler oder blockierte Gruppen; summierte Gruppenzeit
932,8 Sekunden. `corrected-developer-id-results-resumed/001-test-results.json`
hat SHA-256 `c9ddc29c752b5c451fd6e1a9d4c30770a368b248463ddcd6c157f34746f58147`.
Alle zusätzlichen einzelnen Releaseprüfungen und manuellen Produktions-
messungen sind inzwischen bestanden. Die Testzeiten betragen 194,6 Sekunden
für die Performance-Matrix, 81,6 Sekunden für 256-MiB-Paranoia und
78,3 Sekunden für den komplexen Paranoia-Baum mit KPAR2-Reparatur. Dieser
Lauf umfasst 18 Dateien, 20 Verzeichnisse und 221.327.790 Eingabebytes und
repariert eine beschädigte Einheit. Der korrigierte Releasebuild ist mit
Exitcode 0 abgeschlossen, alle 20 Ergebnis-/Zeitdateien sind an den Index
gebunden. `source-after-build.json` bestätigt 1.320 unveränderte Quelleingaben;
die sechs lokal bereitgestellten Assets sind bytegleich mit den gesicherten
endgültigen Dateien. Die tatsächlichen GUI-Gegenproben für Startdialog-
Abbruch, unvollständiges Paket und Ordnerauswahl-Abbruch sind inzwischen
bestanden. Alle 129 geprüften Einträge der installierten Apps, Sidecars und
Root-Anker bleiben nach jedem Fall byte-, metadaten- und inodegleich;
atime ist ausgenommen. `gui-installer-negative-cases.json` und die drei
Nachvergleiche belegen dies. Ein Abbruch des macOS-Administratordialogs oder
tatsächliche App Translocation sind dadurch nicht belegt. Die normale
Installation des vollständigen Kits unter PID 9073 scheiterte anschließend
an einer falschen Identitätsablehnung. Die folgende Korrektur benötigt einen
neuen Build und eigene Freigabenachweise. Alte PASS-Ergebnisse werden nicht
auf den erneut geänderten Kandidaten übertragen.

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
