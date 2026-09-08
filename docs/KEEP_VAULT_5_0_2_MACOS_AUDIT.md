# Keep Vault 5.0.2: macOS-Prüfbericht

Technische Abnahme am 8. September 2026 abgeschlossen: Keep Vault 5.0.2,
Build 13 ist im dokumentierten Prüfumfang zur Veröffentlichung vorbereitet.
Container v12 und KPAR2 v4 bleiben unverändert. Maßgeblich ist ausschließlich
der endgültige Kandidat unter `build/audit/5.0.2-20260908/installer-ctime-fix/`
mit Apple-Job `de8618c3-7404-4b7f-b35e-591fd5fd92c2`, Status `Accepted`.
Alle drei Apps bestehen Developer-ID-, Stapling- und Gatekeeper-Prüfungen.
Das endgültige ZIP hat SHA-256
`c4f069e0091259a0c6a1f76d880879facec689625b059e5d5659b70e5af112e1`.
Alle sechs Veröffentlichungsdateien und 38 ursprünglichen Slices sind
unabhängig gebunden; 1.320 Quelleingaben bleiben bis nach dem letzten
funktionalen Test unverändert.

153 von 153 Volltestgruppen sowie sechs zusätzliche Einzelprüfungen und
drei Produktionsmessungen bestehen. Beide tatsächlichen GUI-Installationswege,
die abschließende DE/EN-Oberfläche und die installierten App-/Sidecar-/Ankerbytes
sind geprüft. Physisch installiert und registriert ist ausschließlich die
kanonische Haupt-App `/Applications/Keep Vault.app` in Version 5.0.2, Build 13.
Der vollständige frische Offline-Produktions-Core-Lauf besteht in 79,562 Sekunden;
die echten GUI-Nachweise sind davon getrennt. Als letzte funktionale Ausführung
besteht der unveränderte reguläre Teststarter gegen die finale Installation
mit komplexem Paranoia-/KPAR2-Rundlauf in 70,532 Sekunden. Die freigegebene
Schlüsselzettelgestaltung, Papierdruck, QR-Kopie sowie Original- und
kryptografische Löschung sind im jeweiligen tatsächlichen Prüfumfang belegt.

Dieser Bericht hält die technische Abnahme vor Commit, Tag und GitHub-Upload
fest. Er behauptet keine bereits erfolgte öffentliche Veröffentlichung.
Vorgesehen ist das stabile Release
[v5.0.2](https://github.com/michael-feinermann/keep-vault/releases/tag/v5.0.2)
mit genau den sechs geprüften Dateien; öffentliche Sichtbarkeit, Tagzuordnung
und Uploadbytes müssen anschließend tatsächlich bestätigt werden.
Die technisch zuvor abgeschlossene Version 5.0.1 bleibt auf Commit
`e52159e7a569a8b77fe7732006388c4401c4009f` und Tag `v5.0.1` erhalten;
ihr GitHub-Eintrag bleibt ein Entwurf. Ihr [Prüfprotokoll](KEEP_VAULT_5_0_1_MACOS_AUDIT_PROGRESS.md)
ist vom neuen Release getrennt.

Die folgenden Entwicklungs- und Zwischenstände bleiben historische Belege.
Frühere Kandidaten, Fehler und damalige offene Gates werden dadurch nicht
nachträglich für bestanden erklärt. Der abschließende Status steht im
Abnahmetableau und in den letzten Abschnitten dieses Berichts.

## Prüfgegenstand

- Versionsanzeige unter dem deutschen und englischen Untertitel.
- Unveränderte bisherige Passwort-/PIN-Auswahlregeln, ergänzt um lokale
  vollständige Passwortmodelle, PIN-Paarprüfung und Datums-/Zahlenmuster.
- Auswahlprüfungen ausschließlich bei Archivierung; separate technische
  Eingabegrenzen und unveränderte KDF-Bytes beim Entpacken, Auflisten und
  Reparieren.
- Mitgelieferte, gehashte und signierte Modelldaten einschließlich Attribution.
- GUI, bestehende Sicherheitsregressionen, Produktions-KDF, beide Universal-
  Slices, Signaturen, Notarisierung, Installation und Veröffentlichungsartefakte.

Der [Credential-Vertrag](KEEP_VAULT_V12_CREDENTIAL_POLICY.md), die
[macOS-Releaseanforderungen](KEEP_VAULT_V12_MACOS_RELEASE.md) und das
[PIN-Modellprotokoll](KEEP_VAULT_5_0_2_PIN_MODEL_AUDIT.md) beschreiben die
verbindlichen Prüfungen. Die [Modelldokumentation](../KalynaArchiver/Resources/PasswordModel/README.md)
nennt endliche Abdeckung und Grenzen. Modellwerte sind keine gemessene Entropie.

## Bisherige unabhängige Befunde

Der Quellvergleich bestätigt die unveränderten früheren PIN- und
Passwort-Prüfungen nach Abzug der additiven Modellintegration. Die Dateien
`V12MasterKdf`, `RecoveryService`, `SuiteKeySchedule`, `KdfPrimitives`,
`KdfSalts` und `EncryptionSuite` bleiben bytegleich zum abgeschlossenen
5.0.1-Stand. Die Paarprüfung steht am gemeinsamen Erstellungsstart.

Sechs eingefrorene synthetische v12-/KPAR2-Testarchive enthalten leere, kurze,
über den bisherigen Auswahlgrenzen liegende und wegen neuer Regeln abgelehnte
Geheimnisse. Ihre Erzeugung verwendet den dokumentierten 5.0.1-Quellstand mit
ausschließlich drei entfernten Auswahlprüfungen, dem verifizierten SDK,
frischen privaten Paketablagen und unveränderten Produktions-KDF-Parametern.
Der historische Generatoraufruf enthielt allerdings `--force-evaluate`, das
den gesperrten Restore überschreibt. Ein separater strikter Wiederholungsnachweis
ohne diese Option besteht mit beiden unveränderten archivierten Lockdateien
und 87 unveränderten Quell-/Projektdateien; die archivierten Befehle werden nicht
rückwirkend verändert. Datei- und
Provenienz-Hashes sowie sechs separat mit Python SHA3 nachgerechnete
Credential-Werte stimmen. Der inzwischen bestandene integrierte 5.0.2-Lesetest
ist im Wiederholungslauf unten dokumentiert.

Die unabhängige Modellprüfung fand zusätzliche Fälle für BIP39-Abwandlungen
und regelmäßig eingefügte unsichtbare Zeichen. Die Korrekturen und stärkeren
Variantenregressionen wurden in die unten dokumentierten erfolgreichen
integrierten Läufe aufgenommen. Dort bestehen auch die Prüfungen technischer
Fehlermeldungen im Entpackdialog und der Faktorformatmeldungen in beiden Sprachen.

## Erster integrierter Lauf und Korrekturen

Der erste frische Lauf enthielt 152 Gruppen: 144 bestanden, acht fehlgeschlagen,
keine blockiert. Laufzeit 334,3 Sekunden. Der beobachtete Vorher-/Nachher-
Quellenvergleich aller 1.303 erfassten Dateien blieb identisch, einschließlich
der Lockdateien. Dies ist ein Diagnoseergebnis und keine Freigabe.

Die Fehler betreffen die irrtümliche Erfassung privater Auditprojekte im
Buildverzeichnis, eine noch auf Build 12 festgelegte Testassertion und sechs
neue Kompatibilitätsassertionen, die native Dateinamen im falschen Ausgabekanal
suchten. Bei allen sechs Archivfällen war die vorherige direkte Entschlüsselung
bereits bytegenau erfolgreich. Die eigentlichen Listen-, Extraktions- und
Reparaturprüfungen wurden nach Korrektur vollständig und erfolgreich wiederholt,
wie im folgenden Abschnitt dokumentiert.

Die unabhängige Prüfung fand außerdem widersprüchliche Restoreoptionen:
`--force-evaluate` hebt `--locked-mode` auf. Die korrigierten macOS-Test- und
Buildstarter verwenden diese Option nicht, setzen `RestoreForceEvaluate=false`
und kontrollieren unveränderte Lockdateien. Der separat festgestellte veraltete
Verifier-Lock wurde korrigiert: Seine sieben Ziel-/Paketeinträge entsprechen
bei Version, Contenthash und Abhängigkeitskanten dem bereits abgeschlossenen
5.0.1-App-Lock. Alle vier betroffenen Microsoft-Pakete bestehen zusätzlich
die Autoren- und Repository-Signaturprüfung. Der korrigierte Verifier besteht
einen frischen strikten Restore und Releasebuild mit null Warnungen/Fehlern
und 13 unveränderten Eingabedateien. Die eigenständige AOT-Veröffentlichung
und signierte Programmausführung sind damit noch nicht geprüft. Microsoft beschreibt das Verhalten
in [NU1512](https://learn.microsoft.com/en-us/nuget/reference/errors-and-warnings/nu1512).

Die neuen Lock-Prüffunktionen der drei macOS-Starter bestehen zwölf
separate Fälle mit gültigen, veränderten, fehlenden und symbolisch verlinkten
Dateien. Die neue lesbare Modelldatennotiz ist mit 72.883 Bytes und SHA-256
`fcc48f7f9d123570230f6e0fdb45a9e172c9addea17a619081392a3d8ec57ea2`
gebunden. Ihre isolierten Prüffunktionen bestehen sieben Shell- und
25 .NET-Fälle; die signierte App-Prüfung bleibt ein eigener Gate.

## Erfolgreicher integrierter Wiederholungslauf

Mit den korrigierten Quellen besteht der vollständige Lauf auf macOS 26.6.2,
arm64, 10 logischen CPUs und 16 GiB Arbeitsspeicher: 152 von 152 macOS-
Volltestgruppen, null Fehler und null blockierte Tests. Laufzeit 367,7 Sekunden,
Summe der Gruppenlaufzeiten 843,2 Sekunden, Parallelfaktor 2,29. Der frische
Releasebuild meldet null Warnungen/Fehler. Der Starter verwendet effektiv
gesperrten Restore, private SDK-/Paket-/Artefaktverzeichnisse und die zur
installierten vertrauenswürdigen 5.0.1-App gehörenden nativen Komponenten.
Dies ist noch kein Build der signierten 5.0.2-Distributions-App.

Alle vier neuen PIN-/Encoding-, sechs Passwortmodell-, acht Credential-
Kompatibilitätsgruppen und der neue DE/EN-Oberflächengate bestehen.
Die sechs eingefrorenen Archivfälle bestehen einschließlich Auflisten,
Entpacken, Authentifizierung, Manipulationsablehnung ohne Klartextausgabe und
exakter KPAR2-Rekonstruktion bei unverändert beschädigter Quelle. Der wirksame
Modellzugriffswächter meldet in diesen Lesepfaden keine Aufrufe. Die tatsächlichen
Fenster auf dem Desktop, der Offline-Erststart und ein mit menschlicher
Mauseingabe erzeugter neuer Archivrundlauf waren zu diesem Zeitpunkt noch offen.
Die späteren GUI-Ergebnisse und verbleibenden Prüfungen stehen unten.

Die 1.306 erfassten Quell-/Projekt-/Ressourcen-/Testdateien sind vor und nach
dem Wiederholungslauf in Inhalt und Modus identisch. Der Testinventarhash lautet
`d5991f97fe5fbccd2f97cc7c0ffdb3e2fff8a579449a0d0b4d535cbfd5049a76`.
Lokale Belege: `build/audit/5.0.2-20260906/full-repeat.log`,
`full-repeat-results.json`, `full-repeat-timings.json` und
`source-after-full-repeat.json`.

## Signierter Entwicklungsbuild vom 7. September 2026

Nach dem vom Nutzer bestätigten Entsperren besteht der frische Universalbuild
mit den vorhandenen USB-Schlüsseln. Keep Vault und QR-Scanner sind unter
`/Applications` in Version 5.0.2, Build 13 installiert. Dieser Kandidat trägt
eine Apple-Development-Signatur und die vorhandenen hybriden Signaturen;
eine Developer-ID-Notarisierung oder öffentliche Freigabe ist das noch nicht.

Die vollständige Testmenge besteht erneut mit den frisch signierten nativen
Komponenten: 152 von 152 Gruppen, null Fehler, null blockiert, 383,8 Sekunden.
Die 1.306 erfassten Eingabedateien bleiben vor und nach dem Build in Inhalt
und Modus identisch. Die .NET-Kompilierung meldet null Warnungen/Fehler;
die native Crypto++-Kompilierung enthält die bestehende Signvergleichswarnung.

Der separate App-Paar-Audit bestätigt die vollständigen Pfad-, Typ-, Größen-
und Bytevergleiche zwischen Entwicklungsausgabe, installierten Apps und ZIP,
einschließlich zehn äußerer Sidecars und 32 Architektur-CDHashes in 16
Mach-O-Dateien. Beide Apple-Codesign-Prüfungen bestehen. Erweiterte Attribute
und ACLs gehören nicht zu diesem Bytevergleich. Belege liegen unter
`build/audit/5.0.2-20260906/development-build-results-20260907/` und in
`development-installed-pair-audit-20260907.json`.

Die abschließende Developer-ID-Installation, Notarisierung und Bereinigung
der App-Registrierungen blieben zu diesem Zwischenstand offen.

Nach diesem getesteten Build wurden ausschließlich die DE/EN-Druckmeldung in
`KeepVaultMac/Gui/MainWindow.Localization.cs` und der XML-Kommentar in
`KeepVaultMac/Services/KeySheetService.cs` korrigiert. Der Druckpfad übermittelt
bereits zwei getrennte Aufträge mit je zwei Seiten; die alte Meldung behauptete
irrtümlich einen dreiseitigen Auftrag. Die korrigierte Meldung bestätigt nur
die Übermittlung an CUPS, keine abgeschlossene Papierausgabe. Funktionaler
Code blieb unverändert. Der neue Snapshot
`source-after-print-text-fix-20260907.json` enthält weiterhin 1.306 Dateien
und gegenüber dem signierten Entwicklungsstand exakt diese beiden erwarteten
Dateiänderungen bei unveränderten Modi. Diff und Vorher-/Nachher-Hashes stehen
in `print-log-text-fix-20260907.patch` und `print-log-text-fix-20260907.json`.
Zu diesem Zeitpunkt war der Produktquellstand erneut eingefroren. Der nachfolgende
Developer-ID-Build muss die vollständigen Tests mit diesem neuen Stand erneut
bestehen; die bisherigen 152/152 gelten für den zuvor gebauten Development-Stand.

## Laufende GUI-Prüfung und separate Produktionsmessungen

Die installierte App lief für die ersten GUI-Prüfungen unter dem
Prozessprofil `(version 1)(allow default)(deny network*)`. Ein privater
LaunchServices-Prüfstarter erhielt die App-Zuordnung und startete ausschließlich
über feste `exec`-Aufrufe Sandbox, Netzwerkprobe und unveränderten signierten
Original-Launcher. Bootstrap, abgewiesene TCP-Probe und installierter Core
hatten dieselbe PID 53907. Die positive TCP-Kontrolle funktionierte unmittelbar
davor und danach außerhalb des Profils. Laufzeit-Bundle-ID, Bundlepfad und
Corepfad entsprachen anschließend der kanonischen Installation. Dies war eine
prozessbezogene Prüfung; Betriebssystemdienste waren nicht systemweit isoliert.

Ein direkter Start ohne LaunchServices hatte zuvor keine Laufzeit-Bundle-ID.
Ein separater Versuch mit abweichender Prüf-Bundle-ID war für die
GUI-Steuerung ebenfalls nicht nutzbar. Diese Startversuche gelten nicht als
bestandene sichtbare GUI-Prüfungen. Der anschließende sichtbare Start mit PID
53907 verwendete die ursprüngliche Netzsperre ohne UNIX-Socket-Ausnahmen und
veränderte keine signierten App-Dateien. Belege: `offline-ls-canonical-gui-20260907.json` und
`offline-ls-canonical-runtime-20260907.json` im privaten Auditverzeichnis.

Die tatsächlichen Fenster zeigen `Version 5.0.2` unter dem deutschen und
englischen Untertitel. Die Versionszeile und aufklappbare Regelhilfe wurden
auch im verkleinerten Fenster visuell geprüft. Die zusätzliche Bewertung des
synthetischen Wortpassworts `Sommer Wiese Mond Vulkan Fluss Orange Wolke 2026!`
zeigt 120 statt mindestens 128 und lehnt es ab. Die deutsche GUI weist
`07092026` als heutiges lokales Datum zurück und sperrt eine vollständige PIN
im ansonsten akzeptierten Passwort. Eine separate zulässige PIN mit 16
Ziffern wird akzeptiert. Diese Versions-, Hilfe- und Auswahlprüfungen wurden
unter der ersten Netzsperre ausgeführt. Vorbereitende automatisierte
GUI-Ereignisse werden nicht als menschliche Entropie ausgewiesen.

Der anschließende erste GUI-Archivversuch scheiterte an diesem zusätzlichen
äußeren Prüfprofil: `MacZpaqSeatbelt.RunCanaryAsync` konnte im Elternprozess
seinen lokalen TCP-Listener nicht binden (`PermissionDenied`). Es entstand kein
Archiv. Die synthetische Quellfixture mit fünf Dateien, 15 Unterverzeichnissen
und 34.832.501 Bytes blieb unverändert. Die erste Faktorgeneration wurde
verworfen; ihre zuvor durch Keep Vault exportierten Schlüsselzettel bleiben
ausschließlich Belege der PDF-Ausgabe.

Beide PDFs dieser Generation bestehen die unabhängige Prüfung: jeweils zwei
Seiten, alle vier Seiten visuell vollständig und lesbar, vier Faktor-QRs mit
jeweils exakt den eigenen 256 ASCII-Hexzeichen und zwei Rückseiten-QRs mit
exakt der gedruckten Bezugsquellen-URL. Die Faktoren sind getrennt; Passwort
und PIN fehlen in Text, Metadaten und QR-Nutzdaten. Die QR-Decodierung durch
macOS Vision und eine separate Auswertung seiner korrigierten Datenbytes
stimmen einschließlich Terminator und vollständigem Padding ohne Zusatzsegmente
überein. Die PDF-Hashes und Dateiidentitäten blieben unverändert. Belege:
`build/audit/5.0.2-20260906/pdf-review-first-generation/final-qa.json`,
`visual-qa.json` und `independent-qr/independent-qr-verification.json` im selben
Verzeichnis. Dies ist kein Kamera-, Papierdruck- oder erfolgreicher Archivtest.

Der zweite GUI-Versuch verwendete unter PID 54923 das äußere Prüfprofil
`(version 1)(allow default)(deny network-outbound)`. Die Ausgangsverbindung
wurde nachweislich gesperrt, lokale Canary-Listener waren erlaubt. Der
Archivstart scheiterte dennoch vor Ausführung von ZPAQ am inneren
`sandbox-exec`: Exitcode 71, keine Standardausgabe und 53 Bytes Fehlerausgabe.
Eine unabhängige minimale Gegenprobe mit innerem `allow default` und `true`
unter demselben äußeren Profil reproduziert exakt
`sandbox-exec: sandbox_apply: Operation not permitted` mit abschließendem
Zeilenumbruch. Auch Apples SDK-Header `usr/include/sandbox.h`, Dokumentation
zu `sandbox_init`, beschreibt einen Fehler bei bereits bestehender Sandbox.
Belege: `offline-outbound-gui-20260907.json` und
`offline-nested-sandbox-control-20260907.json` im privaten Auditverzeichnis.

Der weitere vollständige GUI-Archivtest erfolgte deshalb nach normalem
App-Start ohne zusätzliches äußeres Seatbelt-Profil. Die produktinterne
ZPAQ-Sandbox bleibt unverändert und erforderlich. Ein vollständiger
Archivrundlauf unter der äußeren Netzsperre ist nicht nachgewiesen; die bereits
bestandenen Offline-Prüfungen belegen die oben genannten GUI-Auswahlprüfungen.

In der realen GUI bestand zunächst das Entpacken der eingefrorenen
Kompatibilitätsfixture mit leerem Passwort und leerer PIN. Der Erfolgsdialog
und die unabhängig geprüfte Datei `canary.txt` mit 81 Bytes und erwarteter
SHA-256 stimmen. Beleg: `gui-compat-empty-20260907.json`. Damit wurde dieser
technisch gültige Lesefall zusätzlich zur integrierten Testgruppe auch über
die Oberfläche ausgeführt.

Für das neue Testarchiv stieg der angezeigte Maus-Sample-Zähler nach der vom
Nutzer ausgeführten Mausbewegung von einem vorbereitenden Sample auf 9.306;
alle neun Pools zeigten jeweils 1.034 Samples. Die Generierung setzte die
Quellpoolanzeige anschließend auf null. Der vorbereitende Ausgangswert wird
nicht als menschliche Eingabe gezählt; Sample-Zahlen sind kein Entropiebeweis.
Diese neue Faktorgeneration wurde nicht als Test-PDF exportiert.

Am 7. September um 10:27:01 Uhr wurde direkt über Keep Vault der getrennte
Druck an `Brother_MFC_L3750CDW_series` übermittelt. CUPS führte die Aufträge
15 und 16 mit jeweils 105.472 Bytes. Die korrekt abgefragte Abschlussliste
enthält beide Aufträge; die Warteschlange hatte anschließend keine offenen
Aufträge. Beleg: `gui-print-cups-completed-20260907.json` mit Exitcode null
und `bothFound = true`. Der frühere, mit einer Auftragsnummer statt dem
Druckernamen fehlgeschlagene `lpstat`-Aufruf bleibt separat in
`gui-print-cups-jobs-20260907.json` dokumentiert und ist kein Erfolgsbeleg.
Der Nutzer bestätigte die tatsächliche Papierausgabe durch konkretes
Layoutfeedback und hielt anschließend den gedruckten Schlüsselzettel A vor
die Kamera. Der Scanner erkannte beide identischen Codes; der tatsächliche
Kopieren-Knopf und das anschließende Einfügen in Keep Vault übertrugen exakt
den erwarteten Faktor mit 256 ASCII-Hexzeichen. Die automatische Leerung der
Zwischenablage wurde danach in der Scanner-Oberfläche bestätigt. Beleg:
`gui-printed-camera-copy-20260907.json`. Ein CUPS-Abschluss allein wäre dafür
kein hinreichender Nachweis gewesen.

Die GUI meldete um 10:27:46 Uhr die erfolgreiche Erstellung von
`archives/paranoia-502-print-test.kzpaq` einschließlich KPAR2, mit Paranoia,
Kompressionsstufe 5, einer 16-stelligen PIN und Passwort-Modellwert 144.
Der integrierte Bytevergleich über fünf Dateien und 34.832.501 Bytes bestand
vor der ausdrücklich gewählten Originallöschung. Der separate Nachcheck
`gui-original-deletion-20260907.json` bestätigt: alle fünf Originaldateien
entfernt, die 15 Verzeichnisse erhalten, deren Pfadmenge unverändert und die
separate Kontrolldatei unverändert. Archiv und KPAR2 sind mit Größe und SHA-256
erfasst; es wurde keine neue Test-PDF angelegt.

Auch das anschließende Entpacken dieses neuen Archivs über die GUI besteht.
Der unabhängige Vergleich `gui-real-tree-comparison-20260907.json` bestätigt
exakt fünf Dateien, 15 Unterverzeichnisse und 34.832.501 Bytes ohne fehlende
oder zusätzliche Pfade. Pfad, Typ, Größe und SHA-256 stimmen mit der
eingefrorenen Referenz überein; zusätzlich bestehen alle fünf direkten
Dateistream-Vergleiche gegen `reference-source`. Leere, versteckte und
Unicode-Pfade sind enthalten, Verknüpfungen und Spezialdateien ausgeschlossen,
die beobachteten Identitäten während der Prüfung unverändert. Erweiterte
Attribute, ACLs und ein privilegiert unveränderlicher Dateibaum sind dadurch
nicht belegt. Dies ist der bestandene GUI-Rundlauf des installierten
Entwicklungskandidaten, noch kein Test des späteren Developer-ID-Artefakts.

Auch die zusätzliche eingefrorene Fixture `oversized-raw.kzpaq` ließ sich
über die GUI entpacken: 262 UTF-16-Codeeinheiten im Passwort einschließlich
führender und abschließender Leerzeichen sowie einer zerlegten Umlautfolge,
dazu eine 17-stellige PIN mit führender Null. Die resultierende `canary.txt`
enthält exakt die erwarteten 81 Bytes. Beleg:
`gui-compat-oversized-raw-20260907.json`. Zusammen mit dem leeren Lesefall
bestätigt das die GUI-Verarbeitung ohne Archivierungs-Auswahlregeln, Kürzen
oder Unicode-Normalisierung für diese konkreten Testeingaben.

Die separate kryptografische Löschung wurde über die GUI ausschließlich an
eigenständigen Kopien des neuen Testcontainers und seiner KPAR2-Datei geprüft.
Ohne Bestätigungsmarkierung, nach Abbrechen der letzten Rückfrage sowie bei
einer Klartextdatei mit `.kzpaq`-Endung blieben alle Kontroll-Hashes unverändert.
Ein Pfadwechsel setzte die Bestätigungsmarkierung zurück. Der bestätigte
positive Lauf entfernte KPAR2 und Container; das Originalpaar, die Klartextprobe
und die außerhalb der Eingabe liegende Kontrolldatei blieben unverändert.
Danach waren Eingabepfad und Bestätigungsmarkierung geleert. Belege:
`gui-crypto-erase-{before,unchecked,cancelled,plain-rejected,success}-20260907.json`.
Diese Prüfung belegt keine Löschung aus Backups, Snapshots oder SSD-Reserven.

Dabei wurde ein GUI-Lokalisierungsfehler gefunden: Analyse-, Ablehnungs- und
Abschlussmeldungen erschienen trotz deutscher Sprachwahl auf Englisch. Die
Oberfläche verwendet jetzt stabile, zweisprachige Statusschlüssel und stellt
den aktuellen Status bei einem Sprachwechsel neu dar. Die Löschentscheidung
und die Reihenfolge in den gemeinsamen Löschdiensten wurden nicht geändert.
Die korrigierte Oberfläche war damit kompiliert. Der spätere sichtbare
Nachtest bestätigt die DE/EN-Analyse- und Ablehnungsanzeigen, fand aber einen
weiteren Fehler beim dauerhaften Erhalt der Abschlussmeldung. Dieser Befund,
seine Korrektur und die getrennten Nachweise stehen im aktuellen Abschnitt
weiter unten.

Nach Abschluss dieses GUI-Zyklus wurde auf Wunsch des Nutzers das Layout der
Schlüsselzettel überarbeitet. Der sichtbare Titel und der PDF-Dokumenttitel
enthalten die tatsächliche App-Version sowie A beziehungsweise B. Drei volle
Schreibzeilen mit 9 mm Abstand und der Hinweis `PIN nicht eintragen` bzw.
`Do not write down the PIN` sind fest reserviert. Faktorgröße 14 Punkt und
beide QR-Symbole mit 132 Punkt bleiben erhalten. Vier echte PDFs aus dem
Produktdienst wurden erzeugt und auf allen acht Seiten visuell geprüft;
der frische, strikt isolierte Build und `keysheet.full-factor-print` bestehen.
Der Quellenvergleich vor und nach dem Build umfasst unverändert 1.306 Dateien.
Belege liegen unter `key-sheet-layout-preview`. Zum Zeitpunkt dieser ersten
Vorschau stand die ausdrücklich verlangte Layoutfreigabe noch aus. Dieser
Zwischenstand war keine Abnahme des endgültigen Developer-ID-Artefakts.
Nach der ersten Vorschau verlangte der Nutzer zusätzlich, die vier
Metadatenbezeichnungen bis einschließlich Doppelpunkt fett zu setzen und die
jeweiligen Werte normal zu belassen, auf Deutsch und Englisch. Diese
Korrektur ist mit getrennter Breitenmessung beider Schriftschnitte umgesetzt.
Die neue tatsächliche PDF-Generation unter `key-sheet-layout-preview/bold-labels`
besteht den strikt isolierten Build und den vollständigen Faktortext-Test;
die 1.306 Quellinputs bleiben während des Builds unverändert. Alle acht neuen
Seiten wurden erneut visuell geprüft. Die unabhängige Prüfung bestätigt alle
16 tatsächlichen Bold-Labelspannen einschließlich Doppelpunkt, normale
Wertspannen und zwölf vollständig dekodierte QR-Rohdaten samt Terminator und
Padding. Der Beleg `independent-bold-qa-02/independent-final-qa.json` bindet
diese Ergebnisse an die vier konkreten PDF-Hashes. Die öffentliche Installationsseite
verweist jetzt auf die Anleitung des jeweiligen Releases und auf die
Faktor-QR-Codes der Schlüsselzettel. Der Nutzer hat genau diese korrigierte
Vorschau inzwischen mit „Sieht gut aus. Setzt das um“ ausdrücklich freigegeben.
Die Zustimmung ist am 7. September 2026 im Abschnitt `approval` von
`user-printed-layout-feedback-20260907.json` dokumentiert und an den Quellhash
`06760cf6c4db0df7a028ef1c408eca0b6e009e458bd705395ab535e7108ded55`
sowie `key-sheet-layout-preview/bold-labels/output/pdf` gebunden. Die früheren
`false`-/`NOT_APPROVED`-Einträge der Datei bleiben historische Zwischenstände.
Die Layoutfreigabe ist damit abgeschlossen. Die gesonderten Ergebnisse von
Tests, Notarisierung und öffentlicher Veröffentlichung werden im aktuellen
Abnahmestand unten geführt.

Drei separate frische Teststarter verwenden die aktuell installierten
signierten nativen Komponenten und bestehen jeweils ohne Fehler:

- Produktions-Worker-Gleichheit aller zehn Suiten: 8,5 Sekunden.
- Primitive und vollständige Container aller zehn Suiten samt
  Referenzvergleich und Pipeline-Skalierung: 184,2 Sekunden.
- 256 MiB, Paranoia, Kompressionsstufe 5 und Produktions-Argon2id: 72,4
  Sekunden Testlauf, 71,843 Sekunden gemessener Ablauf. Archivieren und
  Verschlüsseln, KPAR2-Erstellung und Prüfung sowie Entschlüsseln und
  Entpacken bestehen mit vollständigem Datenvergleich.

Die Ergebnis- und Zeitdateien stehen unter `manual-production-worker-20260907-*`,
`manual-cipher-suites-20260907-*` und `manual-paranoia-256mib-20260907-*` im
privaten Auditverzeichnis. Diese Messungen ersetzen weder die Prüfung des
späteren Developer-ID-Artefakts noch den abschließenden komplexen Ordnerlauf.

## Selbständiger Installationssatz und ergänzende Sicherheitsprüfung

Die vorherige Prüfung fand einen tatsächlichen Paketfehler: Das native ZIP
enthielt nur das App-Paar mit zehn Sidecars, während Archivoperationen den
privilegiert eingerichteten ZPAQ-v12-Anker benötigen. Das bloße Beilegen des
workspaceabhängigen Shellinstallers hätte weiterhin Xcode beziehungsweise
Compiler und SDK auf dem Zielgerät verlangt. Dieser historische Befund bleibt
erhalten; seine Korrektur ist jetzt als Produkt- und Packagingcode umgesetzt.

Das neu gebaute Development-ZIP enthält `Keep Vault Installer.app`. Die App enthält einen
Universal-NativeAOT-Verifier, den vorkompilierten Löschhelfer und durch die
Apple-Bundlesignatur geschützte Installationsskripte. Das feste Paket umfasst
am Wurzelpfad drei Apps, zehn Sidecars des App-Paars, `INSTALLATION.txt` sowie
`installation-manifest.json` mit fünf eigenen Sidecars, insgesamt 20 Einträge.
Die sechs äußeren Releaseassets, ZIP und fünf Signatur-/Hashdateien, bleiben
unverändert im Aufbau. Der operative Paketmodus benötigt keine Zielinstallation
von .NET, SDK, Compiler oder Xcode. Der Paketbau und die NativeAOT-Prüfungen
sind unten belegt. Der erste vollständige Testlauf enthält einen Fehler;
die spätere Wiederholung besteht mit 153 von 153 Gruppen. Der praktische
Installer-Durchlauf ist noch nicht abgenommen.

Das Inventar wird zuerst gegen beide einkompilierten Signaturpins geprüft.
Danach werden die vollständigen Pfade, Typen, Dateigrößen, SHA-256-Werte und
POSIX-Modi sowie Version, Build und Kennung aller drei Apps kontrolliert.
Zusätzliche, fehlende, mehrdeutige, verlinkte oder spezielle Objekte werden
abgewiesen. Nur die sechs separat authentifizierten Manifestdateien stehen
außerhalb ihrer eigenen Inhaltsliste. Nach dem Stapeln und `stapler validate`
aller drei Apps muss das endgültige Inventar erneut erzeugt und hybridsigniert
werden. Das ZIP und seine äußeren Signaturen folgen erst danach.

Die Apple-Systemprüfung `syspolicy_check distribution` ist allein kein
Nachweis intakter lokaler Ticketbytes. Die isolierten Gegenproben unter
`staple-policy-review-p8s9x5i9` akzeptierten damit teilweise beschädigte oder
fremde vorhandene Tickets, die `stapler validate` zurückwies. Deshalb kombiniert
der Zieladapter die aktuelle Apple-Verteilungsrichtlinie mit der exakten
Ticketbindung: `Contents/CodeResources` der gestagten oder installierten App
muss bytegleich zum endgültigen signierten Inventar sein. Die vollständige
Inventar- und Objektprüfung umschließt diesen Vergleich. Eine solche
Kombination wird nicht als Gleichwertigkeit von `syspolicy_check` und
`stapler validate` ausgegeben.

Der native Einstieg authentifiziert den tatsächlich laufenden Installer und
bindet dessen aktiven CDHash an die Kopie. Eine separate Apple-Prüfung umfasst
alle Universal-Slices. Vor Skript- oder Verifierausführung wird ausschließlich
das feste Paket in ein privates root-eigenes Verzeichnis kopiert; fremde ACLs
werden entfernt, Links und unsichere Typen beziehungsweise Modi abgewiesen.
Der Benutzer erhält nur Lesen, Durchsuchen und Ausführen. Das Inventar wird
vor und nach dieser ACL-Vergabe geprüft. Die anschließende Installation läuft
als angemeldeter Benutzer aus diesem unveränderlichen Satz; ZPAQ-Anker,
Rollbackgrenze und bestehende Transaktionskontrollen bleiben verbindlich.
Eine begrenzte reguläre `.DS_Store` im Downloadordner darf ignoriert werden;
sie wird nicht mitkopiert. Private Kopien werden nur bei übereinstimmender
root-/Geräte-/Inodenidentität bereinigt.

Ein zusätzlicher Erststartfall wurde inzwischen im nativen Einstieg ergänzt:
Gatekeeper App Translocation kann den gestarteten Installer von seinen
benachbarten Paketdateien trennen. Apple beschreibt genau diese Grenze
bundle-relativer Zugriffe in den [App Translocation Notes](https://developer.apple.com/forums/thread/724969).
Die bisherige automatische Suche im Bundle-Elternordner reicht dann nicht.
Der Einstieg bietet nun eine native Ordnerauswahl an, falls dort kein
vollständiges Paket liegt. Die Vorprüfung kontrolliert die festen 20 Einträge
mit `lstat`, ihre erwarteten Verzeichnis-/Dateitypen und bei Dateien die
Einfachverlinkung. Die physische Ordnerprüfung verwirft symbolische Links.
Auch der ausgewählte Ordner muss anschließend dieselbe root-geschützte
Kopie, dynamische CDHash-Bindung, Apple-Prüfung und vollständige
Inventarverifikation bestehen. Keine Authentifizierungsgrenze wurde für die
Auswahl gelockert. `installer-translocation-review/results.json` bindet die
Korrektur an den SHA-256 von `InstallerMain.swift`
`74b4e6ecb612a5b81d24569a4ee78a7e4c35453d03a98b540fd7d4a9022bbde1`.
Beide Architektur-Slices kompilieren mit `-warnings-as-errors`; je zwölf
Dateisystemfälle bestehen unter ARM64 und Rosetta-x86_64. Dies umfasst keinen
tatsächlichen Administrator- oder Installer-GUI-Aufruf. Dieser bleibt offen.

Ein Fehlerrollback prüft den authentifizierten Vorherzustand. Er vergleicht
die vollständige alte App samt fünf Sidecars, Metadaten, Verzeichnissen,
Dateimodi und Ticketbytes mit dem zuvor gebundenen Fingerabdruck und wiederholt
die Apple-/Hybridprüfung. Ein gültiges 5.0.1-Ticket wird dabei weder mit dem
anderen 5.0.2-Ticket verglichen noch an neue 5.0.2-Noticepflichten gebunden.
Unter `prior-release-rollback-lxxcg737` bestehen die echte Apple-/Hybridprüfung
des alten Paars, elf negative Gegenproben und ein privater Ablauf der
Produkt-Rollbackfunktion mit tatsächlichem `NSFileManager`-Austausch.
Dessen Löschhilfe war auf eigene private Testobjekte begrenzt; dieser Nachweis
ist kein privilegierter vollständiger Paketinstallationslauf.

Der native Verifier berücksichtigt außerdem die unterschiedliche Darwin-ABI:
ARM64 verwendet `fstat`/`lstat`, x86_64 die Symbole `fstat$INODE64` und
`lstat$INODE64`. Die unabhängige C-Probe unter `darwin-stat-abi-8_8c8frg`
zeigt, dass das unqualifizierte x86_64-`fstat` die verwendete 64-Bit-Struktur
falsch befüllt. ARM64 und x86_64 unter Rosetta bestätigen die korrigierte
Zuordnung. Dies ist ein ABI-Nachweis auf dem vorhandenen Apple-Silicon-Mac;
eine Installation auf einem separaten physischen Intel-Mac wird nicht behauptet.

Die begrenzten Verifierbelege unter `native-install-verifier` umfassen
72 synthetische Fälle, 13 CLI-Fälle, den Vergleich aller 16 Mach-O-Dateien
des zuvor installierten Paars mit den Buildwerkzeugen sowie 14 Prüfungen des
Vorherzustands-Fingerabdrucks. Die nativen Einstiegsslices kompilieren für
ARM64 und x86_64 mit `-warnings-as-errors`. Die privaten Tests
`tools/Test-InstallerEntry-macOS.py` und `tools/Test-PackageMode-macOS.py`
prüfen unter anderem Literalbehandlung, Stagingantworten, Objektwechsel,
Ticketabweichungen und das frühe Sperren nicht geschützter Paketquellen.
Das sind gezielte Komponentenprüfungen. Der inzwischen erzeugte Universal-
NativeAOT-Verifier besteht zusätzlich auf beiden tatsächlich gestarteten
Slices die Prüfung des neuen Development-Kits:
`approved-installer-native-aot-architectures.json` verzeichnet jeweils Exit 0
und 146 authentifizierte Inventareinträge. Der unabhängige private Kit-Audit
unter `installation-kit-audit-selfcheck-20260907` bestätigt exakt 20 Wurzeln,
19 Mach-O-Dateien, 38 Slices sowie ZIP-Bytes und Unix-Modi. Diese Nachweise
ersetzen weder die vollständige erfolgreiche Testmenge noch den tatsächlichen
Installer-GUI-Durchlauf, Apple Accepted, Stapling, den finalen
Installationsvergleich oder die öffentliche stabile Veröffentlichung.

## Aktueller Development-Durchlauf und nachfolgende GUI-Korrekturen

`approved-installer-development-build.log` endet mit 151 von 152 bestandenen
Gruppen, einem Fehler und null blockierten Gruppen. Die Laufzeit beträgt
492,8 Sekunden, die Summe der Gruppenlaufzeiten 962,1 Sekunden. Die einzige
fehlgeschlagene Gruppe ist `packaging.hybrid-key-separation`. Ihre Assertion
erwartete noch die frühere SDK-/`xcrun`-Einbindung im inzwischen absichtlich
SDK-freien `Verify-ReleasePairMetadata-macOS.sh`. Der tatsächliche Befund ist
damit eine veraltete Testannahme; der fehlgeschlagene Lauf bleibt dennoch
151/152 und wird nicht rückwirkend zu einem Erfolg umgewertet.

Die Testassertion wurde auf die festen absoluten Systemwerkzeuge und das
Fehlen von `xcrun` angepasst. Die echte Gegenprobe mit feindlichem `PATH` und
Shellstartdateien bleibt erhalten. Der separate Nachlauf dieser Gruppe
bestand mit 1 von 1 Gruppen in 79,0 Sekunden. Der Beleg
`sdk-free-metadata-targeted-evidence/results.json` hat SHA-256
`b0bde7f61f03e712cf26e1d6478c2d791f0f7784629dfcf261cc3ca1debd1de6`.
Dieser gezielte Nachtest ersetzt keinen vollständigen neuen Lauf.
`approved-installer-development-source-before.json` und `-after.json`
enthalten für den Installer noch den Quellhash
`fbe13c7ea165e7d4f860b422dbf711c18a05870d1ce4511237ac7ae326861406`.
Der vollständige Lauf belegt daher nicht die spätere Ordnerauswahl mit dem
oben genannten Hash `74b4e6ec…22bbde1`.

Die installierte App 5.0.2, Build 13 wurde sichtbar unter PID 81532 geprüft.
Die Version bleibt unter dem Untertitel in Deutsch und Englisch lesbar;
Analyse eines verschlüsselten Containers und Ablehnung einer Klartextdatei
folgen dem DE/EN-Sprachwechsel. Die positive kryptografische Löschung entfernte
die ausgewählten eigenständigen Container-/KPAR2-Kopien. Originalcontainer,
Original-KPAR2 und separate Klartext-Kontrolldatei blieben identisch. Der
Erfolgsdialog erschien auf Deutsch; Pfad und Bestätigungsmarkierung wurden
geleert. Diese Ergebnisse sind in
`approved-layout-gui-first-erase-result.json` festgehalten.

Derselbe sichtbare Lauf fand einen verbleibenden Oberflächenfehler: Nach
Schließen des Erfolgsdialogs überschreibt ein verzögert zugestelltes
`TextChanged`-Ereignis den Status `eraseCompleted` mit `eraseNotAnalyzed`.
Die eigentliche Kopielöschung und die unveränderten Originale sind belegt;
eine korrekte dauerhafte Abschlussanzeige war damit noch nicht bestanden.
Die minimale Korrektur erhält den Abschlussstatus beim programmgesteuerten
Leeren des Pfades. Jeder neue nichtleere Pfad setzt Analyse und Bestätigung
weiterhin zurück. Löschdienst, Faktoren und kryptografische Reihenfolge
bleiben davon unberührt.

Die neue Regression `gui.erase-completion-status` verwendet die echte
verzögerte Avalonia-Ereigniszustellung und prüft Abschlussanzeige, leeren Pfad,
zurückgesetzte Bestätigung, nachfolgende Pfadänderungen und Sprachwechsel.
Sie wurde in die Testmenge aufgenommen, die damit nun 153 Gruppen erwarten
lässt. Vor dem gezielten Build wurden 1.319 Inputs in
`gui-fixes-source-before.json` erfasst. Der frische Lauf
`Test-KeepVault --category GUI --parallel 1` besteht mit 24 von 24 Gruppen in
21,2 Sekunden; die neue Regression besteht in 1,390 Sekunden. Der Beleg
`gui-fixes-targeted-evidence/results.json` hat SHA-256
`b92cb9e4d435a3bf5449d28bb49f878aa12f7810600f41da78e0bd8cff8c3922`.
Das ist ein gezielter GUI-Testlauf, kein neuer vollständiger 153er-Lauf und
keine erneute sichtbare Löschprüfung des installierten Kandidaten.

Der folgende Development-Durchlauf mit 153 erwarteten Gruppen ist in
`final-gui-development-build.log` dokumentiert. Er wurde am 7. September
2026 gegen 14:04 Uhr durch einen Mac-Neustart unterbrochen; JSON-Ergebnisse
liegen für diesen Versuch nicht vor. Der Versuch wird weder als bestanden
noch als abgeschlossene Testmenge gewertet.

Zusätzlich sind die vier Pfadplatzhalter für Archivziel, Eingabearchiv,
Entpackziel und Löschcontainer auf Deutsch und Englisch lokalisiert. Die
bereits erteilte Freigabe der korrigierten Schlüsselzettel gilt weiter; es
ist keine erneute gestalterische Zustimmung erforderlich.

Die Wiederholung in `restart-development-build.log` wurde erfolgreich mit
Exitcode 0 abgeschlossen: 153 von 153 Gruppen bestanden, null Fehler und
null blockierte Gruppen, 405,4 Sekunden Gesamtdauer und 921,4 Sekunden
summierte Gruppenlaufzeit. Der Beleg
`restart-development-results/001-test-results.json` hat SHA-256
`343a5bac41eda92892e1958a1c0e40acc3d0a548c96883ef820f69a763cbd049`.
Die Vorher-/Nachher-Snapshots `restart-development-source-before.json` und
`-after.json` stimmen für alle 1.319 Quelleingaben überein. Die installierte
Development-App ist byteidentisch mit dem frisch gebauten Bundle.

`restart-development-kit-audit.json` bestätigt das neue Paket mit genau
20 Wurzelobjekten, 19 Mach-O-Dateien und 38 Slices. Beide NativeAOT-Slices
führten die authentifizierte Manifestprüfung tatsächlich erfolgreich aus:
ARM64 nativ und x86_64 unter Rosetta, dokumentiert in
`restart-development-native-aot-architectures.json`. Das belegt keinen
GUI-Lauf auf einem separaten Intel-Mac.

Der anschließende sichtbare GUI-Nachtest startete am 7. September 2026 um
15:19:35 Uhr unter PID 34669. Er bestätigt die lesbare Versionsnummer unter
dem Untertitel, alle vier Pfadplatzhalter sowie den PIN-Hinweis 6 bis 16
auf Deutsch und Englisch. Eine echte kryptografische Löschung entfernte
nur die ausgewählten eigenständigen Container-/KPAR2-Kopien; Originale
und Kontrolldatei blieben unverändert. Nach dem Erfolgsdialog bleibt die
Abschlussanzeige sowohl nach OK als auch beim Sprachwechsel DE/EN/DE
erhalten. Der Pfad ist leer, die Bestätigung ausgeschaltet. Ein neuer Pfad
setzt Status und Bestätigung zurück. Die App wurde anschließend mit Cmd-Q
beendet und der Prozess ist nicht mehr vorhanden. Beleg ist
`gui-completion-retest-result.json`.

Diese Ergebnisse betreffen den aktuellen Development-Kandidaten. Die
nachfolgende Apple- und Paketabnahme des endgültigen Developer-ID-Kandidaten
ist im nächsten Abschnitt getrennt belegt.

## Apple-Notarisierung und endgültiges Paket

Apple hat die originale Einreichung unter Job-ID
`672ab61e-4909-4fe9-a9e2-1685ea774e09` mit `Accepted`, `statusCode = 0`
und `issues = null` angenommen. Die privaten Belege liegen unter
`build/audit/5.0.2-20260906/notary-502-kh3uwr54/`.
`notary-direct-service-log.json` hat SHA-256
`a995cff5d3317c6cbb1d7ceaaa6dead83c6d6b312063753dcd58a9697b4e1310`;
das ursprünglich eingereichte ZIP hat SHA-256
`a7c94ceebd88eb0b2cf4da289ce3d8ec6f5b8a306196bcb44e51ee29cb4990cb`.
`apple-submission-bound-audit.json` bestätigt die Bindung aller 38 originalen
Architektursignaturen. Die 76 Rohzeilen im Apple-Log entsprechen exakt diesen
38 Signaturen: Die drei Bundle-Hauptprogramme erscheinen je Architektur
auch unter ihrem Bundlepfad; die übrigen Zeilen sind exakte Duplikate.
`apple-ticket-multiplicity-audit.json` belegt, dass keine zusätzliche oder
fehlende Binärdatei dahintersteht.

`final-developer-id-build.log` bestätigt Developer-ID-Signaturen,
erfolgreiches Stapling, `stapler validate` und Gatekeeper-Annahme für
Keep Vault, QR-Scanner und Keep Vault Installer. Der anschließende
`final-notarized-package-audit.json` besteht für genau 20 Wurzelobjekte,
19 Mach-O-Dateien und alle 38 unveränderten Slices. Gegenüber der
Einreichung wurden ausschließlich drei Ticketdateien hinzugefügt und die
sechs äußeren Manifest-/Signaturdateien erneuert. Alle übrigen Pfade,
Typen, Modi und Bytes sind identisch. Dieser Vergleich ist getrennt von
der Apple-Ticketvalidierung und der hybriden Manifestprüfung dokumentiert.

Die tatsächliche hybride Prüfung des endgültigen Inventars besteht mit
149 Einträgen in beiden NativeAOT-Slices, ARM64 nativ und x86_64 unter
Rosetta. `final-native-installation-verifier.json` dokumentiert diese
Ausführung am extrahierten `final-installer-kit`; sie ist kein tatsächlicher
GUI-Installerlauf und kein Test auf separater Intel-Hardware.
`final-release-assets.json` bindet genau sechs zur Veröffentlichung
vorbereitete Dateien. Das endgültige ZIP umfasst 43.678.062 Bytes und hat
SHA-256 `cac58f018ab60734e4565aea601d590e390d6640419eabe41e62a66f8e9c7484`.
Es unterscheidet sich wegen der gestapelten Tickets und des erneuerten
Manifests vom ursprünglichen Einreichungs-ZIP.

Die 1.319 Quelleingaben bleiben unverändert. Der Kandidat basiert weiterhin
auf Commit `e52159e7a569a8b77fe7732006388c4401c4009f` mit dem geprüften,
noch nicht abschließend committeten 5.0.2-Arbeitsstand. App-Installation und
Authentifizierung für den Root-ZPAQ-Anker sind inzwischen abgeschlossen.
Der finale Testlauf in `final-developer-id-build.log` besteht mit 153 von
153 Gruppen, null Fehlern und null blockierten Gruppen in 405,5 Sekunden;
die summierte Gruppenlaufzeit beträgt 918,9 Sekunden. Der Beleg
`final-developer-id-results/001-test-results.json` hat SHA-256
`8ec5a2d0a5b28c5b40f3e0ba7054cea27c46bb99c4b25a1a3e26c3e44c1db93d`.

Auch die zusätzlichen einzeln gestarteten Releaseprüfungen bestehen:
Produktions-Worker-Gleichheit in 7,7 Sekunden, unabhängiger paralleler
MAC-KAT in 0,4 Sekunden, v12-/KPAR2-Rundlauf in 25,1 Sekunden,
KPAR2-Worker-Gleichheit in 0,2 Sekunden, physische EIO-Reparatur in
0,6 Sekunden und vollständige ZPAQ-Matrix in 21,6 Sekunden. Dies sind die
jeweiligen Gesamtlaufzeiten; die Ergebnisdateien mit den Präfixen `003`,
`005`, `007`, `009`, `011` und `013` und dem Suffix `-test-results.json`
liegen im selben Ergebnisverzeichnis.

Die anschließend ausgeführten Produktionsprüfungen bestehen ebenfalls:

| Releaseprüfung | Gesamtlaufzeit | Ergebnisdatei | SHA-256 |
| --- | ---: | --- | --- |
| Primitive und vollständige Container aller zehn Cipher-Suiten | 195,0 s | `015-test-results.json` | `61ee88f33e04edd89a6c1b4d2bf0392a74735e8b0bfdc1ecbec8c3241ad8f35e` |
| 256 MiB, Paranoia, Stufe 5, Produktions-KDF | 75,4 s | `017-test-results.json` | `a1765a599d66237cad65235954982be18155d7441b66d3ec4ab680e8f747ff1b` |
| Komplexer Paranoia-Verzeichnisbaum mit KPAR2-Reparatur | 73,7 s | `019-test-results.json` | `d22fbd7f36ad7864faa6d8c0ef1ab54f52c1a208bee1f77f80ee5459b38e6f8f` |

Die Performance-Matrix hält die Grenze von 25 Prozent gegenüber der
angegebenen Referenzmessung auf demselben Mac ein. Der komplexe Lauf
verarbeitet 18 Dateien, 20 Verzeichnisse und 221.327.790 Eingabebytes;
eine beschädigte Einheit wird durch KPAR2 repariert. Diese Messungen
verwenden die Produktionsparameter von Argon2id. Die gesonderte
Pipeline-Skalierung innerhalb der Performance-Matrix verwendet ausdrücklich
die Test-KDF-Speichergröße und wird nicht als Produktions-KDF-Messung
ausgegeben.

`final-developer-id-build.log` endet mit `release_publish_swap=complete` und
den endgültigen App-/ZIP-Pfaden unter `dist/Keep Vault-macOS/`. Damit ist
der lokale Releasebuild vom 7. September 2026 abgeschlossen. Der tatsächliche
native Installer-GUI-Lauf und der letzte komplexe Paranoia-Lauf nach finaler
Installation bleiben gesondert offen. Commit, Tag, Uploadprüfung und
öffentliche stabile Freigabe folgen erst nach diesen Ergebnissen.

## Installer-GUI-Befund und erforderliche Wiederholung

Der tatsächliche native Installer-GUI-Test am 8. September 2026 scheiterte
mit „Installation angehalten“ und dem Codesign-Fehler
`No such file ... invalid requirement specification`. Die Anforderung wurde
als getrenntes Argument nach `-R` übergeben. `codesign` interpretiert diese
Form als Dateipfad; eine Anforderung als Text benötigt `-R=<Anforderung>`.
Die Prüfung stoppte die Installation, statt den Fehler zu übergehen.
Der Befund betrifft die Ausführung des Installers und wurde durch die zuvor
bestandenen Komponenten-, Build- und Notarisierungsprüfungen nicht erfasst.

Im folgenden privaten Integrationslauf bestand die korrigierte Codesign-
Prüfung. Danach scheiterte die ACL-Vergabe mit `user:501`, weil `chmod` den
numerischen Text nicht in eine Benutzer-UUID übersetzen konnte. Es wurde
keine App installiert; die fehlgeschlagene Zwischenkopie wurde entfernt.
Die Korrektur ermittelt den Kontonamen mit `getpwuid_r`, prüft dessen
Rückauflösung mit `getpwnam_r` und kontrolliert die UID zusätzlich auf der
Rootseite. Die tatsächlich erzeugten ACL-Befehle verwenden diesen gebundenen
Kontonamen und gewähren ausschließlich Lesen, Durchsuchen und Ausführen.

Die ACLs werden außerdem vor der ersten Systemrichtlinienprüfung und der
Ausführung nativer Programme vergeben. Damit ist keine nachträgliche
ACL-Metadatenänderung an bereits gestarteten nativen Dateien erforderlich.
Eine weitere Gegenprobe fand den Zugriff auf `/dev/fd/6` durch den bisherigen
nativen Signaturprüfer bei Rootdateien mit Modus 0600 und Lese-ACL blockiert.
Die Korrektur liest begrenzte Signaturbytes direkt aus dem gehaltenen
Dateideskriptor und prüft sie mit der gemeinsamen Signatur-API. Die bisherigen
Signatur-, Größen- und Identitätsprüfungen bleiben erhalten.

Diese Produktkorrekturen sind inzwischen umgesetzt. Die privaten Belege
`installer-literal-requirement-regression-20260908.json` und
`installer-account-acl-regression-20260908.json` im Auditverzeichnis vom
6. September bestätigen die echten Codesign- und ACL-Befehle einschließlich
gezielt wieder eingeführter Fehler. `held-signature-regression-20260908.json`
bestätigt 15 bestandene Prüfungen der gehaltenen Signaturbytes, SHA-256
`e1a7966944f70bf01b71ffba33f8115fca8cf03eaac0496e60ab8e5560f93982`.

`build/audit/5.0.2-20260908/root-acl-native-before-after.json` zeigt an
derselben unveränderten Root-/ACL-Zwischenkopie: Der alte Verifier bricht
mit dem `/dev/fd`-Zugriffsfehler ab, die neu gebauten NativeAOT-Verifier
bestehen mit allen 149 Inventareinträgen auf ARM64 und unter Rosetta-x86_64.
Dabei wurde ein korrigierter externer Verifier gegen die bestehende alte
Zwischenkopie ausgeführt. Das ist ein gezielter Komponentenbeleg, kein
bestandener neuer Gesamtinstallerlauf. Die Prüfung des Installereinstiegs
ist nun vor der Signierung automatisch im Paketbau verpflichtend;
`installer-entry-release-gate.log` im neuen Auditverzeichnis bestätigt sie.

`correction-source-delta.json` bindet genau neun geänderte Quell-/Test-/
Buildpfade und den Übergang von 1.319 auf 1.320 Quelleingaben. Passwort-/PIN-
Regeln und Archivkryptografie wurden durch diese Korrekturen nicht geändert;
die gemeinsame hybride Signatur-API wurde ohne Abschwächung ihrer bisherigen
Prüfungen ergänzt. Der eingefrorene neue Stand wird in
`build/audit/5.0.2-20260908/corrected-developer-id-build.log` gebaut.
Die zuvor dokumentierte Apple-Annahme, der ZIP-Hash und sämtliche Build-PASS-
Ergebnisse bleiben historische Nachweise des fehlerhaften Kandidaten. Sie
dürfen nicht auf das veränderte Installerartefakt übertragen werden. Version
5.0.2, Build 13 bleibt vor der ersten öffentlichen Veröffentlichung das Ziel;
der korrigierte Kandidat benötigt eigene Signatur-, Notarisierungs-, Stapling-
und vollständige Prüfnachweise. Der tatsächliche Installer-GUI-Lauf und der
letzte komplexe Lauf nach finaler Installation sind erneut erforderlich.
Das README-Beispiel wurde auf die Textform `-R='…'` korrigiert.

## Historischer Kandidat mit Apple-Annahme am 8. September 2026

Apple hat die neue Einreichung unter Job-ID
`c4d7f3a5-3a54-4954-af83-d003bc194824` mit `Accepted`, `statusCode = 0`
und `issues = null` angenommen. Das originale Einreichungs-ZIP hat SHA-256
`72de4c27b7271fa264447d535826afb425f5c7ce0c5a07538eb25113478ac76b`.
Der Dienstbeleg
`build/audit/5.0.2-20260908/notary-candidate/notary-direct-service-log.json`
hat SHA-256
`386e1e7ac1b79ae3392a717c296c74589d784e3913d85818a1683f338cbd87a2`.
`apple-submission-bound-audit.json` im selben Tagesverzeichnis bestätigt alle
38 originalen Architektursignaturen; die 76 Apple-Rohzeilen sind diesen
Signaturen zugeordnet. `source-after-apple.json` enthält 1.320 Quelleingaben,
keine Änderungen und `matchesPrevious = true`.

Diese neue Annahme gilt für den korrigierten Kandidaten und ist vom
überholten Job `672ab61e-4909-4fe9-a9e2-1685ea774e09` getrennt. Der
Einreichungs-ZIP-Hash ist vom nachfolgenden gestapelten Veröffentlichungs-ZIP
zu unterscheiden. Stapling, Ticketvalidierung und Gatekeeper-Annahme aller
drei korrigierten Apps sind inzwischen im neuen Buildlog bestanden.

`final-notarized-package-audit.json` im Auditverzeichnis vom 8. September
bestätigt das endgültige Paket: 20 Wurzelobjekte, 19 Mach-O-Dateien und
38 unveränderte Slices. Gegenüber der neuen Einreichung kamen nur die drei
Ticketdateien hinzu; die sechs Manifest-/Signaturdateien wurden erneuert.
Alle übrigen Pfade, Typen, Modi und Bytes stimmen überein.
`final-native-installation-verifier.json` bestätigt auf ARM64 und unter
Rosetta-x86_64 sowohl das hybride Inventar mit 149 Einträgen als auch das
ZIP mit allen fünf Sidecars. Alle geprüften Dateien blieben unverändert.
`final-release-assets.json` bindet genau sechs Dateien. Das endgültige ZIP
hat 43.681.703 Bytes und SHA-256
`820863042b5cfacb6643b1696c8fbf8412c9529d82d921d3bb7174db3dedf81d`.

Der vollständige Testlauf des korrigierten notarisierten Kandidaten besteht
mit 153 von 153 Gruppen, null Fehlern und null blockierten Gruppen in
410,1 Sekunden; die summierte Gruppenlaufzeit beträgt 932,8 Sekunden.
`corrected-developer-id-results-resumed/001-test-results.json` hat SHA-256
`c9ddc29c752b5c451fd6e1a9d4c30770a368b248463ddcd6c157f34746f58147`.
Alle zusätzlichen einzelnen Releaseprüfungen bestehen ebenfalls:
Produktions-Worker-Gleichheit, paralleler MAC-KAT, v12-/KPAR2-Rundlauf,
KPAR2-Worker-Gleichheit, physische EIO-Reparatur und vollständige ZPAQ-Matrix.
Auch die Produktionsmessungen sind abgeschlossen:

| Prüfung des korrigierten Kandidaten | Testzeit | Gesamtlaufzeit | Ergebnisdatei |
| --- | ---: | ---: | --- |
| Performance-Matrix aller zehn Cipher-Suiten | 194,6 s | 194,7 s | `015-test-results.json` |
| 256 MiB Paranoia mit Produktions-KDF | 81,6 s | 81,7 s | `017-test-results.json` |
| Komplexer Paranoia-Baum und KPAR2-Reparatur | 78,3 s | 78,4 s | `019-test-results.json` |

Die drei Ergebnisdateien liegen im Verzeichnis
`corrected-developer-id-results-resumed/`. Ihre SHA-256-Werte sind
`1e1448823dfb6ea904800aebdce4b15d128c6327615ca364bed7583288cabaca`,
`95b1ed62d72a9cbc12db8f250feb45292ff1d166749d401e7f978f53ee621af5`
und `0ccb528d57c0bf86460aa95abc292554024cd38642f04f7abb76aba27b1d6679`.
Der Ergebnisindex bindet insgesamt zehn Ergebnis- und zehn Zeitdateien;
alle 20 Dateien sind mit ihren Indexhashes geprüft. Der komplexe Lauf
verarbeitet 18 Dateien, 20 Verzeichnisse und 221.327.790 Eingabebytes und
repariert eine beschädigte Einheit mit KPAR2.

Der korrigierte Releasebuild ist mit Exitcode 0 und
`release_publish_swap=complete` abgeschlossen. `source-after-build.json`
bestätigt alle 1.320 Quelleingaben unverändert. `published-dist-assets.json`
bestätigt, dass die sechs Dateien unter `dist/Keep Vault-macOS/` exakt den
privat gesicherten endgültigen Assets entsprechen. Dies ist die lokale
Bereitstellung, noch keine öffentliche Veröffentlichung.
Die zusätzlichen tatsächlichen Installer-GUI-Gegenproben sind inzwischen
bestanden: Abbrechen im Startdialog, Auswahl eines unvollständigen Pakets
und Abbrechen der Ordnerauswahl. `gui-installer-negative-cases.json` hat
SHA-256 `6f3dd5afc283f4631219b5494ea359d8f992c984985401f2167aea5ba39fa211`.
Nach jedem Fall bestätigt ein separater Vergleich dieselben 129 Einträge
beider installierter Apps, ihrer zehn Sidecars und der Root-Ankerdateien
einschließlich Versionsuntergrenze unverändert. Geprüft sind Typen, Bytes,
Modi, Inodes/Geräte, Eigentümer/Gruppen, Linkanzahl, Flags sowie mtime/ctime;
atime bleibt ausgenommen. Die Belege sind `gui-cancel-initial-after.json`,
`gui-incomplete-package-after.json` und `gui-cancel-folder-after.json`.
Der Zustandsvergleich führte keine LaunchServices- oder Appbefehle aus.
Ein Abbruch des macOS-Administratordialogs wurde dabei nicht geprüft; die
separate Ordnerauswahl ist kein Nachweis tatsächlicher App Translocation.

Die normale Installation aus dem vollständigen Paket mit 20 Wurzelobjekten
unter PID 9073 scheiterte nach der lokalen Administratorfreigabe mit
Exitcode 2: `The bound package, installer, verifier or rollback helper changed
identity.` Zuvor bestanden die wiederholte Prüfung aller 149 Inventareinträge
und die Apple-Prüfungen. `gui-final-installer-normal-failure.json` belegt den
Fehler; `gui-installer-normal-failure-state.json` bestätigt alle 129 zuvor
installierten Einträge unverändert. Der bestandene Build und die Apple-Annahme
machen diesen Kandidaten deshalb nicht veröffentlichbar.

## Nachgewiesener ctime-Fehler und erneuter Kandidat

Die getrennte Wiederholung in `installer-identity-trace/finding.json` zeigt
die genaue Fehlergrenze: Nach der erfolgreichen nativen Prüfung aller 149
Inventareinträge schlug die unmittelbar folgende Verzeichnisbindung fehl.
Ausschließlich ctime von `Keep Vault Installer.app` änderte sich von
1788870435 auf 1788870436. Gerät, Inode, Eigentümer, Modus, Größe, mtime und
Linkanzahl blieben gleich. Der Quell-/Zwischenkopienvergleich bestätigt
156 Einträge mit unveränderten Typen, Modi und Bytes. Das Ablaufprotokoll
`installer-identity-trace/sealed-install-xtrace.log` hat SHA-256
`059a3509f31dd12ef84b020562f5f51fd00069010a8455b79c9d654d1a80cbf9`.

Damit ist die falsche Ablehnung durch die ctime-Bindung kausal belegt.
Welcher Betriebssystemprozess oder welche konkrete Xattr-Operation ctime
änderte, ist nicht nachgewiesen. Eine Metadatenänderung durch macOS bleibt
eine Schlussfolgerung. Die Xattr-Mutation in der Regression reproduziert
gezielt dieselbe Feldänderung, identifiziert aber nicht den ursprünglichen
Auslöser.

Die Korrektur lässt ausschließlich ctime bei der länger gehaltenen Bindung
des Installer-App-Verzeichnisses aus. Dessen übrige Identitätsfelder,
Symlink- und Schreibschutzprüfungen bleiben erhalten. Paketwurzel und
reguläre Helfer binden ctime weiterhin; die Helfer bleiben zusätzlich an
SHA-256 gebunden. Root-Eigentum, geschützte Zwischenkopie, Apple-Signaturen
und vollständiges hybrides Inventar bleiben verpflichtend. Die native
Verzeichnisbindung innerhalb eines Verifier-Aufrufs bleibt unverändert.

`package-ctime-regression.json` belegt 19 bestandene Fälle. Sie prüfen die
zulässige alleinige ctime-Änderung am Installer-Verzeichnis und weiterhin
abgelehnte Änderungen an Root-ctime, Helfer-ctime, Modus, Schreibbarkeit,
mtime, Inode und Symlink sowie die bisherigen Helfer-, Ticket- und
SDK-Unabhängigkeitsprüfungen. Ein absichtlich wiederhergestellter alter
Verzeichnis-ctime-Vergleich lässt den neuen positiven Test scheitern. Diese
Mutationsgegenprobe bestätigt, dass der Test den ursprünglichen Fehler
erkennt. `package-ctime-tests-independent-review.json` dokumentiert die
getrennte schreibgeschützte Prüfung der 19 Fälle und ihrer Nachweisgrenzen.

Zusätzlich ist die Fehlerdarstellung korrigiert: Ein etwa 131 KB langer
Prozesslog wird vollständig in einem 600 × 240 Punkte großen, vertikal
scrollbaren Textfeld dargestellt. Die Systemschrift ist 13 Punkte groß;
der Text ist auswählbar und schreibgeschützt. Kurze Meldungen bleiben direkt
lesbar. Die Meldung für ein unvollständiges Paket liegt auf Deutsch und
Englisch vor. Der private Harness besteht 18 Darstellungsfälle in beiden
Sprachen ohne sichtbare Fenster. Die synthetische native GUI-Prüfung
bestätigt deutsche und englische Langtexte samt Scrollen bis zur letzten
Markierung, den englischen Kurztext per Bildschirmbild und Accessibility
sowie den deutschen Kurztext per Accessibility. Für den deutschen Kurztext
liegt kein zusätzliches Bildschirmbild vor. Die Belege stehen in
`installer-alert-preview-20260908/test-result.json` und
`installer-alert-preview-20260908/gui-preview-result.json`. Die Vorschau
führte weder eine Installation noch eine Authentifizierung aus.

Gegenüber dem zuvor gebauten Kandidaten sind genau fünf Pfade geändert:
`InstallerMain.swift`, `Build-InstallerKit-macOS.zsh`,
`PackageRuntime-macOS.sh`, `Test-InstallerEntry-macOS.py` und
`Test-PackageMode-macOS.py`. Die beiden privaten Harness-Prüfungen werden
vor der Signierung automatisch ausgeführt. Passwort-/PIN-Regeln und
Archivkryptografie bleiben durch diese Änderungen unverändert.
`installer-ctime-fix/source-start.json` bindet erneut 1.320 Quelleingaben.
Der neue Build läuft in
`installer-ctime-fix/corrected-developer-id-build.log` und wurde nach der
neuen Apple-Annahme fortgesetzt. Die früheren PASS-Ergebnisse und Apple-Jobs
werden nicht auf diesen Kandidaten übertragen.

Der neue Einreichungskandidat liegt in `installer-ctime-fix/notary-candidate/`.
Sein ZIP hat 43.679.426 Bytes und SHA-256
`6bd960726f41189635343d5e47f0b509297ca4d17de06eb1038412ac0ba0aa74`.
`submission-input-audit.json` bestätigt Version 5.0.2, Build 13 für alle
drei Apps, die 20 Wurzelobjekte, 19 Mach-O-Dateien und 38 Universal-Slices
sowie die Übereinstimmung von Paket und ZIP. Der Beleg hat SHA-256
`92b208729a15a23d3a5001b5db16d73ea9408b61ee850c05ee8382f96b1191b6`.
Diese Eingangsprüfung ist keine Apple-Notarisierungsannahme und ersetzt
weder das endgültige hybride Inventar noch die spätere Ticketvalidierung.
`installer-ctime-fix/source-before-notary.json` bestätigt alle 1.320
Quelleingaben mit `matchesPrevious = true` und ohne Änderungen. Vollständige
Originalkopien für den Xcode-Abgleich sind mit 332 Einträgen gesichert.

Apple hat diese Einreichung unter Job
`de8618c3-7404-4b7f-b35e-591fd5fd92c2` mit `Accepted`, `statusCode = 0`
und `issues = null` angenommen. Der Dienstbeleg
`installer-ctime-fix/notary-candidate/notary-direct-service-log.json` hat
SHA-256 `3fb3e3a2dfaab7b0f15f9321a07a6effe887ef866f826367c5389efa628ffc1d`.
`installer-ctime-fix/apple-submission-bound-audit.json` bindet die Annahme
an das originale Einreichungs-ZIP und alle 38 ursprünglichen Slices;
die 76 Apple-Rohzeilen ergeben 38 eindeutige Pfad-/Architekturzuordnungen.
`installer-ctime-fix/source-after-apple.json` bestätigt 1.320 unveränderte
Quelleingaben mit `matchesPrevious = true` und ohne Änderungen.

Die Bestätigung `NOTARIZED` wurde dem wartenden Build genau einmal
übergeben. Stapling, `stapler validate` und Gatekeeper-Annahme sind für
Keep Vault, QR-Scanner und Keep Vault Installer im neuen Buildprotokoll
bestanden. Der neue vollständige Testlauf besteht mit 153 von 153 Gruppen,
null Fehlern und null blockierten Gruppen. Die Gesamtlaufzeit beträgt
396,2 Sekunden, die summierte Gruppenzeit 910,3 Sekunden. Der Beleg
`installer-ctime-fix/corrected-developer-id-results/001-test-results.json`
hat SHA-256
`b7f068c25e9be40612fa869b2b88437dbf21f267ad5c6c3cf52924b522c89a6f`.
Alle sechs zusätzlichen Einzelprüfungen bestehen: Produktions-Worker-
Gleichheit, paralleler MAC-KAT, v12-/KPAR2-Rundlauf, KPAR2-Worker-Gleichheit,
physische EIO-Reparatur und vollständige ZPAQ-Matrix. Auch die drei
Produktionsmessungen bestehen: Performance-Matrix 196,1 Sekunden,
256-MiB-Paranoia 81,8 Sekunden und komplexer Paranoia-Baum 75,4 Sekunden
Testzeit. Der komplexe Lauf verarbeitet 18 Dateien, 20 Verzeichnisse und
221.327.790 Eingabebytes und repariert eine beschädigte Einheit. Die
Ergebnisse stehen in `015-test-results.json`, `017-test-results.json` und
`019-test-results.json` des neuen Ergebnisverzeichnisses. Der Build ist mit
Exitcode 0 abgeschlossen.

Das endgültige Veröffentlichungs-ZIP ist 43.685.318 Bytes groß und hat
SHA-256 `c4f069e0091259a0c6a1f76d880879facec689625b059e5d5659b70e5af112e1`.
`installer-ctime-fix/final-notarized-package-audit.json` bestätigt alle
38 unveränderten ursprünglichen Slices. Gegenüber der Einreichung ändern
sich ausschließlich drei Ticketdateien und die sechs Manifestdateien.
Der Beleg hat SHA-256
`07ede9cf135b55f11490118c14ac20b00ce3e54566fd05d8567e9e36503b43be`.
`final-native-installation-verifier.json` bestätigt mit dem tatsächlichen
nativen Verifier je Architektur `verify-installation` mit 149 Einträgen
und `verify-artifact` mit allen Sidecars: vier Aufrufe, alle Exitcode 0.
Die x86_64-Aufrufe laufen über Rosetta und sind kein separater Intel-Mac-Test.
`final-release-assets.json` bindet die sechs endgültigen Dateinamen, Größen
und SHA-256-Werte; SHA-256 des Belegs ist
`194d33bbeead75bfca0b6a49f8312616468b7e9ae466c705274c73b1845454df`.
`published-dist-assets.json` bestätigt ihre Bytegleichheit mit dem lokalen
`dist/Keep Vault-macOS`; das ist noch kein GitHub-Upload.
`source-after-build-independent.json` bestätigt alle 1.320 unveränderten
Quelleingaben, `matchesPrevious = true` und keine Änderungen.

Die erneuten echten GUI-Gegenproben des neuen signierten Installers bestehen:
Abbruch im Startdialog, Ablehnung eines unvollständigen Pakets vor der
Authentifizierung und Abbruch der Ordnerauswahl. Nach jedem Fall bleiben
alle 129 geprüften installierten Einträge einschließlich Bytes, ctime und
Inodes unverändert. `installer-ctime-fix/gui-installer-negative-cases.json`
hat SHA-256 `89f8dec05f53ebf4417dafd776bbdab8dc01412876c5d20ecff3f8e07553f51c`.
Die zugeordneten Belege sind `gui-cancel-initial-after.json`,
`gui-incomplete-after.json` und `gui-cancel-folder-after.json`. Das deutsche
Fenster für ein unvollständiges Paket ist im Bildschirmbild vollständig und
ohne abgeschnittenen Text samt OK lesbar. Ein Abbruch des Administrator-
dialogs oder tatsächliche App Translocation sind damit nicht belegt.
Der erste normale Installerprozess unter PID 34713 ist beendet, ohne dass
ein erfolgreicher Abschluss beobachtet wurde. Der nachfolgende Zustandsbeleg
`installer-ctime-fix/gui-normal-resume-state.json` bestätigt 129 vollständig
unveränderte Einträge. `gui-normal-resumed-start.json` dokumentiert den
neuen normalen Start unter PID 37155 zunächst vor lokaler
macOS-Authentifizierung. Nach der lokalen Bestätigung wurde unter demselben
PID das tatsächliche Fenster „Installation abgeschlossen. Keep Vault und
QR-Scanner sind unter Programme installiert.“ per AX und Bildschirmbild
beobachtet. Der vollständige Text ist ohne Abschneiden sichtbar; OK beendet
den Dialog. `gui-normal-success.json` hat SHA-256
`449f1ef2e9e3e59010608d48cdcf643c025f2545d8c00925759c2df2ae3f820e`.
`gui-normal-installed-audit.json` bestätigt anschließend beide vollständigen
App-Bäume in Version 5.0.2, Build 13, alle zehn externen Sidecars und den
root-eigenen v12-ZPAQ-Anker bytegleich mit dem aktuellen endgültigen Paket.
Der Installationsbeleg hat SHA-256
`1467f14ccce2b8af598c10d78642f8aa807068b37b893eb67602b7bff7d3bddf`.
Physisch ist in den geprüften Programmordnern nur die kanonische Haupt-App
installiert; 21 zusätzliche LaunchServices-Registrierungen bleiben zu diesem
Zeitpunkt als gesonderter Bereinigungsauftrag offen.

Auch der separat gestartete tatsächliche Installer unter PID 46797 besteht
nach Auswahl des vollständigen endgültigen Paketordners und lokaler
Authentifizierung. Das kurze Fenster „Installation abgeschlossen“ ist per AX
und Bildschirmbild vollständig sichtbar; OK beendet den Dialog.
`gui-fallback-success.json` hat SHA-256
`151fcdf95353ff18f1253c23222562f58ab0d6b6e3dfb4143a4880d6f58241eb`.
`gui-fallback-installed-audit.json` hat SHA-256
`50683668f16e00de8bc791e6edc7d6b149e94003911e27cadc69912155cf416c`
und bestätigt erneut beide Apps, zehn Sidecars und den root-eigenen ZPAQ-Anker
bytegleich mit dem endgültigen Paket. Dies ist ein Nachweis der tatsächlichen
Ordnerauswahl, nicht einer vom Betriebssystem ausgelösten App Translocation.

Die tatsächlich installierte Haupt-App unter PID 56850 besteht die finale
GUI-Sichtprüfung per AX und Bildschirmbild auf Deutsch und Englisch. Version
5.0.2 steht unter dem vollständig lesbaren Untertitel, PIN-Hinweis und
Archivpfadplatzhalter sind lokalisiert, die Integritätsprüfung ist in beiden
Sprachen erfolgreich. Anschließend ist Deutsch wiederhergestellt und die App
mit Command-Q beendet. `gui-main-final-de-en.json` hat SHA-256
`8e0c71f6050c622bbf8b327833c43fa4c218d6def7c97c133fb0218c11e96a2c`.
Dies ist ein abschließender GUI-Smoke-Test; die früheren vollständigen
Archiv-, Entpack-, Druck-, QR- und Löschbelege bleiben getrennte Nachweise
für die seither unveränderten betreffenden Produktfunktionen.

Nach Abschluss der GUI-Prüfungen wurden ausschließlich die 21 zusätzlichen
Registrierungen der Haupt-App an zuvor überprüften eigenen Build-, Audit-,
dist-, temporären und Papierkorbpfaden gezielt abgemeldet. Die kanonische
`/Applications/Keep Vault.app` wurde registriert. `final-registration-cleanup.json`
belegt die Aktionen ohne globale LaunchServices-Rücksetzung, App-Löschung oder
Änderung von QR-Scanner/Whisper-Registrierungen. `final-registration-after.json`
bestätigt exakt eine kanonische Haupt-App-Registrierung und null zusätzliche
Einträge; SHA-256
`49271f5a0fa7832bd167a0c4b8c47108c8085d2a2d6276e5d1b66af8c2804934`.
`final-physical-app-inventory.json` prüft unabhängig vom Anzeigenamen alle
82 unmittelbaren `.app`-Bundles in `/Applications` und `~/Applications`,
liest alle Info.plists ohne Fehler und findet genau eine Keep-Vault-Haupt-App:
`/Applications/Keep Vault.app`, Version 5.0.2, Build 13. Der Beleg hat SHA-256
`84665a7bd1d8e8947c6cd59ade4c6cb2a8c378f15777f28837a3efc3fcb80cc1`.

Der vollständige Offline-Produktionslauf ist inzwischen bestanden und wird
im folgenden Abschnitt getrennt von der GUI dokumentiert. Auch der letzte
installierte Komplextest ist inzwischen bestanden; seine abschließenden
Belege stehen nach dem Offline-Nachweis. Die öffentliche Freigabe folgt als
gesonderter Git-/Uploadschritt. Der Einreichungs-
ZIP-Hash darf nicht als Hash des gestapelten Veröffentlichungs-ZIP ausgegeben
werden. Beide Hashes und ihre unabhängige Paket-/Assetbindung sind oben getrennt
dokumentiert.

## Präzisierung des Offline-Nachweises

Die vollständige Offline-Funktion ist unverändert verpflichtend. Abschnitt 3.2
des Nutzerdokuments „Keep Vault: Sicherheitsmodell für PINs und Passwörter“
fordert Offline-Nutzung einschließlich Erststart, Archivierung und Entpackung;
Abschnitt 6 verlangt vollständige Abläufe bei gesperrtem Netzwerk ohne
vorbereitenden Modelldownload. Der Anhang schreibt für diese Offline-Gegenprobe
keine bestimmte GUI-Ausführungsform vor. Die frühere Fassung unseres
[Credential-Vertrags](KEEP_VAULT_V12_CREDENTIAL_POLICY.md) hatte die reale
GUI und die Offline-End-to-End-Prüfung enger miteinander verbunden.

Die Nachweise werden deshalb präzise getrennt: reale GUI-Archivierung und
Entpackung, gesonderte GUI-Erststart-/Auswahlprüfung unter Netzsperre und ein
vollständiger Produktions-Core-Rundlauf in einem frischen Prozess ohne externe
Netzverbindung. Der Core-Lauf muss die unveränderten Erstellungsregeln,
Kompression, Verschlüsselung, KPAR2-Erzeugung und -Reparatur, Authentifizierung,
Entschlüsselung, Entpackung und vollständigen Struktur-, Größen- und SHA-256-Vergleich ausführen.
Er verwendet die eingefrorenen Produktionsquellen, die ausschließlich lokal
mitgelieferten Modelle und die signierten Nativebytes der finalen Installation.
Die frische Vorbereitung von SDK und NuGet dient dem Testbuild; sie ersetzt
keine Modelldaten und ist kein Laufzeitdownload der App. Das externe Netzwerk
muss vor Start des frischen Testprozesses bis zu dessen Ende getrennt bleiben,
mit positiver Verbindungskontrolle davor und danach. Eine vorzeitige
Netzwiederherstellung macht den Offline-Nachweis ungültig.

Dieser Offline-Core-Lauf ist unter
`installer-ctime-fix/offline-e2e-prepared/run-xdf2p6l8/` bestanden. Der private
Runner hat nach frischem Restore, Build und Staging der installierten
signierten Nativebytes ausschließlich vor dem funktionalen Prozessstart
pausiert. Mit ausgeschaltetem WLAN `en0` startet der frische Testprozess und
besteht `performance.paranoia-complex-tree-e2e` mit Exitcode 0 in 79,562 Sekunden.
Er verarbeitet 18 Dateien, 20 Verzeichnisse und 221.327.790 Eingabebytes mit
Kompressionsstufe 5 und dem vollständigen Paranoia-Argon2id-Profil. Eine
beschädigte KPAR2-Einheit wird authentifiziert repariert; der wiederhergestellte
Containerhash sowie die vollständigen Verzeichnis-, Pfad-, Größen- und
Dateihashmengen stimmen. Die Test-Samples zur Faktorgeneration sind synthetisch
und werden nicht als menschliche Entropie ausgewiesen.

77 periodische Messungen während des Laufs prüfen WLAN-Zustand, Interfaces,
IPv4-/IPv6-Routen und numerische TCP-Verbindungsproben. Auch nach Prozessende
und vor Wiederherstellung ist das Netzwerk getrennt. Positive IPv4-/IPv6-
Kontrollen bestehen unmittelbar davor und nach der Wiederherstellung. Der
unabhängige Watchdog bestätigt WLAN wieder eingeschaltet und hat nicht
vorzeitig ausgelöst. Das ist kein Paketmitschnitt und schließt keine
unbeobachtete kurzzeitige Änderung zwischen Messpunkten aus.
`result.json` hat SHA-256
`1c15da13a461236e81eaab8ab9bc683c3cc042503c3a84701a752ff3b44d400d`;
`test-evidence/results.json` hat SHA-256
`a867862a50b2596a9686035282ee7dd5f388b29a2300962d2db40dd8aff482cb`.

Der unabhängige lesende Nachaudit `offline-e2e-independent-audit.json` besteht
mit 2.814 Prüfungen. Er wertet die Rohdaten eigenständig aus: insgesamt 79
Offline-Snapshots mit 316 numerischen TCP-Gegenproben, einschließlich je einer
Probe vor dem Start und nach dem Ende. Die beobachtete Offline-Spanne beträgt
81,457 Sekunden, der größte Abstand zwischen Messpunkten 1,154 Sekunden.
Der Beleg hat SHA-256
`0352950c7de112e2afb4adbaed1897160354bbd1a3472d4caafe1e5361f4ea64`.
Prozessübergreifend sind die beobachteten Python-Monotonic-Werte nicht
vergleichbar; der Nachaudit verwendet dafür UTC-Reihenfolge und bestätigt
die Spanne zusätzlich anhand derselben Orchestrator-Uhr. Der unzuverlässige
prozessübergreifende Deadline-Vergleich des privaten Pause-Hooks wird nicht
als tragender Schutz gewertet. Orchestrator und Watchdog verwenden jeweils
ihre eigene Uhr und ihr eigenes Zeitlimit.

Dies belegt den vollständigen frischen Offline-Produktions-Core-Lauf,
keinen vollständigen beobachteten Offline-GUI-Rundlauf. Die tatsächlichen
GUI-Nachweise bleiben unabhängig erhalten. Diese
Präzisierung betrifft die Testmethodik und schwächt weder Produktfunktion,
Passwort-/PIN-Regeln noch Offline-Pflicht ab. Der gescheiterte äußere
Seatbelt-Versuch bleibt als eigener Prüfprofilbefund dokumentiert; die
produktinterne ZPAQ-Sandbox wird nicht abgeschaltet.

## Letzte funktionale Ausführung gegen die finale Installation

Nach allen GUI-, Installations-, Offline- und Registrierungsarbeiten wird
der unveränderte reguläre Starter `tools/Test-KeepVault.sh` mit frischem,
verifiziertem SDK, frischem Restore/Build und den exakt installierten
signierten Nativebytes ausgeführt: `KEEPVAULT_TEST_RELEASE_ROOT=/Applications`,
`--performance --only performance.paranoia-complex-tree-e2e --parallel 1`.
Der Lauf besteht mit Exitcode 0, einer von einer Gruppe, null Fehlern und
null blockierten Gruppen in 70,532 Sekunden. Mit Paranoia, Kompressionsstufe 5
und vollständigem Produktions-Argon2id werden 18 Dateien, 20 Verzeichnisse
und 221.327.790 Bytes archiviert, eine beschädigte KPAR2-Einheit repariert,
entschlüsselt und entpackt. Verzeichnisstruktur, Pfade, Größen und SHA-256
stimmen vollständig. Auch hier sind die Test-Samples zur Faktorgeneration
synthetisch und keine behauptete menschliche Entropie.

`final-installed-test-summary.json` hat SHA-256
`a0b750d8fce5ba12cbc76706bd5e2e6686b9abfd3df4ed4ecef8b20f4852268e`.
`final-installed-test-evidence/results.json` hat SHA-256
`905fff24578fa1db1ae3ae0019c712b5705429f644e386bfdf85d9a37fb28f96`.
Das vollständige Protokoll ist `final-installed-complex-paranoia.log`.
`source-after-last-functional.json` bestätigt 1.320 unveränderte Eingaben,
`matchesPrevious = true` und keine Änderungen. Die anschließende rein lesende
Prüfung `final-after-last-test-readonly.json` besteht: installierte App-Bäume,
Sidecars und root-eigener ZPAQ-Anker passen weiterhin zum endgültigen Paket;
nur die kanonische Haupt-App ist installiert und registriert, null zusätzliche
Registrierungen. Danach folgen ausschließlich Dokumentation, unverändernde
Quell-/Paket-/Git-Prüfungen, Commit, Tag und Veröffentlichung derselben Artefakte.

## Technische Abnahme und Veröffentlichungsvorbereitung

| Prüfung | Status |
| --- | --- |
| Frischer Testbuild und integrierte Testmenge | neuer de8618-Kandidat 153/153 bestanden, 396,2 s Gesamtlaufzeit, 910,3 s summiert, 0 Fehler, 0 blockiert; früherer c4d7-GUI-Fehler bleibt historisch |
| DE/EN-GUI, Minimalgröße und Auswahlregeln unter äußerer Netzsperre | frühere Versions-/Regelfenster und negative Auswahlfälle geprüft; finale installierte GUI PID 56850 besteht DE/EN-Version, PIN 6–16, Integrität und Archivpfadplatzhalter, danach Deutsch wiederhergestellt und beendet |
| Vollständiger Offline-Produktionslauf ab frischem Prozess mit lokalen Modelldaten | bestanden in 79,562 s: 18 Dateien, 20 Verzeichnisse, 221.327.790 Bytes und eine KPAR2-Reparatur; 77 periodische Offline-Messungen, positive IPv4-/IPv6-Kontrollen davor/danach, WLAN wiederhergestellt, Watchdog nicht ausgelöst; getrennte Core-/GUI-Nachweise, kein Offline-GUI-Claim |
| GUI-Entpacken ohne Archivierungs-Auswahlregeln | leere Eingaben sowie unverändertes 262-Codeeinheiten-Passwort mit 17-stelliger PIN an eingefrorenen Fixtures bytegenau bestanden |
| Neues GUI-Testarchiv, Entpacken und vollständiger Struktur-/Datenvergleich | im Development-Kandidaten ohne zusätzliches äußeres Prüfprofil bestanden; fünf Dateien, 15 Verzeichnisse, 34.832.501 Bytes |
| Geprüfte Originallöschung im neuen GUI-Archivlauf | fünf Dateien nach integriertem Bytevergleich entfernt; Verzeichnisse und separate Kontrolldatei unverändert |
| PDF-Ausgabe der verworfenen ersten Faktorgeneration | vier Seiten und sechs QR-Codes bestanden; kein Archiv- oder Papierdrucknachweis |
| Direkter Papierdruck über Keep Vault für das neue erfolgreiche Testarchiv | beide Aufträge abgeschlossen; Papierausgabe und tatsächliche Kameraerkennung/Kopieren des gedruckten Faktors A bestätigt |
| Kryptografische Löschung über die GUI | Negativfälle und Kopielöschung mit unveränderten Originalen bestanden; korrigierter Abschlussstatus unter PID 34669 nach OK und DE/EN/DE dauerhaft erhalten, neuer Pfad setzt Status und Bestätigung zurück; alle vier Pfadplatzhalter sichtbar DE/EN bestanden |
| Überarbeitete Schlüsselzettel DE/EN mit Versionsnummer, drei Passwortzeilen und PIN-Hinweis | vier echte Service-PDFs erzeugt, acht Seiten visuell geprüft; korrigierte Gestaltung ausdrücklich freigegeben |
| Installationsanleitung und Paketinhalt | neuer de8618-Installer: drei echte GUI-Negativfälle bestanden, je 129 installierte Einträge unverändert, deutsche Paketmeldung visuell vollständig lesbar; normale tatsächliche GUI-Installation PID 37155 mit vollständig lesbarer Abschlussmeldung bestanden; beide Apps, zehn Sidecars und root-eigener ZPAQ-Anker bytegleich mit dem endgültigen Paket |
| Erststart mit durch App Translocation getrennten Paketdateien | tatsächliche GUI-Gegenproben zu unvollständigem Ordner und Ordnerabbruch bestanden; separate Ordnerauswahl belegt keine tatsächliche App Translocation; normale GUI-Installation und positiver separater Ordnerauswahl-Lauf PID 46797 bestanden; tatsächliche App Translocation nicht belegt |
| Installer-Verzeichnisbindung und Meldungsdarstellung | 19 Regressionen mit wirksamer Mutationsgegenprobe sowie 18 Darstellungsfälle und synthetische DE/EN-GUI bestanden; normale tatsächliche GUI-Installation und vollständig lesbare kurze Abschlussmeldung bestanden |
| Zusätzliche einzelne Releaseprüfungen | neuer de8618-Kandidat: alle sechs zusätzlichen Einzelprüfungen bestanden |
| Manuelle Cipher- und Paranoia-Produktionsmessungen | neuer de8618-Kandidat bestanden: Performance-Matrix 196,1 s, 256 MiB 81,8 s, komplexer Paranoia-Baum 75,4 s; 18 Dateien, 20 Verzeichnisse und eine KPAR2-Reparatur |
| Developer ID, Apple Accepted, Stapling, Gatekeeper und Bytevergleich | neuer Apple-Job de8618c3-7404-4b7f-b35e-591fd5fd92c2 Accepted und an ZIP sowie 38 ursprüngliche Slices gebunden; Stapling, Gatekeeper aller drei Apps, 38 unveränderte Slices und sechs finale Assets bestanden; 149 Manifest-Einträge und ZIP/Sidecars auf arm64 und x86_64/Rosetta verifiziert; c4d7 bleibt historisch |
| Finale Installation und nur aktuelle Keep-Vault-Registrierung | beide tatsächlichen Installationswege erfolgreich; 21 zusätzliche eigene Registrierungen gezielt entfernt, danach genau eine kanonische Haupt-App und null zusätzliche Registrierungen; unabhängiger Scan aller 82 unmittelbaren App-Bundles bestätigt genau Keep Vault 5.0.2/13 unter /Applications |
| Letzter komplexer Paranoia-Struktur-/Reparaturlauf | regulärer unveränderter Teststarter, frischer Build gegen finale Installation, Exit 0, 70,532 s, 18 Dateien, 20 Verzeichnisse, 221.327.790 Bytes und eine KPAR2-Reparatur; danach 1.320 Quellen unverändert und nur kanonische Haupt-App registriert |
| Geprüfter Commit, Tag, Uploaddigests und öffentliche Freigabe | nach dieser abgeschlossenen technischen Abnahme auszuführen und separat zu bestätigen; vorgesehene Veröffentlichung v5.0.2 stable/latest mit genau sechs geprüften Assets |

Nach dem letzten funktionalen Gate erfolgen ausschließlich unverändernde
Paket-/Git-Prüfungen, Ergebnisdokumentation und Veröffentlichung derselben
Artefakte. Eine Produkt- oder Artefaktänderung erfordert diesen Gate erneut.

## Nachweisgrenzen

Ein bestandener Testkorpus bestätigt die geprüften Eigenschaften und Fälle.
Er beweist weder Fehlerfreiheit noch garantierte Entropie menschlich gewählter
Geheimnisse. Quellen-Snapshots erfassen beobachtete Datei-/Modusänderungen;
sie sind kein privilegiert unveränderlicher Buildbaum und schließen einen
vorübergehenden Austausch durch denselben Benutzer nicht aus. Die signierten
Endartefakte werden zusätzlich unabhängig geprüft.

Windows wird anhand des [aktualisierten Portierungsvertrags](KEEP_VAULT_V12_WINDOWS_UPDATE.md)
später auf Windows-Hardware geprüft. macOS-Ergebnisse sind kein Windows-Test.
