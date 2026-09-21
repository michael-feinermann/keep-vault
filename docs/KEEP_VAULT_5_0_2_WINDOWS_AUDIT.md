# Keep Vault 5.0.2 – Windows-Prüfbericht

Arbeitsstand vom 21. September 2026. Dieser Bericht wird um die tatsächlichen
Windows-Läufe ergänzt; offene Prüfungen sind keine bestandenen Freigaben.
Der verbindliche Windows-Arbeitsordner ist seit der ausdrücklichen Korrektur
des Benutzers `C:\Dev\Kalyna`. Entwicklung und Builds in OneDrive sind verboten.
Neue Release-Snapshots liegen unter `work\release-builds` dieses lokalen
Repositories. Frühere OneDrive-/Profilpfade in Prüfprotokollen sind historische
Nachweise und keine aktuelle Arbeitsanweisung.
Die GitHub-Regel steht auch im Hauptbranch in `AGENTS.md`. Am 15. September
wurde die Korrektur des Codex-App-Server-Projekteintrags auf `C:\Dev\Kalyna`
bestätigt. Der Desktop zeigt am 21. September seinen alten Legacy-Projekteintrag
weiterhin mit dem historischen OneDrive-Pfad. Der dafür vorgesehene Helfer ist
nicht mehr aktiv; seine alte Statusdatei ist kein Abschlussnachweis. Sämtliche
Entwicklung und Ausführung erfolgt ausdrücklich unter `C:\Dev\Kalyna`.
Der Snapshot-Regressionslauf bestätigt sowohl
die Ablehnung persönlicher, geschäftlicher und benutzerdefinierter OneDrive-
Pfade als auch die Ablage aller neuen Snapshots unter dem aktiven Repository.
Die verbindliche GUI-Referenz ist der veröffentlichte macOS-Tag `v5.0.2` bei
`8df29a9e13eb65c0769666c3835b4cf0b96dad20`. Seine UI-Quellen sind gegenüber
dem zuvor geprüften macOS-Stand `7ff2eda764ad321ed25c88f862ee20a8a9822690`
unverändert. Der bestehende öffentliche Tag
`v5.0.2` gehört zum macOS-Commit und wird durch die Windows-Ergänzung nicht
verschoben. Die sechs vorhandenen macOS-Dateien bleiben unverändert.

## Aktueller Freigabestatus

**Noch kein freigegebener oder veröffentlichter Windows-Release.** Der vollständig
signierte Kandidat `c5e9e192bab7768f6544cb766c1987c60706b110` besteht Build,
Signatur-/Paketprüfung und EXE-Abnahme. Die vollständige Funktionssuite meldet
60 bestandene und drei fehlgeschlagene Gruppen: Alle drei Fehler betreffen die
nun ausdrücklich abgewiesenen leeren GUI-Renderings vor dem Neustart des
Desktop-Automationshelfers. Der ruhige Performance-Lauf scheiterte erneut.
Die tatsächliche Installation über Windows Explorer und der Start der
Hauptanwendung über die Desktop-Verknüpfung bestanden inzwischen. Weitere
GUI-Prüfungen laufen; vollständige Performance-/GUI-Freigabe und Veröffentlichung
bleiben offen. Neue Änderungen an Messmethodik und Fehlerbereinigung benötigen
einen neuen vollständigen Build und die dazugehörige Abnahme.

Der geprüfte Snapshot liegt unter
`C:\Dev\Kalyna\work\release-builds\c5e9e192bab7-48eeae7c256c4873\src`.
Paket und ZIP liegen dort unter `dist\Keep Vault-portable-win-x64` beziehungsweise
`dist\Keep Vault-portable-win-x64.zip`. Die nachstehenden Pfade zu Protokollen
sind relativ zum kanonischen Repository `C:\Dev\Kalyna`.

| Freigabeschritt | Belegter Stand am 21. September für `c5e9e19` |
| --- | --- |
| Vollständiger signierter Build | PASS, 20:06:27–20:10:03 Ortszeit, SDK `10.0.401`; frischer Native-Satz, selbständige Programme, tatsächliche Setup-Prüfung vor und nach frischer ZIP-Extraktion |
| Unveränderliche Quellen | 1380 Quell-Inputs; Vorher-/Nachher-Hashes bei Build und unabhängiger Abnahme unverändert |
| Funktionstests | 60/63 Gruppen bestanden, darunter native KATs, Container-, Reparatur- und Kompatibilitätsprüfungen; drei GUI-Gruppen scheitern ausschließlich an leeren Renderings, Gesamtstatus FAIL |
| QR-Scanner | 151 Prüfungen im tatsächlichen Release-Build bestanden |
| Fertige EXEs und Manipulationsabwehr | 36/36 Fälle, 70/70 tatsächlich gestartete und abgewartete Verifier-/Setup-Aufrufe bestanden |
| Signaturen und Paketbestand | 13 Paket-PEs plus identischer externer Verifier geprüft; 12 externe Assets, 80 inventarisierte Dateien plus Inventar/Signatur und 82 ZIP-Dateien stimmen überein |
| Performance | FAIL, 20:29:51–20:34:46 Ortszeit: ein Produktionsslot erreicht 297,2 MiB/s, bester Vergleich 341,2 MiB/s mit acht Slots (87,1 %; gefordert mindestens 90 %) |
| GUI-Rendergruppen aus der Vollsuite | FAIL vor Neustart des Automationshelfers: `gui.installer-reference`, `gui.v502-reference-parity` und `gui.reference-render` weisen vollständig transparente Bilder korrekt zurück; Wiederholung offen |
| Tatsächliche Installation und Desktop-Start | PASS über regulären Windows Explorer; 82 Dateien installiert, Hauptfenster durch echte Desktop-Verknüpfung gestartet, Integritäts- und Aufnahmeschutz aktiv |
| Weitere GUI, Startmenü-Verknüpfungen, Papier/Kamera | Weitere interaktive GUI-Prüfungen laufen; noch keine vollständige Abnahme |
| Veröffentlichung und Download-Abgleich | Nicht erfolgt; vorhandener macOS-Tag und sechs macOS-Assets bleiben unverändert |

Die EXE-Abnahme prüfte das Originalpaket, eine vollständige Kopie, das signierte
ZIP, eine frische ZIP-Extraktion und eine echte `--test-copy`-Installation in ein
neues Testverzeichnis. Manipulierte oder fehlende Dateien/Signaturen, zusätzliche
Dateien/Verzeichnisse, Junctions, Aliaswege und Hardlinks wurden abgewiesen.
Vorhandene Installationsziele, Originalpaket, alle sechs ZIP-Dateien,
Kontrollprogramme, Benutzerverknüpfungen und Quell-Snapshot blieben unverändert.
Manipulierte EXEs wurden niemals ausgeführt. Das prüft die Kopier- und
Verifikationspfade. Der danach separat geprüfte interaktive Setup-/Desktop-Start
ist unten abgegrenzt.

Die vollständige Funktionssuite lief von 20:10:42 bis 20:29:22 Ortszeit.
Das Systemereignisprotokoll belegt Standby von 20:10:49 bis 20:25:58; dadurch
verlängerte Einzelzeiten sind keine Performance-Messung. Aus diesem Lauf werden
keine Leistungsaussagen abgeleitet. Nach Ende von Funktionssuite und EXE-Abnahme
wurde um 20:29:51 ein eigener ruhiger Performance-Lauf gestartet. Dieser brach
an der Pipeline-Skalierungsgrenze mit 87,1 Prozent ab; die anschließende
256-MiB-Gruppe wurde nicht erreicht. Der separate finale Reparaturlauf steht
ebenfalls aus.

Ein isolierter Diagnoselauf derselben Skalierungsfunktion erreichte später
92,6 Prozent (345,1 gegenüber 372,7 MiB/s). Er lief ohne die vorausgehenden
Primitiv-/Container-Matrizen und zählt ausdrücklich nicht als Release-PASS.
Die überprüfte neue Messmethodik verwendet ein vollständiges Aufwärmen pro
Kandidat und fünf vorab festgelegte, durchmischte Messrunden. Sämtliche Kandidaten
und Messwerte sowie die 90-Prozent-Grenze bleiben erhalten; kein Ergebnis wählt
einen zusätzlichen Versuch oder verwirft einen Messwert. Ein vollständiger
Release-Lauf mit dieser Änderung steht noch aus.

Die neue Render-Schutzprüfung besteht zehn synthetische Fälle. Sie weist die
acht leeren Bilder des Vorgängers `c3658b8` und die drei nun tatsächlich
fehlgeschlagenen GUI-Gruppen zurück; frühere nichtleere Bilder ersetzen keine
visuelle Abnahme des aktuellen Kandidaten. Die früheren
`GetCursorPos`-/`0x80070005`-Fehler betrafen einen nach dem Systemstandby veralteten
Sky-/Node-Automationshelfer. WTS bestätigte `UNLOCKED`; nach dessen Reset waren
tatsächliche Eingaben wieder möglich. Eine gesperrte Sitzung ist damit kein
aktueller Blocker mehr. Die fehlgeschlagenen Rendergruppen werden durch den
späteren Eingabenachweis nicht rückwirkend bestanden.

Die interaktive Setup-Prüfung wies zunächst zwei vorhandene Benutzerverknüpfungen
korrekt zurück. Diese wurden anschließend mit Hash-Receipts reversibel unter
`work/gui-acceptance-c5e9e19-20260921/previous-shortcuts` gesichert. Ein aus dem
Codex-Prozess gestarteter Installationsversuch scheiterte danach korrekt an
einer geerbten MSIX-Umleitung der neuen Startmenü-Datei. Der Alias-Schutz wurde
nicht gelockert. Beim regulären Start aus der Windows-Explorer-Dateiliste
bestand die Installation anschließend nach
`C:\Users\Michael\AppData\Local\Programs\Keep Vault\5.0.2-6814D3122DC0-66df7cae`
mit 82 Dateien. Der tatsächliche Desktop-Verknüpfungsstart öffnete die
Hauptanwendung; Integrität und Aufnahmeschutz zeigten aktiv. Weitere GUI-Abläufe
werden noch geprüft.

Der gescheiterte umgeleitete Versuch belegte außerdem einen kleinen
Aufräumfehler: Eine bereits mit `CREATE_NEW` erzeugte, danach bei der
Pfadvalidierung abgewiesene Datei konnte leer zurückbleiben. Die Korrektur
entfernt nur dieses selbst erzeugte Objekt über den durchgehend gehaltenen
DELETE-Handle; bestehende Objekte und die Aliasprüfung bleiben unverändert.
Fünf synthetische NTFS-Fälle reproduzieren den alten Restdateifehler und bestehen
nach der Korrektur. Der unabhängige Review ist bestanden; diese Änderung ist
noch nicht Bestandteil des signierten Kandidaten `c5e9e19`.

Nachweise:

- `work/production-release-20260921-200627/result.json` und `build.log`.
- `work/final-suite-full-20260921-201042/result.json`, `group-1.json` und `group-1.log`.
- `work/release-executable-acceptance-20260921T181046Z-7bb8c35def45418b8b0742702ca13373/summary.json`, `results.json`, `provenance.json`, `preservation.json` und die 70 Prozessprotokolle.
- `work/final-release-policy-20260921T181043Z-d3b9e40d00804472a778481da0b6a995/result.json` und `work/release-bundle-metadata-c5e9e19`.
- `work/final-suite-performance-20260921-202951/result.json` und `group-1.json` (`FAIL`).
- `work/pipeline-diagnostic-c5e9e19-20260921/result.json`, `run.log` und `methodology-static-review.json` (Diagnose, keine Release-Freigabe).
- `work/render-guard-verification-20260921/result.json`.
- `work/wts-session-lock-query-20260921/result.json` und `work/gui-acceptance-c5e9e19-20260921/result.json` (weitere GUI-Abnahme noch `IN_PROGRESS`).
- `work/bound-create-cleanup-20260921/provenance.json`, `before-run.log` und `after-run.log`.

Der ZIP-SHA-256 dieses noch nicht freigegebenen Kandidaten lautet
`F29B5F9D38893B363E98045BCA75924D5629FADF456728DFBE7B53B09D557CBB`;
sein SHA-512 ist
`43D0E41A55C33AEA8CF009C504083AD69C1115F3EA3CA883D3E5C84019250772F1135F9A1070B9CB03DA7AAF6AE3039B0B8CBB157EC3E197D061A87D5304B129`.
Ein späterer Neubau erhält eigene Hashes und eigene Freigabenachweise.

### Vorläufe am 21. September

Am 21. September bestanden auf dem festgehaltenen Quellstand `bb37a80` alle
sechs verwalteten Build-/Publish-Schritte sowie 16 verwaltete Testgruppen.
Die QR-Scanner-Prüfung bestand mit 151 Tests. Die Dialogprüfung umfasst sechs
echte modale DE/EN-Lebenszyklen; die PDF-/Druckbestätigung akzeptiert nur ein
ausdrückliches Ja. Diese verwalteten Build-Ausgaben enthalten absichtlich keine
Vault-Native-Dateien und sind keine veröffentlichbaren Releasepakete.

Ein neuer regulärer nativer Einzelbuild desselben Quellstands bestand am
21. September von 19:13:25 bis 19:14:12 unter aktivem Bitdefender 30.0.33.163
mit Antivirus-Update 77834. Alle zehn Ausgaben blieben vorhanden; ihre Hashes
waren auch um 19:22:46 unverändert. x64, erforderliche Exporte, ASLR, DEP,
CFG und CET wurden statisch geprüft. Der neue `kalyna_v12.dll`-SHA256 lautet
`C7FA0A8662E17554CB40FFFDA98CA60B17480590044E2F1F71080A1161ACA253`.
WSC meldete vor und nach dem Build Bitdefender ON/UP_TO_DATE. Der Build hatte
33 Iterator-Deprecation- und fünf beabsichtigte `/Fo`-Override-Diagnosen, keine
Fehler. Das ist ein frischer Build-/Retention-/Static-Nachweis; ein ausdrücklicher
Bitdefender-Scan und eine Herstellerbewertung der historischen Erkennung sind
dadurch nicht behauptet. Keine quarantänisierten Bytes wurden wiederhergestellt
oder wiederverwendet. Dieser Einzelversuch führte keine nativen Produkte aus.
Der ältere, unabhängige GitHub-Defender-Scan ist unten getrennt dokumentiert.

Der signierte Durchlauf auf `558939a` erzeugte am 21. September zwar ein
vollständiges Paket und meldete Exit 0, wurde aber durch die anschließende
Black-Box-Abnahme als **nicht freigabefähig** erkannt: Die eigenständig
veröffentlichte Setup-EXE konnte `BouncyCastle.Cryptography` nicht laden.
Der fehlende direkte Projektverweis auf die tatsächlich verwendete
Signierbibliothek wurde im Installer ergänzt; ein isolierter self-contained
Publish akzeptierte danach das unveränderte signierte Paket und lehnte eine
manipulierte Kopie ab. Die Paket-/Versions-/Zeitstempelprüfung selbst bestand
auf allen 13 Paket-PEs und wurde nicht gelockert.

Zusätzlich wartete PowerShell bei den bisherigen WinExe-Aufrufen nicht
zuverlässig auf deren Abschluss und konnte einen älteren `$LASTEXITCODE`
weiterverwenden. Die Release-Gates starten Prozesse nun ausdrücklich mit
`ProcessStartInfo`, lesen beide Ausgabekanäle, warten begrenzt und prüfen den
Exitcode genau dieses Prozesses. Acht echte synthetische WinExe-Regressionen
bestanden, darunter verzögerte Erfolge/Fehler, Argumente, gefüllte Pipes und
Timeout mit nachgewiesenem Prozessende. Für `558939a` bestanden separat alle
62 Windows-Funktionsgruppen und die aktuelle NuGet-Abfrage aller acht
Windows-Projekte meldete keine bekannten direkten/transitiven Schwachstellen.
Der Performance-Lauf scheiterte an der Pipeline-Skalierungsgrenze; wegen
paralleler Diagnosearbeiten ist ein kontrollierter Lauf auf ruhigem Host nötig.
Die korrigierte signierte Ausgabe `c3658b8` bestand anschließend 62/62
Funktionsgruppen sowie 36/36 Fälle mit 70/70 EXE-Aufrufen. Die acht dabei
erzeugten Hauptfenster-PNGs waren jedoch leer und zählen nicht als visuelle
Freigabe. Der erneute ruhige Performance-Lauf von 19:52:32–19:57:35 blieb rot:
Die Produktionspipeline mit acht Slots erreichte 269,3 MiB/s gegenüber
387,0 MiB/s mit einem Slot (69,6 %). Belege liegen unter
`work/final-suite-full-20260921-194827`,
`work/release-executable-acceptance-20260921T174859Z-05b372d0b9244885abb776d0a451c042`
und `work/final-suite-performance-20260921-195232`.
Darauf folgten die Windows-Slotkorrektur und die Render-Schutzprüfung im neuen
Kandidaten `c5e9e19`; dessen aktueller Status ist oben abgegrenzt.

### Historischer Abbruch am 15. September

Die folgenden Angaben dokumentieren den damaligen Abbruch; sie gelten nicht
als aktueller Fehlbestand des am 21. September vollständig gebauten Kandidaten.

Der geprüfte Implementierungsstand wurde am 15. September als
[`e27699ff1495c836088f1b1bd22eef19018b748d`](https://github.com/michael-feinermann/keep-vault/commit/e27699ff1495c836088f1b1bd22eef19018b748d)
committet und auf `codex/windows-v12-5.0.2` gepusht. Die Remote-Commit-ID wurde
anschließend zurückgelesen. Private Schlüssel, unvollständige native
Arbeitskandidaten und die Löschung der quarantänisierten DLL sind nicht Teil
dieses Commits. Der vorhandene öffentliche macOS-Release wurde nicht verändert.

Der anschließend regulär gestartete `Build-Portable.ps1` verwendete einen
unabhängigen, während des Builds gegen Änderungen gehaltenen Quell-Snapshot
dieses Commits und SDK `10.0.401`. Die Quellprüfungen bestanden; alle zehn
nativen Komponenten wurden frisch kompiliert. Die Signierung von
`mldsa87_ref.dll` und `zpaq.exe` einschließlich Hybridprüfung und Zeitstempel
bestand. Beim nächsten Ziel `kalyna_v12.dll` brach die Signierung mit einer
Dateisperre ab. Eine rein lesende Windows-Restart-Manager-Abfrage identifizierte
`Bitdefender Virus Shield` / `VSSERV` als Halter.

**Am 15. September 2026 um 18:54:19 Ortszeit wurde auch dieser neue Build als
`Gen:Variant.Lazy.491499` quarantänisiert.** Die Quarantänemetadaten nennen
ausdrücklich den neuen Snapshot-Pfad und den 573440 Byte großen Native-Build.
Der dort gespeicherte 64-stellige Hashwert lautet
`FBFA0A157A779EE0E558DD2AC3A32977B232215371B4162ACEC8D74E9CF0A432`;
er konnte wegen Sperre und anschließender Quarantäne nicht unabhängig aus der
DLL neu berechnet werden. Die Datei fehlt inzwischen am Buildpfad. Der
vollständige Build endete mit Exitcode 1, bevor Native-Funktionstests, Publish,
Installerprüfung und ZIP-Erzeugung erreicht wurden. Es gab keinen weiteren
Neubau zur Umgehung der Erkennung und keine Änderung der Schutzfunktionen.

| Freigabeschritt | Stand nach dem Lauf vom 15. September |
| --- | --- |
| Implementierung und macOS-Referenzabgleich | Im gepushten Quell-Commit enthalten; Umfang und GUI-Grenzen unten |
| Fehler-/Sicherheitskorrekturen | Implementiert; abgegrenzte Regressionen bestanden |
| Unsignierter nativer GitHub-Build mit aktivem Defender | Alle zehn Komponenten und der belegte Custom-Scan bestanden; eigener, begrenzter Nachweis |
| Vollständiger signierter Build | Blockiert durch erneute Quarantäne |
| Vollsuite, Performance und finale Archiv-/Reparaturläufe | Nicht ausgeführt mit einem vollständigen finalen Native-Satz |
| GUI | Fünf verwaltete GUI-Gruppen, Scannerprüfungen und 16 Renderings bestanden; finale installierte GUI und Papier/Kamera offen |
| Commit und Push | Implementierungs-Commit auf GitHub bestätigt |
| Windows-Veröffentlichung | Nicht erfolgt |

### Neue Windows-Identität am 21. September

Bei der Wiederaufnahme am 21. September war der externe Schlüsselordner
`A:\Keep Vault ReleaseKeys v12` nicht erreichbar. Auch der genaue Ordnername
an den Wurzeln der angeschlossenen Laufwerke wurde nicht gefunden; es fand
keine rekursive Suche nach Schlüsselmaterial statt. Der Benutzer beauftragte
daraufhin ausdrücklich eine neue, lokal unter Windows geschützte Identität
und eine spätere Übertragung. Die Windows-Identität ist vom macOS-Release
getrennt; Verfahren und Exportweg stehen in `WINDOWS_RELEASE_KEYS.md`.
Die neue RSA-4096/ML-DSA-87-Identität wurde am 21. September erfolgreich
erzeugt und mit beiden Signatur-Roundtrips geprüft. Zertifikat-Thumbprint:
`7BA65B5130F34AB9F15C0D074699D46D9BCCD21C`. Die privaten Dateien liegen
außerhalb Git/OneDrive in einem ACL-geschützten direkten Benutzerordner;
AES-256-GCM-Hüllschlüssel sind an den Windows-Benutzer gebunden durch DPAPI.
74 synthetische Speicher-/Kryptografieprüfungen und 46 öffentliche
Policy-/Parameter-/MSBuild-Prüfungen bestanden. Ein realer Testfehler durch
AppData-Virtualisierung wurde behoben: umgeleitete Ordner werden jetzt vor
der Erzeugung von Geheimnissen abgelehnt. Ein portabler Produktionsexport
wurde nicht erstellt; der spätere Exportweg wurde nur mit Testschlüsseln geprüft.
Die öffentlichen Bestandteile sind in `WindowsRelease/Signing` committet;
der Produktionsnachweis liegt in `work/windows-release-key-receipt-20260921.json`.
Private Dateien sind weder Bestandteil des Repositories noch der Release-Assets.

### Historische Antimalware-Befunde

Bitdefender hat am 9. September 2026 um 12:35:59 Ortszeit die frisch kompilierte
Datei `tools/kalyna_v12.dll` als `Gen:Variant.Lazy.491499` quarantänisiert.
Der in der Quarantänemetadatei protokollierte SHA-256 lautet
`EB9C783FBC418880F0FB1B9B9ACD871731959A2BC55AAC070AC880410EA24BA1`
(573440 Bytes). Die Erkennung ist ungeklärt. Ein Vergleich der einschlägigen
Crypto++-Quellen mit dem festen Upstream-Tag `CRYPTOPP_8_9_0` ergab nur die
dokumentierte Apple-Anpassung in `cpu.cpp`; das ist kein Nachweis, dass die
erkannte Binärdatei sicher ist. Es wurde keine Ausnahme eingerichtet, keine
Quarantänedatei wiederhergestellt und kein Antimalware-Schutz verändert.

Nach dem erneuten Fund wurde das vollständige offizielle Crypto++-8.9.0-
Quellarchiv heruntergeladen und sein SHA-256 gegen den bereits dokumentierten
Wert `ab5174b9b5c6236588e15a1aa1aaecb6658cdbe09501c7981ac8db276a24d9ab`
geprüft. Alle 684 im Repository enthaltenen Dateien wurden verglichen:
673 sind bytegleich, zehn unterscheiden sich ausschließlich in Zeilenenden,
und nur `cpu.cpp` enthält die dokumentierte Apple-spezifische Anpassung.
Es gibt keine zusätzlichen lokalen Dateien in diesem Vendor-Bestand.
Dieser umfassendere Herkunftsnachweis umfasst auch beide Windows-MASM-Quellen.
Er klärt die konkrete Antimalware-Erkennung des erzeugten Binärprogramms nicht.
Der Benutzer teilte anschließend mit, Bitdefender sei ausgeschaltet;
dies wurde nicht als bestandene Sicherheitsprüfung gewertet.

Ohne diese Bibliothek waren die vollständige Kryptografie-, Archiv- und
Installationsprüfung sowie der finale Release-Build damals blockiert. Die neun
übrigen signierten Arbeitskandidaten ersetzten keinen vollständigen frischen
Satz. Der reguläre Neubau vom 21. September und der oben dokumentierte signierte
Kandidat enthalten wieder alle erforderlichen Komponenten. Das erklärt die
historische Erkennung anderer Bytes weiterhin nicht.

### Unabhängiger geschützter Build auf GitHub

Der zusätzliche Workflow `Windows native Defender evidence` aktiviert den
Microsoft-Defender-Schutz ausschließlich auf einem kurzlebigen GitHub-Runner,
bevor der Checkout erfolgt. Er entfernt dort die voreingestellten Ausnahmen,
verlangt aktive Schutzfunktionen, Normalmodus, aktuelle Definitionen und eine
leere aktuelle Erkennungsliste. Er führt keine erzeugte Produkt-DLL/EXE aus,
verwendet keine Release-Schlüssel und lädt ausschließlich Text-/JSON-Nachweise
hoch. Diese Prüfung hebt die offene Bitdefender-Erkennung nicht auf.

Der erste Lauf
[`35003540412`](https://github.com/michael-feinermann/keep-vault/actions/runs/35003540412)
bestand die Schutzvorprüfung, scheiterte aber vor der nativen Kompilierung:
Windows Server 2022 unterstützt den zusätzlich verwendeten System-SHA3-Aufruf
nicht. `Verify-MldsaReference.ps1` prüft nun unabhängig davon jeden portablen
SHA3-Fingerprint gegen den unveränderten Quellenpin. Wo die Plattform SHA3
unterstützt, bleibt deren zusätzliche Gegenprüfung erhalten. Der unabhängige
SHA-256-Vergleich und alle Skein-Pins bleiben verpflichtend. Sechs synthetische
Positiv-/Manipulationsfälle mit dem tatsächlichen Skript bestanden.

Im zweiten Lauf
[`35004359038`](https://github.com/michael-feinermann/keep-vault/actions/runs/35004359038)
bestanden Quellenprüfung und frische Kompilierung aller zehn nativen Komponenten
einschließlich `kalyna_v12.dll` mit MSVC `19.44.35228`. Defender war vor und nach
dem Build aktiv, seine aktuelle Erkennungsliste blieb leer. Der Job scheiterte
anschließend am geforderten Zusammenhang zwischen Scan-Start, Pfad, Scan-ID und
Abschlussereignis. Dieser Lauf ist daher kein bestandener Scan. Die Diagnose
speichert inzwischen auch auf diesem Fehlerpfad sämtliche abgefragten Ereignisse
mit Original-XML, Schutzstatus und Dateihashes; die Annahmekriterien bleiben gleich.

Der dritte Lauf
[`35005426526`](https://github.com/michael-feinermann/keep-vault/actions/runs/35005426526)
lieferte beide Custom-Scan-Ereignisse mit gleicher Scan-ID, unveränderte Hashes
aller zehn Dateien und keine Erkennung. Der Job blieb rot, weil Defender den
Verzeichnispfad als `folder:_D:\...` meldet. Der korrigierte Prüfer entfernt nur
dieses beobachtete Präfix im Feld `Scan Resources` und verlangt weiter den
exakten Einzelpfad sowie geordnete Ereignisse 1000/1001 mit gleicher Scan-ID.
Der Replay der Originalereignisse belegt die frühere falsche Ablehnung und den
korrigierten Erfolg; neun manipulierte Ereignisfälle werden weiterhin abgewiesen.
Auch die 41 Schutz-/Inventarprüfungen und fünf Diagnose-Fehlerpfadfälle bestehen.

**Der abschließende Lauf
[`35006246507`](https://github.com/michael-feinermann/keep-vault/actions/runs/35006246507)
für exakt
[`72fd322d950e7eaeba5c367bb54596869e54f5f0`](https://github.com/michael-feinermann/keep-vault/commit/72fd322d950e7eaeba5c367bb54596869e54f5f0)
ist vollständig bestanden.** Alle zehn nativen Komponenten wurden mit
SDK `10.0.401` und MSVC `19.44.35228` frisch gebaut. Die Quellenprüfung bestätigte
433 Vendor-Dateien, drei Windows-Dateien, 202 Crypto++-Übersetzungseinheiten und
21 dreifach gepinnte ML-DSA-Quellen. Defender blieb vor und nach Build/Scan gesund,
im Normalmodus mit Echtzeitschutz und ohne Ausnahmen; Definition `1.459.223.0`
war aktuell. Erkennungshistorie und aktive Bedrohungen waren leer. Das passende
Custom-Scan-Ereignispaar 1000/1001 ist mit Original-XML belegt; alle zehn SHA-256-
und SHA-512-Werte sind vor und nach dem Scan gleich.

Der lokal nachgeprüfte Nachweis liegt unter
`work/hosted-native-defender-35006246507/review-receipt.json`.
Es wurden keine Produktprogramme ausgeführt, keine Release-Schlüssel verwendet
und keine Binärdateien übertragen. Dieser Erfolg betrifft den frischen,
unsignierten CI-Satz. Die Bitdefender-Erkennung anderer, quarantänisierter Bytes
bleibt ungeklärt; vollständiger signierter Release-Build und native Funktions-/
Ende-zu-Ende-Prüfungen werden dadurch nicht ersetzt.

## GUI und macOS-Referenz

Die folgenden früheren Layout-, Komponenten- und Bildprüfungen belegen ihre
jeweiligen Quellstände. Für `c3658b8` meldete die Funktionssuite zwar auch die
GUI-Gruppen grün, ihre acht aktuellen Hauptfenster-PNGs sind aber leer.
`RenderEvidenceGuard` weist solche Ausgaben nun ausdrücklich zurück. Die
Kompilierung und zehn synthetische Schutzfälle bestehen; die neue Schutzprüfung
und die interaktive GUI müssen auf einem aktiven Desktop erneut laufen.
Es gibt damit derzeit keine abschließende visuelle GUI-Freigabe.

Der geschützte WPF-Build fand einen weiteren Buildfehler: Das SDK legt sein
temporäres Markup-Projekt im gesperrten Quellordner an. `Directory.Build.targets`
behält die originale SDK-Task und deren NuGet-/RID-Verarbeitung bei, verwendet
aber einen exakt benannten, vorher erzeugten Ausgabeslot. Dessen Identität
bleibt ab `CREATE_NEW` durchgehend gehalten; die Quellordner werden nicht
für neue Dateien freigegeben. Fünf MSBuild-Schutzfälle und die erweiterte
Snapshot-Regression bestehen. Der geschützte Kandidaten-Build und Rebuild
vom 21. September bestanden mit 1366 unveränderten Quellhashes und geprüftem
eingebettetem Scrollleisten-BAML; dies war noch kein finaler Release-Build.
Der Scanner erhält außerdem seinen vorab angelegten `dist`-Ordner und leert
nur dessen Inhalt. Synthetische Prüfungen bestätigen, dass auch direkte und
verschachtelte Verzeichnisverknüpfungen keine fremden Zielinhalte löschen.
Beim Release-Testbuild bleibt der normale `PublishSingleFile`-Wert erhalten,
damit der unveränderte Paket-Lock nicht durch einen abweichenden Override
ungültig wird; `dotnet build` erzeugt weiter die ausführbare Test-Assembly.

Der letzte Referenzvergleich ergänzt außerdem zwei bisher fehlende
Bestätigungen: den ausdrücklichen Export geheimer Faktoren in getrennte
Test-PDFs und mögliche Kopien im Windows-Druckspooler, Drucker oder
Netzwerk-Druckserver. Die DE/EN-Texte entsprechen der macOS-Referenz mit dem
Windows-Spoolernamen. Beide Faktoren werden vor der Nachfrage validiert;
nur ein ausdrückliches `Yes` erreicht Dateiauswahl oder Druckerauswahl und
Ausgabe. Close/Cancel und andere Rückgaben erzeugen keine Ausgabe oder
Erfolgsmarkierung. Die vorhandene Archivpfadnormalisierung kann davor erfolgen.
Die passenden Regressionen sind in `gui.v502-reference-parity` enthalten;
ihre tatsächliche Ausführung bestand im geschützten `bb37a80`-Testlauf sowie in
der Funktionssuite des Kandidaten `c3658b8`. Das belegt die Handlersemantik;
für die Darstellung gilt die oben genannte Einschränkung.

Die Windows-Oberfläche übernimmt die Referenzstruktur aus `KeepVaultMac`:
1220 × 860 Ausgangsgröße, 980 × 720 Mindestgröße, Hintergrund `#08101D`,
Inter-Schrift mit mitgelieferter Lizenz, Karten, Spalten, Register, Abstände,
Statusanzeige und Zustände für Fokus, Auswahl, Hover und deaktivierte Eingaben.
Die Texte und Ansichten sind auf Deutsch und Englisch vorhanden. Native
Fensterrahmen, Datei-/Druckdialoge und die technische Monospace-Schrift sind
plattformabhängig; eine pixelgenaue Gleichheit sämtlicher Betriebssystemelemente
wird nicht behauptet.

Fünf GUI-Testgruppen bestanden im früheren verwalteten Referenzlauf
unter Runtime `10.0.12`, einschließlich der Installer-Oberfläche.
Darunter werden acht Ansichten aus den tatsächlichen WPF-Produktionskontrollen
gerendert. Dafür wird kein Screenshot-Schutz abgeschaltet. Diese renderbaren
Kontrollen und die automatisierten Handlerprüfungen ersetzen keinen kompletten
interaktiven Durchlauf der final signierten Anwendung.

Auch Installer und Scanner sind an den Referenzablauf angepasst. Der Installer
verwendet native Windows-Kontrollen für Bestätigung, Fortschritt und Ergebnis;
lange Meldungen erscheinen vollständig in einem begrenzten, schreibgeschützten
und auswählbaren Detailfeld. Der Scanner übernimmt 760 × 800, 430 Pixel
Vorschaubereich, einen 120 Pixel hohen Ergebnisbereich mit internem Scrollen
und die Aktionen und Sprachsegmente am unteren Rand. Seine 151 Prüfungen
bestehen mit null Buildwarnungen/-fehlern. Weitere acht DE/EN-Renderings zeigen
kurze/lange Installer-Meldungen und den Scanner bei Standard-/Mindestgröße.
Alle 16 damaligen Haupt-/Installer-/Scanner-Ansichten wurden zusätzlich
unabhängig gesichtet; in diesen Ansichten wurde kein verbleibender konkreter
Darstellungsfehler gefunden. Das ist keine Prüfung aller Hover-, DPI- oder
physischer Kamerazustände.

Der weitere Abgleich der tatsächlichen Meldungen fand noch eine konkrete
Abweichung: Die Hauptanwendung verwendete native `MessageBox`-Fenster statt der
dunklen macOS-Referenzdialoge. Information, Warnung, Fehler und Bestätigung
verwenden nun `Gui/SecurityDialog.cs` mit Referenzfarben, Akzentbalken, Inter,
Abständen und runden Schaltflächen. Der vorhandene dunkle Scrollleistenstil
wird über `Gui/ReferenceScrollBar.xaml` von Hauptfenster und Dialog gemeinsam
verwendet. Lange Meldungen bleiben vollständig lesbar und auswählbar, während
die Schaltflächen sichtbar bleiben. Die bisherige Credential-Testhook- und
`MessageBoxResult`-Semantik bleibt erhalten.

Ein frischer isolierter Managed-Build mit SDK `10.0.401` bestand ohne Warnungen
und Fehler; 209 Eingabehashes blieben während dieses Builds stabil und keine
native Produktkomponente wurde in seine Ausgabe kopiert. Die beiden erneut
ausgeführten Gruppen `gui.v502-reference-parity` und `gui.reference-render`
bestanden. Zwölf Dialogansichten in DE/EN, einschließlich langer Meldungen und
420 × 300 bei 150 Prozent Render-DPI, sowie acht Hauptansichten wurden geprüft.
Sechs echte WPF-`ShowDialog`-Komponententests bestätigten unter Runtime `10.0.12`
den tatsächlichen initialen Tastaturfokus auf Abbrechen, die Sperre und spätere
Freigabe des Elternfensters sowie `No` bei Close/Cancel und `Yes` ausschließlich
bei ausdrücklichem Accept-Button-Event. Der dabei geprüfte App-Assembly-SHA-256
lautet `FFF1DCC9B97AD197925A9A8725DD7CC5B361170246F602E7BEEB6EE345415A78`.

Ein früherer zusätzlicher Bedienversuch über das unterstützte Windows-Automationswerkzeug
konnte die aufnahmegeschützten modalen Fenster nicht zuverlässig adressieren.
Auslesbare Bedienelemente sind kein erfolgreicher Eingabenachweis. Der Schutz
wurde nicht abgeschaltet; dieser Versuch belegte noch keine OS-Eingaben.
Nach dem späteren Reset sind echte Eingaben, die Explorer-Installation und der
Desktop-Start nachgewiesen; die übrigen finalen GUI-Prüfungen laufen noch.

Weitere 14 bewusst ausgewählte verwaltete Gruppen zu Runner/SHA3/Quellabdeckung,
Lokalisierung, Passwortmodell, PIN und technischen v12-Credentialbytes bestanden
im vorherigen isolierten Build desselben Abends. Ihr Test-Assembly-Hash
`6971B3748FCC46DA409857D2C2E27CEA88632C999546E00ACEA2A615A6E4FE18` bleibt von
dem nach den Scrollleisten- und Modaltest-Ergänzungen neu gebauten Testprogramm
getrennt. Dies ist weiterhin eine Teilprüfung und keine volle Kryptosuite.

Die Schlüsselzettel verwenden das Referenzlayout mit getrennten Faktoren A/B,
je zwei identischen QR-Codes, drei PIN-Schreibzeilen und einer separaten
Anleitungsseite. Die vier aktuellen DE/EN-PDFs haben jeweils zwei Seiten.
Eine unabhängige Prüfung mit PyMuPDF und zxing-cpp bestätigt die vorgesehenen
256-stelligen Testfaktoren und alle 24 QR-Payloads in PDF- und Druckrenderings.
Alle dafür verwendeten Faktoren sind ausdrücklich synthetische Testwerte.
Ein tatsächlicher Papierausdruck mit anschließendem Kamerascan ist noch offen.

## Behobene Fehler und Sicherheitsprüfung

- WPF-Eingaben werden vor dem Wechsel in Arbeits-Threads übernommen; direkte
  Zugriffe auf threadgebundene Kontrollen aus den Callbacks sind entfernt.
- Die Erzeugungsrichtlinie für Passwort/PIN bleibt von der technischen
  Entschlüsselungskompatibilität getrennt. Referenzmodelle und eingefrorene
  Kompatibilitätsfixtures behalten durch `.gitattributes` ihre exakten Bytes.
  Zeilenendenkonvertierung hatte zuvor die gepinnten Modellhashes beschädigt.
- Native ZPAQ-Ausgaben werden relativ zu gehaltenen Verzeichnis-Handles neu
  angelegt. Junctions, fremde Vorbelegungen, Namensaliasse und Pfadwechsel
  werden abgewiesen; ergänzende Unicode-Zeichen und Streaming-Metadaten bleiben
  erhalten. Thread-Infrastrukturfehler beenden den Native-Prozess kontrolliert,
  ohne durch noch laufende Worker zurückzuspringen.
- Dateiinspektion hält einen echten Lesezugriff und verhindert konkurrierende
  Schreib-/Umbenennungszugriffe. Mehrdateioperationen und Shortcut-Erstellung
  binden auch den Rollback an die tatsächlich erzeugten Objekte.
- Installerprüfung und -kopie halten Quelle und Ziel während der Übergänge;
  unzulässige Pfade, zusätzliche Dateien, Hardlinks, Reparse Points und
  Änderungen während der Kopie werden abgewiesen.
- Die Native-Quellprüfung kontrolliert 433 Vendor-Dateien, drei zusätzliche
  Windows-Änderungen und die vollständige Menge von 202 Crypto++-Übersetzungseinheiten
  vor dem Build. Leere Pfadsegmente und andere mehrdeutige Einträge werden
  zurückgewiesen.
- Die anschließende Build-Kettenprüfung ergänzt die bisher nicht einzeln
  gepinnten MASM-Dateien `x64dll.asm` und `x64masm.asm`; der aktuelle Vendor-
  Prüfumfang beträgt dadurch 433 Dateien. Die Crypto++-Archivierung verwendet
  eine explizite Liste aus 178 optimierten und zwei separat kompilierten C++-
  Objekten sowie zwei MASM-Objekten. Ein pauschales `*.obj` konnte bei erneut
  verwendetem Arbeitsverzeichnis alte oder fremde Objekte aufnehmen. Die
  Regression führt nur die echte CMD-Listenerzeugung mit synthetischen Dateien
  aus und bestätigt den Ausschluss solcher Objekte, das Ersetzen alter Listen
  und den Abbruch bei beiden möglichen Schreibfehlern. Der oben belegte
  unsignierte GitHub-Build nach dieser Korrektur besteht; die vollständige
  lokale Signierung und native Funktionsprüfung bestanden später im Kandidaten
  `c3658b8`.
- Die Windows-Suite ruft den vorhandenen nativen
  `keepvault_v12_kalyna_join_failure_kat` nun ausdrücklich als eigene Gruppe
  `crypto.kalyna-join-failure-kat` auf. Der Test verwendet den regulären
  signaturprüfenden Bibliothekslader und gibt sein zusätzliches Lade-Handle
  auch bei Fehlern frei. Die native Laufzeitprüfung dieser Gruppe bestand in
  der vollständigen Funktionssuite des Kandidaten `c3658b8`.
- Die Argon2-Fehlerbereinigung wartet auf die kumulativ gestarteten Worker.
  Zuvor wurde der kumulative Abschlusszähler mit der nach erfolgreichen Joins
  sinkenden Aktivzahl verglichen. Bei einem späten Create-/Joinfehler konnte
  dadurch Speicher zu früh freigegeben werden. Der isolierte Windows-Harness
  reproduziert für beide Fehlerarten die alte vorzeitige Freigabe und bestätigt
  nach dem Fix das Ende aller Worker vor der Freigabe. Er fängt den gefährlichen
  Vorher-Fall ab, statt selbst einen Use-after-free auszuführen.

Die früher protokollierten Teilprüfungen umfassen 10/10 Passwortmodell-/PIN-Gruppen,
2/2 Kompatibilitäts-Provenienz-/Ablehnungsgruppen, 3/3 Dateisicherheitsgruppen,
5/5 GUI-Gruppen und 151 QR-Scanner-Prüfungen. Die sechs tatsächlichen
Kompatibilitäts-Entschlüsselungs-/Reparaturgruppen und die komplette Suite
sind durch diese Teilprüfungen allein nicht belegt; sie bestanden anschließend
in der vollständigen 62-Gruppen-Suite des Kandidaten `c3658b8`.

Die sieben ZPAQ-Gruppen bestehen auch mit dem am 15. September nach den
Analysekorrekturen neu gebauten und signierten Arbeitskandidaten. Beim ersten isolierten Lauf fehlte der Test-Apphost; nach dessen
Übernahme besteht auch die Prozessabbruch-/Ausgabebegrenzungsgruppe. Das war
ein unvollständiger Testaufbau und kein erfolgreicher erster Gesamtlauf.
Am 15. September bestehen zusätzlich ML-DSA-87-Interoperabilität samt
Manipulationsablehnung, der echte Argon2id-Referenzvergleich mit 1 GiB,
ChaCha20-Parallelvergleich über 256 MiB einschließlich Countergrenzen,
Threefish-Parallelvergleich, AES-NI-Provider, unabhängiger Skein-MAC-Vergleich
und Prozesshärtung. Argon2-, Threefish- und Skein-Prüfungen wurden nach dem
gezielten Neubau ihrer geänderten Quellen erfolgreich wiederholt.

Der vollständige statische Lauf analysiert 23 Übersetzungseinheiten und endet
mit Exitcode 0. Die verbleibenden Warnungen und ihre Bewertung stehen im
[separaten Native-Analysebericht](WINDOWS_NATIVE_ANALYSIS_5.0.2.md). Ein erfolgreicher
Analyselauf wird ausdrücklich nicht mit Warnungsfreiheit gleichgesetzt.

## Build und Abhängigkeiten

Alle Windows-Projekte zielen auf .NET 10; die ausführbaren Produkte tragen
Version `5.0.2`, Dateiversion `5.0.2.0`. Hauptanwendung, Release-Verifier,
Signierwerkzeug und QR-Scanner wurden mit dem exakt gepinnten SDK `10.0.400`
im Locked Mode wiederhergestellt. Die Lockfiles wurden bewusst für die neue
TFM regeneriert. `System.Security.Cryptography.ProtectedData` ist auf
`10.0.0` aktualisiert; die unter .NET 10 WPF bereits enthaltene
`System.Security.Cryptography.Pkcs`-Paketreferenz wurde entfernt.
Der separate selbständige WPF-Installer hat einen eigenen geprüften Lockfile.

Für den abschließenden Build wurde der SDK-Pin am 15. September auf `10.0.401`
angehoben. Der vorherige SDK enthält Runtime `10.0.11`; Microsoft hat für
`10.0.12` weitere Sicherheitskorrekturen veröffentlicht. Das Windows-x64-SDK-
Archiv wurde über Microsofts offizielle Release-Metadaten bezogen und vor der
Installation gegen deren SHA-512 geprüft. Die endgültige Laufzeit soll daher
`.NET` und `WindowsDesktop` `10.0.12` enthalten; frühere Teilprüfungen unter
`10.0.11` bleiben als frühere Ergebnisse erkennbar. Quelle:
[Microsofts Sicherheitsupdate vom 8. September 2026](https://devblogs.microsoft.com/dotnet/dotnet-and-dotnet-framework-september-2026-servicing-updates/).

Die erneute NuGet-Abfrage am 15. September 2026 meldet für die fünf Graphen
Hauptanwendung/Tests, Scanner/Tests, Signierwerkzeug, Installer und Verifier
einschließlich transitiver Pakete keine bekannten anfälligen Pakete in den
abgefragten Quellen. Das ist eine Datenbankabfrage und keine Garantie gegen
unbekannte Schwachstellen.

Der neue Signierwerkzeug- und Installer-Build besteht mit null Warnungen und
null Fehlern. Ein Build allein belegt weder die vollständige Anwendung noch
GUI, Installationsablauf, native Sicherheit oder veröffentlichte Artefakte.

## Schlüssel und Signierung

Private Release-Schlüssel werden direkt aus dem ausdrücklich ausgewählten
privaten Schlüsselordner gelesen. Für den neuen Windows-Kandidaten ist dies
`C:\Users\Michael\Keep Vault ReleaseKeys v12\Windows-20260921` mit der
getrennten öffentlichen Identität unter `WindowsRelease/Signing`.
Der spätere portable Transfer erfolgt ausdrücklich über
`tools/Export-WindowsReleaseKeys.ps1` im ursprünglichen Windows-Benutzerkonto
in ein neues privates NTFS-Ziel; bloßes Kopieren der DPAPI-Dateien ist kein
portables Backup. Das vollständige Exportverzeichnis ermöglicht Signierungen
und bleibt privat. Ein Produktionsexport wurde noch nicht erstellt; siehe
[Windows-Schlüsselablage und Transfer](WINDOWS_RELEASE_KEYS.md).
Weder Passwort noch Schlüsselinhalt werden als Prozessargument,
Umgebungsvariable, Logeintrag oder temporäre Klartextdatei weitergereicht.
Der RSA-PFX-Schlüssel wird mit `EphemeralKeySet` geladen. Passwort-Bytes,
Passwort-Zeichen und temporäre Schlüsselarrays werden nach Gebrauch gelöscht.
Die AES-GCM-Envelope-Typen sind ausschließlich `KVMDSA12` und `KVPFXP12`;
Typ und kanonische Länge sind authentifiziert. Die alte universelle
`KVSECRT1`-Release-Hülle wird nicht akzeptiert. Für ML-DSA und PFX bestehen
getrennte Wrapping-Key-Dateien. Reparse-Pfade, mehrfache Hardlinks und
abweichend aufgelöste Dateien sind für Release-Geheimnisse gesperrt.

Das frühere öffentliche macOS-RSA-Zertifikat wurde sicher geladen und geprüft;
es bleibt historische Referenz und ist nicht die Identität des neuen
Windows-Kandidaten:

- Subject und Issuer: `OU=Keep Vault, O=Michael Feinermann, CN=Keep Vault macOS Hybrid Release`.
- RSA 4096 Bit; Zertifikatssignatur SHA-512/RSA; EKU Code Signing.
- Gültigkeit UTC: 15. August 2026 14:48:44 bis 12. August 2036 14:48:44.
- SHA-256 des öffentlichen SPKI:
  `BCA8E666BDC632C4A1C4BE0041B8677B820FF6F21C77BA9129E5809598295DE9`.

Die neue Windows-Identität hat Subject und Issuer
`CN=Keep Vault Windows Release 2026-09-21`, den Thumbprint
`7BA65B5130F34AB9F15C0D074699D46D9BCCD21C` und den öffentlichen RSA-SPKI-SHA-256
`D0C5454E2C122FFD03D6F265876468E3935537FF6BB312EEEE48D883A889CFBB`.
Ihr Zertifikat gilt von 21. September 2026 17:21:39 UTC bis
21. September 2036 17:26:39 UTC. Der ML-DSA-Public-Key-SHA-256 lautet
`B3CF5B4465033351222AC5D6E1CC20F66432BB18AEC623EF76BB2C7823812219`.
Diese öffentlichen Werte wurden unabhängig gegen die kompilierten Programme
des Kandidaten geprüft.

Auch dieses Zertifikat ist selbstsigniert. Die Windows-Zertifikatskette ist damit
nicht allgemein vertrauenswürdig; weder ein Root-Zertifikat noch ein
globales Vertrauen wird installiert. Die Programme prüfen die fest
eingebauten RSA-/ML-DSA-Pins und ihre Authenticode-/Hybrid-Signaturen.
Signierung und RFC3161-Zeitstempel sind getrennte Schritte, damit signtool
keinen privaten Schlüssel und kein Passwort als Argument benötigt.

Die echte App-Prüfung hat eine SHA-256-Signatur trotz angefordertem SHA-512
im bisherigen PowerShell-Signierweg erkannt und korrekt abgewiesen.
`ReleaseAuthenticodeSigner` ruft deshalb `SignerSignEx2` mit dem numerischen
`CALG_SHA_512` und dem flüchtigen Zertifikat direkt auf. Zusätzlich werden
sowohl der PE-Inhaltsdigest als auch der primäre CMS-Signerdigest als
SHA-512 geprüft; ein SHA-512-Zertifikat oder Zeitstempel allein genügt nicht.
Alle neun verfügbaren Native-Arbeitskandidaten wurden so erneut signiert und
weisen PE-/CMS-SHA-512, 64-Byte-PE-Digest und einen RFC3161-Zeitstempel auf.
Windows bestätigt dabei ausschließlich `CERT_E_UNTRUSTEDROOT`; die echte
Anwendungsprüfung akzeptiert die korrekten eingebauten Pins.

Bestandene synthetische Regressionen verwenden frisch erzeugte Testschlüssel:

- v12-ML-DSA- und PFX-Rundlauf mit UTF-8-Passwort einschließlich Leerzeichen.
- Ablehnung falscher Geheimnistypen, manipuliertem Header, Nonce, Payload
  und Tag, falscher Länge, angehängter Bytes und ungültigem UTF-8.
- Hybride RSA-PSS/SHA-512- und ML-DSA-87-Signatur mit unabhängiger nativer
  ML-DSA-Referenzprüfung; veränderte Nutzdaten werden abgelehnt.
- `tools/Test-EphemeralAuthenticode.ps1`: Signatur aus einem rein
  speicherinternen Zertifikat; Windows bestätigt ausschließlich
  `CERT_E_UNTRUSTEDROOT`, nach einem EXE-Bitflip `TRUST_E_BAD_DIGEST`.
  PE und primärer CMS-Signer verwenden nachweislich SHA-512; eine absichtlich
  mit SHA-256 signierte Gegenprobe wird zurückgewiesen.

## Paket und Installer

Der implementierte Paketaufbau umfasst die selbständigen Programme `Keep Vault.exe`,
`QR-Scanner/QR-Scanner.exe`, `Keep Vault Release Verifier.exe` und
`Keep Vault Setup.exe`. Alle benötigten Laufzeitkomponenten sind eingebettet;
auf dem Zielgerät ist kein SDK, Compiler oder Restore erforderlich.
`RELEASE-INVENTORY.json` bindet Produkt, Version, Architektur und den gesamten
Dateisatz mit relativen Pfaden, Größen und SHA-512-Digests. Das Inventar wird
mit beiden vorhandenen Verfahren signiert und umfasst auch sämtliche bereits
erzeugten Signatur-Sidecars. Nur das Inventar und sein eigener Signatur-Sidecar
sind aus diesem nichtzirkulären Dateisatz ausgenommen.

Der Installer hält Dateien und Elternverzeichnisse während der Prüfung und
Kopie offen. Zusätze, Auslassungen, mehrdeutige Pfade, Reparse Points und
Hardlinks werden abgewiesen. Er erstellt ein neues Verzeichnis im lokalen
Programmverzeichnis des Benutzerkontos, prüft die installierte Kopie erneut
und legt danach Verknüpfungen an. Bestehende App-Dateien werden niemals
überschrieben. Vorhandene Verknüpfungen führen zu einem ausdrücklichen Abbruch
vor der Installation; dieser Fall wird nicht als Erfolg gemeldet. Es gibt
keinen privilegierten Installerprozess und keine System-Truststore-Änderung.

Ein fehlgeschlagener Vorgang lässt alte Installationen unverändert. Eine
angefangene neue, nicht verknüpfte Kopie kann als überprüfbares Restverzeichnis
zurückbleiben; es wird keine unsichere rekursive Bereinigung fremder Pfade
versucht. Die oben protokollierten 36 EXE-Fälle mit 70 Prozessaufrufen bestätigen
die tatsächlichen Verifikations- und Kopierpfade. Die zusätzliche echte
Explorer-Installation und der Desktop-Verknüpfungsstart bestanden anschließend;
weitere DE/EN-GUI-Abläufe und Startmenü-Verknüpfungen sind noch zu prüfen.

Die synthetische Inventarregression ist bestanden: Originalprüfung und Kopie
mit identischem Inventardigest, Ablehnung einer zweiten Kopie in ein vorhandenes
Ziel, blockierter Schreibzugriff auf eine während der Prüfung gehaltene Datei,
Zurückweisung zusätzlicher oder veränderter Dateien und unsicherer relativer
Pfade. Die Shortcut-Serialisierung erfolgt vollständig über `IShellLink` und
einen Speicherstream. Ein unabhängiger Windows-Shell-Readback der synthetischen
Verknüpfung bestätigt den beabsichtigten Zielpfad. Es wurde dabei kein Programm
über die Verknüpfung gestartet und keine Benutzerverknüpfung verändert.

## Reproduzierbare Release-Kommandos

Der Wrapper erstellt selbst einen
unabhängigen Snapshot des vorher geprüften und committeten Quellstands.
In einem frischen PowerShell-Prozess muss SDK `10.0.401` das erste `dotnet`
im PATH sein. Diese Befehle sind die Vorlage für einen neuen Kandidaten;
bestandene und offene Läufe sind oben jeweils mit ihrem Quellstand dokumentiert:

```powershell
pwsh -NoProfile -File tools/Build-Portable.ps1 -ReleaseKeyDirectory 'C:\Users\Michael\Keep Vault ReleaseKeys v12\Windows-20260921'
# Nur nach Exitcode 0: den vom Wrapper ausgegebenen Snapshot-Pfad verwenden.
$snapshotRoot = '<verifizierter Snapshot-Pfad>\src'
$tests = Join-Path $snapshotRoot 'work\native-gate-tests\KalynaArchiver.Tests.dll'
$dist = Join-Path $snapshotRoot 'dist'
$verifier = Join-Path $dist 'Keep Vault Release Verifier-win-x64.exe'
$package = Join-Path $dist 'Keep Vault-portable-win-x64'
$zip = "$package.zip"
$env:KEEPVAULT_TEST_REPOSITORY_ROOT = $snapshotRoot
dotnet $tests --full
dotnet $tests --performance --only performance.cipher-suites
dotnet $tests --performance --only release.paranoia-256mib-level5
. (Join-Path $snapshotRoot 'tools\Invoke-ReleaseExecutable.ps1')
Invoke-ReleaseExecutable -Executable $verifier -Arguments @($package)
Invoke-ReleaseExecutable -Executable $verifier -Arguments @($zip)
Invoke-ReleaseExecutable -Executable (Join-Path $package 'Keep Vault Setup.exe') -Arguments @('--verify', $package)
pwsh -NoProfile -File (Join-Path $snapshotRoot 'tools\Test-ReleaseTamperResistance.ps1') `
    -ReleaseDirectory $package -ReleaseZip $zip -Verifier $verifier
# Danach tatsächliche Installation, DE/EN-GUI und Shortcut-Starts prüfen.
# Den komplexen Archiv-/Reparaturlauf als letzten Funktionstest ausführen:
dotnet $tests --performance --only release.paranoia-complex-tree-level5-repair
```

Nach jedem Testlauf sind Exitcode und `.test-results.json` separat zu sichern;
der nächste Lauf überschreibt diese Ergebnisdatei. Die volle Standardsuite
schließt die drei Performance-Gruppen aus. Testausgaben und distributierbare
Dateien liegen unter dem gemeldeten Snapshot, nicht im `dist` des ursprünglichen
Arbeitsverzeichnisses. Für die Companion-Prüfung muss der final signierte
QR-Scanner auch am vom Test verwendeten Companion-Pfad bereitstehen; ein
unvollständiger Testaufbau ist kein Produktnachweis.

Für das getrennte Signieren neugebauter Native-Tools liefert der überprüfbare
Helper nur Dateipfade und öffentliche Pins:

```powershell
$releaseSigning = & tools/New-ReleaseSigningParameters.ps1 -ReleaseKeyDirectory 'C:\Users\Michael\Keep Vault ReleaseKeys v12\Windows-20260921'
. tools/NativeToolTargets.ps1
$nativeTargets = @(Get-NativeToolTargets -Root $PWD)
& tools/Sign-Binaries.ps1 -Path $nativeTargets @releaseSigning
& tools/Generate-ReleaseManifests.ps1 @releaseSigning
```

Der komplette Parameterfluss zu `Sign-Binaries`, `New-HybridSignature`,
`Generate-ReleaseManifests` und `Sign-ManagedOutput` ist geprüft. Die Skripte
akzeptieren keine Klartext-PFX-Passwortparameter mehr. Ein frischer
PowerShell-Prozess pro Quell-Snapshot verhindert die Wiederverwendung einer
bereits geladenen Signierassembly aus einem anderen Verzeichnis.

Für `c3658b8` bestehen die nativen KATs/Threadfehlerprüfungen, Funktionssuite,
ZIP-Entpack- und EXE-Abnahme sowie Signatur-/Inventar-/Hashprüfungen. Offen bleiben
der bestandene Performance-Nachweis, der echte 256-MiB-Paranoia-Lauf auf Stufe 5,
der abschließende komplexe Ordnerbaum-Rundlauf und die reale Installer-/GUI-Abnahme.
Nach weiteren Produktkorrekturen müssen Build und betroffene Abnahmen am neuen
unveränderlichen Quell-Commit wiederholt werden. Veröffentlichung, Remote-Abgleich
und heruntergeladene finale Assetbytes werden erst nach den Freigabegates bestätigt.
