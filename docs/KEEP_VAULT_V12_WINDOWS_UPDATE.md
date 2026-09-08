# Keep Vault v12 unter Windows aktualisieren

Dieses Dokument ist die Arbeitsanleitung für den späteren Windows-Port. Die
macOS-Umsetzung 5.0.2 ist die normative v12-Zielreferenz. Der
[Passwort-/PIN-Vertrag](KEEP_VAULT_V12_CREDENTIAL_POLICY.md) gehört vollständig
dazu. Der [macOS-Prüfbericht für 5.0.2](KEEP_VAULT_5_0_2_MACOS_AUDIT.md)
dokumentiert die am 8. September 2026 abgeschlossene technische macOS-Abnahme.
Vor dem Port sind zusätzlich der veröffentlichte Tag und die konkrete
Commitzuordnung zu prüfen. Die Windows-Version wird separat gebaut und getestet;
ein erfolgreicher macOS-Lauf ist kein Windows-Nachweis.

## Direktauftrag für Codex unter Windows

Der folgende Auftrag kann unverändert an Codex auf dem Windows-Rechner
übergeben werden:

```text
Arbeite im Repository keep-vault an der Windows-Version von Keep Vault v12.
Starte vom vollständig geprüften und gepushten macOS-5.0.2-Stand, der durch
Tag und Prüfbericht bestätigt ist. Prüfe Commit- und Tree-Hash sowie die
Zuordnung zu origin/master und arbeite auf einem neuen Branch codex/windows-v12.
Der technisch abgeschlossene, weiterhin nur als GitHub-Entwurf vorliegende
Vorgänger v5.0.1 liegt auf
e52159e7a569a8b77fe7732006388c4401c4009f und ist nicht die vollständige
5.0.2-Zielreferenz. Keinen beliebigen neueren Commit ungeprüft als Basis nehmen.

Lies zuerst den vollständigen aktiven Quellbaum einschließlich
KalynaArchiver, KeepVaultMac als normative Referenz, nativer Quellen,
Packaging, QR-Scanner, Tests, Build-Skripten und Dokumentation. Suche danach
gezielt nach v11, V11, alten Magic-Werten, alten KDF-/KPAR2-Pfaden und
Fallbacks. Abwärtskompatibilität ist ausdrücklich verboten. Entferne jeden
Legacy-Produktionspfad, statt ihn zu überbrücken.

Portiere die Windows-App ausschließlich auf das v12-Protokoll. Implementiere
und prüfe die nativen Windows-x64-DLLs, insbesondere kalyna_v12.dll,
threefish_ref.dll, aes_ref.dll, mars_ref.dll, shacal2_ref.dll,
chachapoly_ref.dll, argon2_ref.dll und zpaq.exe. Der bisherige Hinweis
„Windows Kalyna port is intentionally deferred“ ist ein Blocker und darf
nicht als erfolgreicher Build gelten. Verwende nur nachweislich kompatible,
lizenzierte Quellen und aktualisiere das Provenienz- und Hash-Manifest.

Übernehme zuerst KEEP_VAULT_V12_CREDENTIAL_POLICY.md einschließlich sämtlicher
alten Regeln und der neuen Offline-Modelldaten, ihrer Hashes und Vektoren.
PIN6–16 und Passwort24–256 sowie alle Auswahl-, Stärke-, Paar- und Datumsregeln
gelten ausschließlich beim Erstellen. Die Windows-GUI darf beim Entpacken keine
alten Längen-/Syntax-Qualitätsgates weiterverwenden. Der gemeinsame KDF-Pfad
verwendet ausschließlich technische Kodierungs-/Ressourcengrenzen.

Übernehme den Parallelisierungsvertrag des macOS-v12-Standes:

* Archivieren, Kompression, Verschlüsselung, Entschlüsselung, Entpacken,
  Integritätsblätter und KPAR2-Recovery arbeiten mit begrenzten Worker-Pools.
* Poly1305 muss ab der festgelegten Mindestgröße parallel laufen und durch
  RFC-8439-KATs, Parallel-vs.-Skalar-Vergleich, Tail-, Overflow- und
  Join-Fehler-Tests abgesichert sein.
* CTR-Counterbereiche müssen disjunkt sein. Counter-Überlauf wird vor jeder
  Ausgabemutation abgewiesen.
* Nach Create-, Cancel-, Wait- oder Join-Fehlern werden alle Worker sicher
  beendet, bevor Schlüssel, Jobtabellen oder Caller-Puffer freigegeben werden.
* Argon2id bleibt die einzige absichtliche Ausnahme: t=4 und p=4 sind fest,
  die Branches und Paranoia-Runde bleiben sequentiell. Diese Werte dürfen
  nicht aus untrusted Headerdaten kommen.

Führe Locked Restore und Release-Build mit dem im Repository gepinnten
.NET-10-SDK sowie Visual Studio 2022, MSVC, Windows SDK, MASM und PowerShell 7
aus. Protokolliere Host, SDK, Compiler, Commit, Tree-Hash, Worker-Limits,
Dauer und Exit-Code. Verwende für Build und Packaging einen unveränderlichen
Snapshot desselben Commits. Nie aus einem nachträglich veränderten Live-
Arbeitsbaum signieren.

Führe in dieser Reihenfolge aus und stoppe bei einem Fehler mit einem
reproduzierbaren Befund:

1. Locked Restore, native Build- und PE-/Exportprüfung.
2. Unabhängige KATs für Kalyna, Threefish, AES, MARS, SHACAL-2,
   ChaCha20-Poly1305, SHA3, Skein und Argon2id.
3. Smoke-Suite, danach die vollständige Windows-Suite.
4. Alle Cipher- und Kaskaden-Benchmarks mit Warm-up und Medianregeln.
5. Exakter 256-MiB-Durchlauf mit Kompressionsstufe 5, Paranoia und komplettem
   Argon2id.
6. Release-Verifier, Authenticode-/Manifestprüfung, Mutationstests,
   ZIP-Inhaltsprüfung, Installation und reale DE/EN-GUI einschließlich
   Offline-Erststart und unveränderter Geheimnisbytes.
7. Als letzten funktionalen Lauf ein komplexer Ordnerbaum mit leeren,
   kleinen, großen, zufälligen, stark komprimierbaren Dateien, Unicode-Namen,
   tiefen Verzeichnissen und ähnlichen Dateinamen. Archivieren, verschlüsseln,
   entschlüsseln, entpacken und alle Daten, Hashes und Metadaten vergleichen.
8. Danach nur unverändernde Paket-, Git- und Veröffentlichungsprüfungen.
   Jede Produkt- oder Artefaktänderung macht den letzten Gate ungültig.

USB- oder Hardware-Schlüssel dürfen nur direkt und speicherintern verwendet
werden. Private Schlüssel, PFX-Passwörter und geheime Schlüsselcontainer dürfen nie
in Argumenten, Umgebungsvariablen, Logs, temporären Dateien, Artefakten oder
Git erscheinen. Fehlt eine sichere Signaturquelle, signiere nicht ersatzweise
mit einem Testschlüssel und dokumentiere den Blocker. Öffentliche Zertifikate
und Zertifikatsketten dürfen Bestandteil der überprüfbaren Signaturartefakte sein.

Führe einen vollständigen Code- und Sicherheitsreview durch. Melde offene
TOCTOU-, Reparse-Point-, Hardlink-, ADS-, Pfad-, Ressourcen-, Thread-Lifecycle-
und Geheimnisbefunde mit Datei, Zeile und Kommando. Behaupte niemals
„ohne Sicherheitslücken“, solange ein Gate offen ist. Erzeuge kein öffentliches
Release, keinen Store-Upload und keine Veröffentlichung, bevor alle Windows-
Gates separat bestätigt und ausdrücklich freigegeben wurden.

Wenn alle nichtöffentlichen Gates bestanden sind, prüfe git diff --check,
stage nur geprüfte v12-Dateien, committe mit
„Implement Keep Vault v12 Windows parallel pipeline“ und pushe den Branch
codex/windows-v12. Führe danach einen Remote-Hash-Abgleich durch und schreibe
das vollständige Protokoll in die Windows-Dokumentation.
```

## Ziel und harte Grenzen

* Ziel ist ein neuer Windows-v12-Stand mit `ContainerVersion = 12` und
  `KPAR2 = 4`.
* Die Windows-App akzeptiert ausschließlich v12. Es gibt keinen v11-Reader,
  keine v11-Migration und keinen Kompatibilitäts-Fallback.
* Der alte unlizenzierte Kalyna-Referenzcode darf nicht übernommen werden. Die
  native v12-Kalyna-Implementierung muss aus einer nachweislich kompatiblen,
  lizenzierten Quelle stammen und im Provenienzprotokoll stehen.
* Die Windows-Version darf erst als Release bezeichnet werden, wenn alle
  Windows-Gates, die Signaturprüfung und ein echter Windows-End-to-End-Lauf
  bestanden sind.

## 1. Arbeitsbaum und Toolchain vorbereiten

1. Einen eigenen Windows-Branch vom gepushten v12-Commit anlegen. Vor Beginn
   `git status --short` prüfen und keine macOS-Artefakte in den Windows-Build
   übernehmen.
2. Visual Studio 2022 mit C/C++, Windows 10/11 SDK, MASM und PowerShell 7
   installieren. Die verwendete SDK-Version sowie MSVC-Version in das
   Buildprotokoll schreiben.
3. Das Repository über `global.json` im Locked-Mode wiederherstellen. Die
   `packages.lock.json` darf nur durch einen bewusst dokumentierten
   Dependency-Update geändert werden. `--force-evaluate` darf dabei nicht
   mit `--locked-mode` kombiniert werden: Es überschreibt den gesperrten Modus.
   Normale Builds setzen `RestoreForceEvaluate=false` und vergleichen die
   geprüften Lockdatei-Hashes vor und nach Restore/Build.
4. Für reproduzierbare Builds einen case-sensitiven, unveränderlichen
   Quell-Snapshot des geprüften Commits verwenden. Das Build-Skript darf nicht
   zwischen Review, Compilerlauf und Packaging aus dem Live-Arbeitsbaum lesen.
5. `external/VENDOR-PROVENANCE.md` und die zugehörigen SHA-256-Manifeste auf
   dem Windows-Rechner erneut gegen die tatsächlich kompilierten Quellen
   prüfen.

## 2. Projekte auf v12 umstellen

* `KalynaArchiver`, `KalynaArchiver.Tests` und der Release-Verifier zielen auf
  dieselbe freigegebene Windows-TFM, derzeit `net10.0-windows` mit dem im
  Repository gepinnten .NET-10-SDK. Es gibt keine parallele v11-TFM.
* Alle Projektdateien, Ressourcen, Fehlermeldungen und README-Texte müssen
  `v12` verwenden. Vorkommen von `v11`, `V11`, alten Magic-Werten oder alten
  KDF-/KPAR2-Feldern sind vor dem Commit zu suchen und zu entfernen.
* Die Windows-Interop muss ausschließlich die v12-Namen laden, insbesondere
  `kalyna_v12.dll`. Ein fehlendes oder nicht vertrauenswürdiges natives Modul
  ist ein harter Fehler, kein Fallback auf eine andere DLL.

## 3. Native Windows-Bibliotheken

`tools/Build-Native.cmd` ist nur das Gerüst. Es muss den vollständigen v12-
Satz für x64 erzeugen:

* `kalyna_v12.dll` aus der lizenzierten v12-Kalyna-Quelle mit den beiden
  Exporten für den parallelen und den skalaren CTR-Pfad. Exportnamen,
  Calling-Convention, Endianness und Gegenprüfung gegen eine unabhängige
  Implementierung festhalten.
* `threefish_ref.dll`, `aes_ref.dll`, `mars_ref.dll`, `shacal2_ref.dll` und
  `chachapoly_ref.dll` aus den jeweils dokumentierten Quellen.
* `argon2_ref.dll` und `argon2.exe` aus der geprüften PHC-Referenzquelle.
* `zpaq.exe` mit dem v12-Streaming-Format `KVP12ZP1` und dem gehärteten
  Argument-/Dateilistenpfad.
* Für alle nativen Ziele `/O2 /MT /GS /sdl /guard:cf` sowie beim Linken
  `/guard:cf /CETCOMPAT`, ASLR und NX aktivieren. Die Crypto++-Bibliothek und
  ihre Adapter müssen mit denselben ABI-relevanten SIMD-Optionen gebaut
  werden; `CRYPTOPP_DISABLE_ASM` darf nicht nur auf einer Seite gesetzt sein.

Vor dem Einbinden in die App:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File tools\Verify-MldsaReference.ps1
cmd /c tools\Build-Native.cmd
```

Der bisherige Exit-Code „Windows Kalyna port is intentionally deferred“ ist
kein bestandener Build, sondern ein bewusst zu beseitigender Port-Blocker.

## 4. Parallelisierungsvertrag

Die Parallelisierung ist datenunabhängig und bleibt speicherbegrenzt:

* Archive, Kompression, Entschlüsselung und Entpacken arbeiten in begrenzten
  Chunks/Worker-Pools. Worker-Anzahl und Chunk-Größe werden gekappt und nie
  aus untrusted Headerdaten übernommen.
* Jeder native Worker muss bei `CreateThread`-, Cancel- und Wait-Fehlern bis
  zum sicheren Abschluss verfolgt werden. Erst danach dürfen Jobtabellen,
  Schlüsselkopien und Caller-Puffer freigegeben werden.
* CTR-Keystreams erhalten disjunkte Counterbereiche. Überlauf wird vor der
  ersten Ausgabemutation abgewiesen.
* Poly1305 wird ab der festgelegten Mindestgröße über unabhängige Blöcke
  parallel berechnet. Die letzte Teilnachricht, Blockreihenfolge, Länge und
  Nonce müssen in einem unabhängigen RFC-8439-KAT sowie in einem
  Parallel-vs.-Serial-Test abgedeckt sein.
* Blatt-Hashes/MACs und KPAR2-Daten-/Paritätsblöcke dürfen parallel laufen,
  solange kein Puffer wiederverwendet wird, bevor alle abhängigen Worker
  abgeschlossen sind. Fehler werden deterministisch zusammengeführt.
* Argon2id ist die einzige absichtliche Ausnahme: `t = 4`, `p = 4`, die beiden
  Branches und die Paranoia-Runde bleiben sequenziell. Die Speichergröße wird
  wie bei macOS aus PMI16 abgeleitet und nicht im Container gespeichert.

## 5. Container- und KDF-Vertrag

Der Windows-Port muss dieselben v12-Invarianten wie macOS erfüllen:

* Magic/Container-Version v12, `KPAR2-v4`, keine v11-Lese- oder
  Migrationspfade.
* Vier verpflichtende Faktoren: Passwort, PIN und zwei getrennte generierte
  1024-Bit-Hex-Faktoren.
* Separate SHA3-512- und Skein-1024-Branches, length-prefixed und
  domain-separated. Paranoia führt die vollständige zweite Argon2id-Runde aus.
* Authentifizierung erfolgt vor Klartextausgabe. Ein verschlüsselter Container
  erhält dual authentifizierte KPAR2-Metadaten; ein manipuliertes oder nicht
  authentifiziertes Sidecar wird nicht als vertrauenswürdig behandelt.
* Pfade, Reparse Points, Hardlinks, ADS, führende Bindestriche und
  mutierendes Input/Output werden vor und während des Vorgangs geprüft.

## 6. Windows-Build und Testreihenfolge

Die Gates werden in dieser Reihenfolge protokolliert. Jeder Lauf erhält
Commit, Tree-Hash, Toolchain, Host, Runtime, Test-ID, Dauer und Exit-Code.

```powershell
dotnet restore --locked-mode
dotnet build KalynaArchiver\KalynaArchiver.csproj -c Release --no-restore
dotnet build KalynaArchiver.Tests\KalynaArchiver.Tests.csproj -c Release --no-restore

# zuerst günstige KATs und Infrastruktur
dotnet run --project KalynaArchiver.Tests -c Release --no-build -- --smoke

# vollständige Windows-Suite ohne vorzeitigen Abbruch
dotnet run --project KalynaArchiver.Tests -c Release --no-build -- --full

# primitive und Container-Messungen, nur auf einem ungestörten Rechner
dotnet run --project KalynaArchiver.Tests -c Release --no-build -- --performance
```

Zusätzlich verpflichtend:

1. Unabhängige Kalyna-, Threefish-, AES-, MARS-, SHACAL-2-, ChaCha20-
   Poly1305-, SHA3-, Skein- und Argon2-KATs.
2. Parallel-vs.-skalar für jeden Cipher und jede Kaskade, einschließlich
   Poly1305 und KPAR2.
3. Fehlerpfade für Thread-Erzeugung, Join/Wait, Cancellation, Counter-Overflow,
   beschädigte Chunks und beschädigte Paritätsblöcke.
4. Ein kompletter Durchlauf mit 256 MiB, Kompressionsstufe 5, Paranoia und
   echtem Argon2id. Die gemessene Zeit und die effektive Worker-Anzahl dürfen
   nicht nur aus einer Schätzung stammen.
5. Release-Verifier, Authenticode-/Manifestprüfung und Tamper-Tests für jede
   EXE, DLL, jedes Manifest und die ZIP-Datei; Installation und echte GUI
   einschließlich vollständigem Offline-Betrieb.
6. Als letzter funktionaler Test ein komplexer Ordnerbaum mit leeren Dateien,
   sehr kleinen und großen Dateien, zufälligen und stark komprimierbaren
   Daten, ungewöhnlichen Unicode-Namen, verschachtelten Verzeichnissen und
   absichtlich ähnlichen Dateinamen. Archivieren, verschlüsseln, entschlüsseln,
   entpacken, Hashes und Metadaten vergleichen.
7. Danach nur unverändernde Paket-/Git-Prüfungen; keine weiteren Mutationen
   oder funktionalen Tests ohne erneuten letzten Gate.

Die Performance-Baseline muss pro Maschine gekennzeichnet werden. Ein
Speedup darf nicht durch Entfernen von Authentifizierung, KDF-Runden,
Fehlerkorrektur oder Sicherheitsprüfungen erkauft werden.

## 7. Signieren und Packaging

* Für Entwicklungsbuilds nur ein ausdrücklich markiertes Testzertifikat
  verwenden; es darf nicht als global vertrauenswürdige Root-CA installiert
  werden.
* Für eine spätere Windows-Veröffentlichung ein geschütztes
  Authenticode-Zertifikat, die drei RSA-SPKI-Pins und die drei ML-DSA-87-Pins
  separat verifizieren. Private Schlüssel und PFX-Passwörter gehören weder in
  Argumente, Logs, Git noch in die ZIP-Datei.
* `tools\Build-Portable.ps1` muss die Haupt-App, den separaten QR-Scanner und
  den Release-Verifier aus demselben Snapshot bauen. Erst danach werden
  SHA3-/Skein-Manifeste und die hybriden Signaturen erzeugt.
* Vor dem Commit die ZIP-Datei in ein neues Verzeichnis entpacken und mit dem
  eigenständigen Verifier prüfen. Das Ergebnis darf keine Symlinks,
  Debug-Symbole oder unbeabsichtigten Zusatzdateien enthalten.

## 8. Abschluss und Freigabeentscheidung

Erst wenn alle Gates grün sind:

```powershell
git diff --check
git status --short
git add <geprüfte-v12-Dateien>
git commit -m "Implement Keep Vault v12 Windows parallel pipeline"
git push origin <windows-v12-branch>
```

Ein Push ist noch keine Veröffentlichung. Tag, öffentliche ZIP, Store-Upload
oder sonstige Verteilung benötigen eine gesonderte Freigabe nach dem
Windows-Sicherheitsreview. Offene Punkte werden in
`docs/KEEP_VAULT_V12_MACOS_RELEASE.md` beziehungsweise im Recheck-Protokoll
mit konkretem Testnamen und reproduzierbarem Kommando festgehalten.

## 9. Verbindliche Ergänzungen aus macOS 5.0.2

- Marketingversion und Buildnummer sind unabhängig von Container v12. Unter
  dem DE/EN-Untertitel muss die echte Version aus den Build-Metadaten stehen.
  Haupt-App und QR-Scanner müssen dieselbe Release-Version/Buildnummer tragen.
- Schlüsselzettel müssen im sichtbaren Titel und im PDF-Dokumenttitel die
  tatsächliche App-Version enthalten: `Keep Vault [Version] Schlüsselzettel A`
  beziehungsweise B; auf Englisch `Keep Vault [Version] Key Sheet A/B`.
  Die Versionsangabe verändert weder den v12-Container noch die Bindung der
  Schlüsselzettel an Archivpfad, Verfahren und Faktoren.
- Unter dem Aufbewahrungshinweis werden die vier Metadatenbezeichnungen
  einschließlich Doppelpunkt fett gesetzt, ihre Werte dagegen in normaler
  Schrift. Das gilt für Verschlüsselungssuite, Archivdatei, Erstellungsgerät
  und Speicherort sowie die englischen Entsprechungen. Der Zeilenumbruch
  berücksichtigt die tatsächlichen Breiten beider Schriftschnitte.
- Für das handschriftliche Benutzerpasswort sind mindestens drei volle
  Schreibzeilen mit gut nutzbarem Abstand vorzusehen. Direkt daneben steht
  `PIN nicht eintragen` beziehungsweise `Do not write down the PIN`.
  Passwort und PIN werden niemals als digitale Inhalte in Blatt, QR-Code oder
  PDF aufgenommen. Lange Metadaten dürfen weder Schreibzeilen verdrängen noch
  Faktorzeichen, Hinweise oder QR-Codes verdecken oder abschneiden. Unlösbare
  Überläufe müssen vor einem Druckauftrag verständlich gemeldet werden.
- DE/EN-PDF und tatsächlicher Papierdruck müssen dieselbe geprüfte Gestaltung
  verwenden. Jeder getrennte Druckauftrag enthält nur einen vollständigen
  Faktor mit zwei identischen QR-Codes sowie eine öffentliche Installationsseite
  ohne Geheimwerte. Alle Seiten rendern und visuell prüfen; gedruckte QR-Codes
  zusätzlich mit dem separaten Scanner erkennen und durch tatsächliches
  Kopieren/Einfügen auf exakte Übereinstimmung prüfen. Der CUPS-Nachweis von
  macOS ersetzt keinen Windows-Drucktest. Die endgültige macOS-Vorschau mit
  fetten Feldbezeichnungen wurde am 7. September 2026 mit „Sieht gut aus.
  Setzt das um“ ausdrücklich freigegeben und ist die gestalterische Referenz.
- Sämtliche eingebetteten Passwortmodelldaten einschließlich Originalindizes,
  Hashes, Counts, Lizenzen und fester Modellparameter unverändert übernehmen.
  Fehlende Daten sperren nur eine positive Archivierungsprüfung. Kein
  Netzwerk-Fallback und kein Download beim Erststart.
- Exakte Paarprüfung gegen das rohe Passwort und vier heutige Datumsformen
  aus der lokalen Windows-Zeitzone vor dem endgültigen Archivstart. Tests für
  Midnight-Wechsel, führende Nullen und Schaltjahre übernehmen.
- Bestehende 128-Bit-Schwelle unverändert; `Hneu <= Halt` für jeden Testfall.
  Unkalibrierte Modelle nicht als empirische Entropie oder Angriffskosten
  ausgeben. Alle Sprach-, BIP39- und Unicode-Referenzvektoren auf Windows
  unabhängig ausführen, einschließlich statischer nicht regelkonformer, aber
  kryptografisch korrekter v12-Archive und KPAR2-Wiederherstellung ohne
  Modellaufrufe. Keine neue Normalisierung der KDF-Eingaben.
- Die macOS-5.0.1-Korrekturen bleiben Voraussetzung: Streaming-Leerverzeichnisse,
  native Lesefehler, geordnete Speicherzulassung, vollständige volatile
  Skein-Arbeitsfeldlöschung und verifizierte schreibgeschützte Archivstaging-
  Daten. Plattformmechanismen für unveränderliches privates Staging müssen
  unter Windows unabhängig implementiert und mit negativen Gegenproben
  geprüft werden. POSIX-APIs nicht ungeprüft als Windows-Nachweis übernehmen.
- Vor Abschluss nur die aktuelle Installation und ihre Dateizuordnungen
  registrieren. Alte Builds dürfen nicht als zusätzliche App-Auswahl erscheinen.
  Prüfarbeitskopien und GitHub-Entwürfe sind keine öffentliche Freigabe.
- Originaldateien erst nach erfolgreicher Archivierung und vollständigem
  Wiederherstellungs-/Bytevergleich löschen. Für die separate kryptografische
  Löschung müssen KPAR2-Daten vor dem Container unbrauchbar werden. Negativfälle
  ohne Bestätigung, nach Abbruch und mit einem Klartextcontainer müssen alle
  Originale unverändert erhalten. Pfadwechsel setzen die Bestätigung zurück;
  Status, Fehler und Abschlussmeldungen folgen der gewählten DE/EN-Sprache.
  Backups, Snapshots und physische SSD-Reste werden dadurch nicht als gelöscht
  ausgewiesen. Die macOS-GUI-Gegenproben belegen die Löschung ausgewählter
  Kopien und den Erhalt der Originale. Beim erneuten GUI-Lauf wurde jedoch
  ein verzögertes Textänderungsereignis gefunden, das die Abschlussmeldung
  wieder auf „Noch keine Datei analysiert“ setzte. Der Abschlussstatus muss
  das programmgesteuerte Leeren des Pfades und anschließende DE/EN-Wechsel
  überstehen. Jeder neue nichtleere Pfad, auch nur ein Leerzeichen, muss
  dagegen Status und Bestätigung zurücksetzen; ebenso das Leeren eines
  lediglich analysierten Pfades. Unter Windows sind die echte verzögerte
  Ereigniszustellung, beide Ausgangssprachen, Sprachwechsel und ein weiterer
  Löschvorgang unabhängig zu prüfen. Der macOS-Regressionstest
  `gui.erase-completion-status` hat den gezielten Nachtest bestanden. Auch
  die erneute sichtbare Prüfung am aktualisierten Development-Kandidaten
  unter PID 34669 besteht einschließlich DE/EN/DE und erneuter Pfadwahl.
  Die Prüfung des endgültigen Developer-ID-Artefakts bleibt davon getrennt.


## 10. Installations- und Rollbackvertrag als Windows-Grundlage

Dieser Abschnitt beschreibt zu übertragende Eigenschaften. Er behauptet
weder einen bereits implementierten Windows-Installer noch bestandene
Windows-Tests. Die aktuelle macOS-Implementierung ergänzt einen selbständigen
signierten Installer mit vorgebautem Verifier und Löschhelfer; der vollständige
aktuelle macOS-Release-Durchlauf wird weiterhin im zugehörigen Prüfbericht
getrennt abgenommen.

- Ein öffentliches Installationspaket muss alle benötigten geprüften
  Komponenten enthalten. Auf dem Zielgerät dürfen weder Quellworkspace noch
  SDK, Paketrestore oder Compiler erforderlich sein. Ein Hinweis auf einen
  nicht mitgelieferten Installer erfüllt diesen Vertrag nicht.
- Ist der vollständige Paketsatz neben dem laufenden Installer nicht
  auffindbar, darf eine explizite Ordnerauswahl eine andere Quelle bestimmen.
  Diese Auswahl ist keine Authentifizierung: Der gesamte ausgewählte Satz
  muss dieselben Typ-, Link-, Identitäts-, Kopier- und Signaturprüfungen
  bestehen. Fehlende Nachbarn dürfen keinen Rückgriff auf ungeprüfte Dateien
  oder eine Installation einzelner Bestandteile auslösen. App Translocation
  ist ein macOS-Fall; unter Windows werden Paketpfade, Auswahlabbruch und
  die entsprechenden Reparse-Point-/Austauschfälle separat geprüft.
- Ein mit beiden vorhandenen Signaturverfahren authentifiziertes Inventar
  bindet den vollständigen erwarteten Satz mit Pfaden, Typen, Größen, Modi
  beziehungsweise plattformgerechten Zugriffsrechten und Digests. Versions-,
  Build- und Produktidentitäten müssen zusammenpassen. Zusätze, Auslassungen,
  mehrdeutige Namen, Reparse Points, Hardlinks und Spezialobjekte werden mit
  Windows-eigenen APIs und gehaltenen Handles unabhängig geprüft.
- Ausführungsfähige Installerbestandteile werden vor ihrem Einsatz in einen
  gegen Änderungen desselben Benutzers geschützten Bereich übernommen.
  Authentifizierung, tatsächliche Prozessidentität, gehaltene Dateiidentität
  und Schutz der gesamten Elternkette müssen vor dem ersten privilegierten
  Einsatz zusammenpassen. macOS-root-Eigentümer, POSIX-Modi und ACL-Symbole
  werden nicht wörtlich übernommen; Windows benötigt eigene Eigentümer-,
  DACL-, Handle- und Dienst-/Token-Grenzen. Der Benutzer darf aus dem geprüften
  Satz lesen und benötigte Programme ausführen, ihn aber nicht austauschen.
- Ein Fehlervorgang muss die zuvor authentifizierte alte Installation exakt
  wiederherstellen. Ihr Inventar, ihre Dateiinhalte, Identitäten und Sidecars
  werden vor dem Austausch gebunden und nach dem Rollback erneut geprüft.
  Alte, gültige versionsabhängige Hinweise oder Signaturmetadaten müssen
  nicht den anderen Bytes des neuen Kandidaten entsprechen. Der Vergleich
  ersetzt keine Authenticode-/Hybridprüfung und darf den bisherigen
  Rückrollschutz nicht abschwächen.
- Das macOS-Beispiel unterscheidet lokale Ticketintegrität und aktuelle
  Apple-Verteilungsrichtlinie. Unter Windows sind die tatsächlich verfügbaren
  Authenticode-, Zertifikatsketten-, Zeitstempel- und Sperrprüfungen ebenso
  präzise zu benennen und zu belegen. Ein erfolgreicher Policyaufruf ist nicht
  automatisch ein Nachweis identischer Artefaktbytes; die Bindung an das
  endgültige signierte Inventar bleibt erforderlich.
- Der gefundene Darwin-Statfehler zeigt, warum ein erfolgreicher ARM64-Lauf
  keine ABI-Aussage für andere Architekturen liefert. Unter Windows müssen
  Strukturgrößen, Feldoffsets, Zeichencodierung, Aufrufkonvention und tatsächliche
  DLL-Exports je unterstützter Architektur unabhängig geprüft werden.
  Kompilation, emulierter Lauf und tatsächlicher Installations-/GUI-Test werden
  getrennt ausgewiesen. Aus einer nicht vorhandenen Hardwareprüfung wird kein
  bestandener Nachweis abgeleitet.

Die freigegebene Schlüsselzettelgestaltung, die unveränderten nur bei
Archivierung geltenden Passwort-/PIN-Regeln und der v12-Bytevertrag bleiben
zusätzlich verbindlich. Diese Installationsanforderungen ändern weder das
vom Benutzer gewählte Passwort und die gewählte PIN noch Containerheader,
KDF oder KPAR2.

## 11. Zwischenstand der macOS-Referenz am 7. September 2026

Der neue Development-Build ist noch keine abgeschlossene 5.0.2-Freigabe.
`approved-installer-development-build.log` dokumentiert 151 bestandene und
eine fehlgeschlagene Gruppe von 152 in 492,8 Sekunden. Die fehlgeschlagene
Gruppe `packaging.hybrid-key-separation` erwartete veraltet SDK-/`xcrun`-Suche
im inzwischen absichtlich SDK-freien Metadatenverifier. Die Testannahme ist
auf feste Systemwerkzeuge ohne `xcrun` korrigiert; die tatsächliche Probe mit
feindlichem `PATH` bleibt erhalten. Der gezielte Nachlauf dieser
Metadatengruppe bestand mit 1 von 1 Gruppen in 79,0 Sekunden. Beleg ist
`sdk-free-metadata-targeted-evidence/results.json`, SHA-256
`b0bde7f61f03e712cf26e1d6478c2d791f0f7784629dfcf261cc3ca1debd1de6`.
Frühere 152/152-Läufe bleiben Nachweise ihrer jeweiligen älteren Quellen und
Artefakte; der gezielte Nachlauf ersetzt keinen neuen Gesamtlauf.

Die Quellsnapshots dieses Development-Builds binden `InstallerMain.swift`
noch an SHA-256 `fbe13c7ea165e7d4f860b422dbf711c18a05870d1ce4511237ac7ae326861406`.
Die spätere Ordnerauswahl bei App Translocation gehört zu einem getrennten
Quellstand mit SHA-256
`74b4e6ecb612a5b81d24569a4ee78a7e4c35453d03a98b540fd7d4a9022bbde1`.
Für diesen Stand sind Kompilation beider Architekturen mit Warnungen als
Fehler und je zwölf Dateisystemfälle unter ARM64 und Rosetta-x86_64 belegt.
Die Auswahl prüft genau 20 Paketobjekte einschließlich ihrer Typen und Links;
die Authentifizierung bleibt unverändert. Diese Komponentenproben ersetzen
keinen tatsächlichen Installer-GUI-/Administratordurchlauf.

Der echte App-GUI-Lauf mit Version 5.0.2, Build 13, PID 81532 bestätigt die
Versionsanzeige in DE/EN, lokalisierte Analyse- und Ablehnungsstatus sowie
die Löschung der ausgewählten Kopien. Originalcontainer, ursprüngliche
KPAR2-Datei und Kontrolldatei blieben unverändert. Der deutsche Erfolgsdialog
und das Leeren von Pfad und Bestätigung bestanden. Der anschließend entdeckte
Fehler mit verzögerter Ereigniszustellung ist minimal korrigiert und durch
die neue Gruppe `gui.erase-completion-status` abgedeckt. Damit werden jetzt
153 Gruppen erwartet. Der frisch gebaute gezielte Lauf
`Test-KeepVault --category GUI --parallel 1` bestand anschließend mit 24/24
Gruppen in 21,2 Sekunden, darunter `gui.erase-completion-status` in
1,390 Sekunden. Vorher wurden 1319 Quelleingaben in
`gui-fixes-source-before.json` gebunden. Der anschließend gestartete
Development-Durchlauf mit 153 erwarteten Gruppen wurde am 7. September 2026
gegen 14:04 Uhr durch einen Mac-Neustart unterbrochen. Für den in
`final-gui-development-build.log` protokollierten Versuch liegt kein
JSON-Ergebnis vor; er gilt nicht als bestanden.

Die nachfolgende Wiederholung in `restart-development-build.log` bestand
mit 153 von 153 Gruppen, null Fehlern und null blockierten Gruppen in
405,4 Sekunden; die summierte Gruppenlaufzeit beträgt 921,4 Sekunden.
`restart-development-results/001-test-results.json` hat SHA-256
`343a5bac41eda92892e1958a1c0e40acc3d0a548c96883ef820f69a763cbd049`.
Die Vorher-/Nachher-Snapshots stimmen für alle 1.319 Quelleingaben überein;
die installierte Development-App ist byteidentisch mit dem frisch gebauten
Bundle. Das neue Paket besteht die Prüfung von 20 Wurzelobjekten,
19 Mach-O-Dateien und 38 Slices. Beide NativeAOT-Slices führten die
authentifizierte Manifestprüfung erfolgreich aus, ARM64 nativ und x86_64
unter Rosetta.

Der sichtbare GUI-Nachtest ab 15:19:35 Uhr unter PID 34669 bestätigt für
5.0.2, Build 13 die lesbare Versionsnummer unter dem Untertitel und alle
vier Pfadplatzhalter in DE/EN. Die echte kryptografische Löschung entfernt
ausschließlich die ausgewählten Container-/KPAR2-Testkopien; Originale und
Kontrolldatei bleiben unverändert. Der Abschlussstatus bleibt nach OK und
DE/EN/DE erhalten. Ein neuer Pfad setzt Status und Bestätigung zurück;
anschließend wurde die App mit Cmd-Q beendet. Beleg ist
`gui-completion-retest-result.json`. Diese macOS-Regression muss der spätere
Windows-Port mit seiner eigenen Ereigniszustellung unabhängig prüfen.

Die privaten Belege liegen unter `build/audit/5.0.2-20260906/`:
`installer-translocation-review/results.json` und
`approved-layout-gui-first-erase-result.json`. Der gezielte GUI-Nachtest steht
in `gui-fixes-targeted-evidence/results.json`, SHA-256
`b92cb9e4d435a3bf5449d28bb49f878aa12f7810600f41da78e0bd8cff8c3922`.
Die neuen Paket- und Slice-Belege sind `restart-development-kit-audit.json`
und `restart-development-native-aot-architectures.json`.

Die nachfolgende Apple-Notarisierung des endgültigen Developer-ID-Kandidaten
ist bestanden: Job `672ab61e-4909-4fe9-a9e2-1685ea774e09`, `Accepted`,
`statusCode = 0`, `issues = null`. Alle drei Apps bestehen Stapling,
`stapler validate` und Gatekeeper. Der originale Einreichungsstand ist mit
allen 38 Architektursignaturen gebunden; 76 Apple-Rohzeilen entsprechen
diesen Signaturen einschließlich Bundlealiasen und Duplikaten. Das
endgültige Paket besteht die Prüfung von 20 Wurzelobjekten, 19 Mach-O-Dateien
und 38 unveränderten Slices. Nur drei Ticketdateien und sechs erneuerte
Manifest-/Signaturdateien unterscheiden es von der Einreichung. Die hybride
Manifestprüfung besteht tatsächlich für 149 Einträge auf ARM64 und unter
Rosetta-x86_64.

Das zur Veröffentlichung vorbereitete ZIP umfasst 43.678.062 Bytes, SHA-256
`cac58f018ab60734e4565aea601d590e390d6640419eabe41e62a66f8e9c7484`.
`final-release-assets.json` bindet dieses ZIP und genau fünf Sidecars;
`final-notarized-package-audit.json` und
`final-native-installation-verifier.json` belegen die getrennten Prüfungen.
Die 1.319 Quelleingaben bleiben unverändert. App-Installation und
Authentifizierung für den Root-ZPAQ-Anker sind abgeschlossen. Der
vollständige Testlauf des notarisierten Developer-ID-Kandidaten besteht mit
153 von 153 Gruppen in 405,5 Sekunden, ohne Fehler oder blockierte Gruppen;
die summierte Gruppenlaufzeit beträgt 918,9 Sekunden.
`final-developer-id-results/001-test-results.json` hat SHA-256
`8ec5a2d0a5b28c5b40f3e0ba7054cea27c46bb99c4b25a1a3e26c3e44c1db93d`.
Die zusätzlichen einzelnen Releaseprüfungen für Produktions-Worker,
parallelen MAC-KAT, v12-/KPAR2-Rundlauf, KPAR2-Worker, physische EIO-Reparatur
und vollständige ZPAQ-Matrix bestehen ebenfalls. Die Performance-Matrix
aller zehn Cipher-Suiten besteht in 195,0 Sekunden, der 256-MiB-Paranoia-Lauf
in 75,4 Sekunden und der komplexe Paranoia-Lauf mit KPAR2-Reparatur in
73,7 Sekunden. Die Ergebnisdateien `015`, `017` und `019` mit dem Suffix
`-test-results.json` und ihre SHA-256-Werte stehen im aktuellen Audit.
Der Releasebuild vom 7. September 2026 ist abgeschlossen; die endgültigen
Artefakte liegen unter `dist/Keep Vault-macOS/`.
Der native Installer-GUI-Lauf, der letzte komplexe Lauf nach finaler
Installation sowie abschließender Commit, Tag und öffentliche stabile
Freigabe bleiben offen.

Der tatsächliche native Installer-GUI-Test am 8. September 2026 fand
anschließend einen Fehler in der Codesign-Argumentform: `-R` mit getrenntem
Anforderungstext wird als Dateipfad ausgewertet; erforderlich ist die Form
`-R=<Anforderungstext>`. Die Installation brach mit einer ungültigen
Anforderungsspezifikation ab. Der zuvor vollständig getestete und von Apple
akzeptierte Kandidat ist damit überholt und darf nicht veröffentlicht werden.
Die Korrektur benötigt neue Signierung, Notarisierung, vollständige
Releaseprüfungen, einen tatsächlichen Installer-GUI-Nachtest und den letzten
komplexen Lauf nach finaler Installation. Die Windows-Grundlage ist erst nach
deren Abschluss und öffentlicher Freigabe des korrigierten Kandidaten gegeben.

Die macOS-Korrekturen sind inzwischen umgesetzt. Ein zweiter Integrations-
fehler betraf numerischen UID-Text in der ACL-Vergabe. Der Installer bindet
nun den systemseitigen Kontonamen durch UID-Rückprüfung, vergibt die reinen
Lese-/Such-/Ausführungsrechte vor jeder nativen Ausführung und vermeidet
nachträgliche ACL-Metadatenänderungen. Der native Signaturprüfer verwendet
begrenzte Bytes aus gehaltenen Deskriptoren, weil `/dev/fd` bei Rootdateien
mit Lese-ACL den Zugriff verweigerte. Bestehende Signatur- und Identitäts-
prüfungen bleiben erhalten. Echte Codesign-/ACL-Gegenproben, 15 Signaturtests
und die Prüfung derselben alten Root-/ACL-Zwischenkopie mit neuen NativeAOT-
Verifiern auf ARM64 und unter Rosetta bestehen. Das ist kein vollständiger
neuer Installerlauf und kein Windows-Nachweis.

Neun Quell-/Test-/Buildpfade sind geändert, 1.320 Quelleingaben eingefroren;
Passwort-/PIN-Regeln und Archivkryptografie bleiben unverändert. Der
Installereinstiegstest wird nun automatisch vor der Signierung ausgeführt.
Der neue Developer-ID-Build läuft unter
`build/audit/5.0.2-20260908/corrected-developer-id-build.log`. Apple hat den
korrigierten Kandidaten inzwischen unter Job
`c4d7f3a5-3a54-4954-af83-d003bc194824` mit `Accepted`, `statusCode = 0`
und `issues = null` angenommen. Der originale Einreichungs-ZIP-Hash lautet
`72de4c27b7271fa264447d535826afb425f5c7ce0c5a07538eb25113478ac76b`.
Alle 38 ursprünglichen Architektursignaturen sind gebunden;
`source-after-apple.json` bestätigt 1.320 unveränderte Quelleingaben.
Stapling, Ticketvalidierung und Gatekeeper-Annahme aller drei korrigierten
Apps bestehen inzwischen. Das endgültige Paket besteht mit 20 Wurzelobjekten,
19 Mach-O-Dateien und 38 unveränderten Slices. Die hybride Inventarprüfung
mit 149 Einträgen und die ZIP-Prüfung einschließlich aller Sidecars bestehen
auf ARM64 und unter Rosetta. Das endgültige ZIP hat 43.681.703 Bytes und
SHA-256 `820863042b5cfacb6643b1696c8fbf8412c9529d82d921d3bb7174db3dedf81d`;
`final-release-assets.json` bindet alle sechs neuen Dateien.

Der korrigierte notarisierte Kandidat besteht außerdem mit 153 von 153
Testgruppen in 410,1 Sekunden, ohne Fehler oder blockierte Gruppen;
die summierte Gruppenlaufzeit beträgt 932,8 Sekunden.
`corrected-developer-id-results-resumed/001-test-results.json` hat SHA-256
`c9ddc29c752b5c451fd6e1a9d4c30770a368b248463ddcd6c157f34746f58147`.
Alle zusätzlichen einzelnen Releaseprüfungen und manuellen Produktions-
messungen sind inzwischen bestanden: Testzeiten 194,6 Sekunden für die
Performance-Matrix, 81,6 Sekunden für 256-MiB-Paranoia und 78,3 Sekunden
für den komplexen Paranoia-Baum mit KPAR2-Reparatur. Die Gesamtlaufzeiten
betragen 194,7, 81,7 und 78,4 Sekunden. Der komplexe Lauf umfasst 18 Dateien,
20 Verzeichnisse und 221.327.790 Eingabebytes; eine beschädigte Einheit wird
repariert. Der korrigierte Releasebuild ist mit Exitcode 0 abgeschlossen.
Alle 20 Ergebnis-/Zeitdateien stimmen mit dem Index überein;
`source-after-build.json` bestätigt 1.320 unveränderte Quelleingaben und
`published-dist-assets.json` die sechs lokal bereitgestellten Dateien
bytegleich mit den privat gesicherten endgültigen Assets. Die tatsächlichen
GUI-Gegenproben für Startdialog-Abbruch, unvollständiges Paket und
Ordnerauswahl-Abbruch sind inzwischen bestanden. Nach jedem Fall bleiben
alle 129 geprüften Einträge der installierten Apps, Sidecars und Root-Anker
byte-, metadaten- und inodegleich; atime ist ausgenommen. Die Belege sind
`gui-installer-negative-cases.json` und die drei zugeordneten Nachvergleiche.
Ein Abbruch des macOS-Administratordialogs ist damit nicht geprüft; die
separate Ordnerauswahl belegt keine tatsächliche App Translocation.
Die normale Installation des vollständigen Kits unter PID 9073 scheiterte
anschließend an einer falschen Identitätsablehnung. Die folgende Korrektur
benötigt einen neuen Build und eigene Freigabenachweise. Die Ergebnisse
bleiben ihrem jeweiligen Kandidaten zugeordnet und ersetzen keine Windows-Prüfung.
Rosetta belegt keinen Test auf separater Intel-Hardware.
Der [aktuelle macOS-Prüfbericht](KEEP_VAULT_5_0_2_MACOS_AUDIT.md) führt die weiteren
Nachtests bis zum endgültigen Release. Keine dieser macOS-Prüfungen ist ein
Windows-PASS; der Windows-Port beginnt erst von der dort abschließend
bestätigten, gepushten und freigegebenen Referenz.

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

Für Windows ist die daraus folgende Anforderung separat umzusetzen und
auf Windows zu testen: Inhalts-/Objektaustausch und harmlose
Betriebssystemmetadaten dürfen nicht anhand eines ungeprüft übertragenen
Zeitstempels gleichgesetzt werden. Die macOS-ctime-Ausnahme ist keine
pauschale Windows-Ausnahme. Jede Ausnahme braucht einen kausalen Befund,
eine Positivprobe und unverändert ablehnende Manipulationsgegenproben.
Die Meldungsdarstellung braucht entsprechende DE/EN-GUI-Prüfungen auf
Windows. Weder die macOS-Probe noch Rosetta belegt Windows- oder separate
Intel-Hardware-Prüfungen.
