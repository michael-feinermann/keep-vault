# Keep Vault v12 unter Windows aktualisieren

Dieses Dokument ist die Arbeitsanleitung für den späteren Windows-Port. Die
macOS-Umsetzung ist der normative v12-Stand. Die Windows-Version wird separat
gebaut und getestet; ein erfolgreicher macOS-Lauf ist kein Windows-Nachweis.

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
   Dependency-Update geändert werden.
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
5. Als letzter funktionaler Test ein komplexer Ordnerbaum mit leeren Dateien,
   sehr kleinen und großen Dateien, zufälligen und stark komprimierbaren
   Daten, ungewöhnlichen Unicode-Namen, verschachtelten Verzeichnissen und
   absichtlich ähnlichen Dateinamen. Archivieren, verschlüsseln, entschlüsseln,
   entpacken, Hashes und Metadaten vergleichen.
6. Release-Verifier, Authenticode-/Manifestprüfung und Tamper-Tests für jede
   EXE, DLL, jedes Manifest und die ZIP-Datei.

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
