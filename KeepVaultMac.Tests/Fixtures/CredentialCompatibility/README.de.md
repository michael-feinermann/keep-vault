# Synthetische v12-Testarchive für die Kompatibilität von Zugangsdaten

Deutsch | [English](README.md)

Diese Dateien enthalten ausschließlich öffentliche, absichtlich synthetische Zugangsdaten und einen festen Kontrolltext. Sie sind keine Archive, die mit einer veröffentlichten Anwendung erstellt wurden. Ihre Faktoren, Zugangsdaten, Salts oder Nonces dürfen niemals für echte Daten verwendet werden.

Sie dienen dazu, die Lesbarkeit von Archiven von den Regeln für die Auswahl neuer Zugangsdaten zu trennen. Alle sechs `.kzpaq`-Dateien sind echte v12-Container mit einem echten, zweifach authentifizierten und verschlüsselten KPAR2-v4-Sidecar, das an ContainerVersion 12 gebunden ist. Der Erzeuger verwendete den aus PMI abgeleiteten Argon2id-Produktionsspeicher, t=4 und p=4. Es war keine Überschreibung der Speicherkosten aktiviert. Der PIN-Teilstringfall verwendet die Paranoia-Suite mit zwei Runden; die anderen Fälle verwenden AES-256.

| Testarchiv | Verstöße gegen die Auswahlregeln und Kontrollwerte für Rohbytes |
| --- | --- |
| `empty` | Leeres Passwort und leere PIN |
| `short` | Passwort mit einem Zeichen und PIN mit einer Ziffer |
| `oversized-raw` | Passwort mit mehr als 256 UTF-16-Codeeinheiten, 17-stellige PIN, führende und abschließende Leerzeichen, zerlegte Unicode-Darstellung, führende Null in der PIN |
| `pin-substring` | Die gesamte PIN kommt wörtlich im Passwort vor; Paranoia-Suite |
| `date-2026-09-06` | Die PIN entspricht DDMMYYYY für das eingefrorene lokale Datum 2026-09-06 |
| `model-and-old-pattern` | Bisher akzeptierte deutsche Wortfolge und aufsteigende PIN `123456` |

Das Manifest legt die tatsächlichen UTF-8-Passwortbytes, ASCII-PIN-Bytes, beide vollständigen v12-Credential-Hashes, Dateihashes und Sidecar-Hashes fest. Die Prüfung der Datumsregel des Testarchivs verwendet ausdrücklich das eingefrorene Datum; der Test hängt nicht davon ab, an welchem Tag ein späterer CI-Lauf ausgeführt wird.

## Herkunft des Erzeugers

Der private Quellsnapshot stammt aus Commit `e52159e7a569a8b77fe7732006388c4401c4009f` (5.0.1). `generator-policy-patch.json` dokumentiert genau drei entfernte Prüfungen, die jeweils durch einen ausdrücklichen NURTEST-Kommentar ersetzt wurden:

1. Die Passwortauswahlprüfung des Writers für die Erstellung.
2. Die PIN-Auswahlprüfung des Writers für die Erstellung.
3. Die alte PIN-Auswahlprüfung in `DeriveMaster`.

Es wurde keine Umgehungsmöglichkeit im Produkt eingeführt. `V12MasterKdf.cs`, `KdfPrimitives.cs`, `SuiteKeySchedule.cs` und `RecoveryService.cs` sind bytegleich mit dem eingefrorenen Commit, wie in `source-provenance.json` dokumentiert. Der Writer und der Ableitungswrapper unterscheiden sich nur durch die dokumentierten Regelkommentare. `FixtureBuilder.cs.txt` enthält den genauen Quelltext des Erzeugers und wird absichtlich weder vom Produkt noch von den Tests kompiliert.

Die nativen Komponenten wurden unverändert aus der installierten Anwendung 5.0.1, Build 12 kopiert. `native-provenance.json` dokumentiert jeden SHA-256-Wert. Es wurden weder native Kompilation noch erneute Signierung, Installation oder Notarisierung ausgeführt. ZPAQ verwendet den bestehenden geschützten nativen Anker über die reguläre Produktions-API.

Die endgültige Erzeugung verwendete SDK 10.0.400, Commit `14fbf8d527`, Runtime 10.0.11, bereitgestellt durch `Provision-VerifiedDotnet-macOS.sh` aus dem Repository. Der Provisioner prüfte vor der Ausführung den festgelegten SHA-512-Wert des Microsoft-Archivs. Der Generator verwendete ein leeres privates HOME, private NuGet-/Cache-/Arbeitsverzeichnisse und eine bereinigte Umgebung. Jede direkte Paketversion in seinem privaten Projektgraphen war exakt festgelegt. Ein frischer Restore aus dem offiziellen Feed erzeugte private Lockdateien; anschließend folgte `build --no-restore --no-incremental`. Der historische zweite Restore kombinierte `--locked-mode` mit `--force-evaluate` und darf daher nicht als Nachweis eines wirksamen Locked-Mode gelten. Die historischen Formulierungen in `source-provenance.json` und `package-provenance.json` werden durch die nachfolgende separate strikte Restore-Prüfung ersetzt. Der Generator verwendet absichtlich ausschließlich JIT; AOT und Trimming sind deaktiviert. Er ist keine ausführbare Releasedatei.

Die genauen privaten Projektdateien, zwei Lockdateien, die NuGet-Konfiguration und das Startskript für die bereinigte Umgebung liegen den Testarchiven bei. `package-provenance.json` dokumentiert alle 56 aufgelösten Paketidentitäten und Inhaltshashes; sie stimmen mit den entsprechenden eingefrorenen 5.0.1-Abhängigkeiten überein. `verified-source-before.json` und `verified-source-after.json` belegen, dass alle 87 Quell-/Projekteingaben während des endgültigen Builds und der Erzeugung identisch blieben. Native Komponenten wurden erst nach dem Build mit `Stage-TestNatives-macOS.sh` bereitgestellt; das Staging-Gate bestand die Signatur-/Team-/Entitlement-Prüfung und die Bytevergleiche zwischen Original und Kopie.

Die frühere Erzeugung der Testarchive mit dem Homebrew-SDK wurde vollständig ersetzt. Zwei anschließende Diagnoseversuche für Reader-Builds in der vorhandenen Umgebung stoppten vor der Kompilation: zunächst NU1004, weil das Deaktivieren von AOT/Trimming die gesperrte Abhängigkeitsmenge änderte, danach NU1403 für den vorhandenen ILCompiler-/ILLink-10.0.11-Cache. Kein abweichendes Paket wurde akzeptiert; weder eine Repository-Lockdatei noch ein globaler Paketcache wurde verändert. Die endgültigen Tests des aktuellen Readers laufen separat über die verifizierte Pipeline `tools/Test-KeepVault.sh`.


## Nachtrag zur strikten Abhängigkeitsprüfung

`strict-restore-addendum.json` dokumentiert eine spätere Prüfung mit den exakt archivierten privaten Lockdateien und dem ursprünglich verifizierten SDK, ohne einen Pakethash zu ändern oder ein Testarchiv neu zu erzeugen. Die wirksamen MSBuild-Eigenschaften wurden ausdrücklich als `RestoreLockedMode=true` und `RestoreForceEvaluate=false` bestätigt. Der Restore lief anschließend mit `--locked-mode --force -p:RestoreForceEvaluate=false` und wurde erfolgreich beendet. Beide privaten Lockdateien blieben bytegleich mit ihren archivierten Kopien; alle 87 Quell-/Projekteingaben blieben ebenfalls identisch. `strict-restore-check.sh.txt` und `strict-restore-check.log.txt` bewahren den genauen Befehl und seine Ausgabe auf.

Das ursprüngliche Manifest und die Erzeugerprotokolle behalten ihre historischen Hashes. Der Test legt diesen Nachtrag und seine Protokollhashes unabhängig fest, sodass der korrigierte Abhängigkeitsnachweis zusammen mit dem ursprünglichen Manifest geprüft wird. Dies ist eine strikte Prüfung der Abhängigkeitskonsistenz für die bereits erzeugten Testarchive, keine neue Erzeugung der Testarchive und kein Releasebuild.

## Unabhängiges Byteorakel

Der Erzeuger rahmt die Rohfelder selbst mit vier Byte langen Little-Endian-Längenwerten. Er verwendet Bouncy Castle 2.6.2 SHA3-512 für beide Faktorhälften und dessen schlüsselgebundene, personalisierte Skein-MAC-1024-1024-Implementierung für den Zweig mit vollständigen Faktoren. Für diese Erwartungswerte verwendet er weder die Framing- noch die Digest-Hilfen der Produktion. Beide unabhängigen Ergebnisse müssen den Credential-Funktionen der Produktion entsprechen, bevor ein Testarchiv geschrieben wird. Dies prüft die internen KDF-Eingaben unabhängig von einem Container-Roundtrip.

Die ursprünglichen Zeichenfolgen mit zerlegter Unicode-Darstellung und erhaltenen Leerzeichen bleiben die kryptografischen Eingaben. Normalisierte Zeichenfolgen werden im Test ausschließlich als negative Kontrollwerte verwendet. Der Testarchivgenerator verwendet deterministische synthetische Faktoren, Salts und Nonces sowie den regulären Sidecar-Generator. Zeitstempel und Sidecar-Entropie führen dazu, dass eine erneute Erzeugung andere Container- oder Sidecar-Bytes liefern kann; sie erfordert eine neue Prüfung und ausdrückliche Aktualisierungen sämtlicher festgelegter Hashes.

## Registrierte Tests

`CredentialCompatibilityTests.Tests` stellt zwei leichte Gruppen und sechs Gruppen mit Produktions-Argon bereit:

- `credentials.static-fixture-provenance` prüft das festgelegte Manifest, Erzeugernachweise, Dateien, Rohkodierung und unabhängige Credential-Vektoren. Es prüft positiv, dass der Test-Hook zum Verbieten von Modellaufrufen sowohl bei der Auswertung als auch beim direkten Laden des Modells vor jedem Ressourcenlesen auslöst.
- `credentials.creation-still-rejects` prüft bisherige und neue Regelgründe und lehnt tatsächliche Versuche zur Neuerstellung von Archiven ab, bevor eine Ausgabe veröffentlicht wird. Der Wortfolgenfall muss ausdrücklich ein verfügbares Modell verwenden, um einen bisherigen Wert von mindestens 128 unter 128 zu senken, damit fehlende Modelldaten nicht als erfolgreiche Korrektur erscheinen können.
- `credentials.read-*` führt direkte Entschlüsselung, ZPAQ-Auflistung, Entpacken, intakte duale KPAR2-Prüfung, Ablehnung eines manipulierten Containers vor jeglichem Klartext, exakte KPAR2-Rekonstruktion in einen separaten Kandidaten sowie Entschlüsselung des reparierten Kandidaten aus. Der kurze Fall lehnt zusätzlich ein falsches Wiederherstellungspasswort ab. Jeder Lesevorgang läuft in einem Scope, der bei jeder Passwortmodellauswertung oder jedem direkten Laden eine Ausnahme auslöst; die abschließende Anzahl der Versuche muss null sein.

Die sechs Lesegruppen reservieren 4 CPU-Tokens und 2560 MiB, verwenden Argon und halten die ZPAQ-Prozessbeschränkung. Sie verwenden weder GUI noch Kamera-, Installations- oder Signierdienste.
