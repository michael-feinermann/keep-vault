# Keep Vault v12 für macOS: normative Releaseanforderungen

Status: verbindliche Spezifikation und Releasecheckliste für die macOS-Ausgabe von Keep Vault 5.0.0, Build 12. Windows ist nicht Bestandteil dieses Releases und wird in einem eigenen Arbeitsschritt aktualisiert.

## Formatgrenze

Diese Anwendung schreibt und liest ausschließlich Container mit der Magic `KZPAQ2\0` und `Version = 12`. `KZPAQ1\0` sowie jede andere Magic werden vor Headerverarbeitung und KDF abgewiesen. Alle produktiven Krypto-, Rollen-, Tweak-, Nonce- und Authentifizierungsdomains tragen `/v12/`. Es gibt weder einen v11-Leser noch eine automatische Migration, eine Legacy-Domain oder einen Fallback auf ältere Formate. Ein Container mit einer anderen Versionsnummer muss vor KDF, Authentifizierung, Entschlüsselung und Ausgabe abgewiesen werden.

KPAR2 bleibt ein eigenständiges Format der Version 4. Bei verschlüsselten Archiven ist im Locator und in der authentifizierten Metadatenhülle `ContainerVersion = 12` gebunden. KPAR2 v4 darf keine Container anderer Generationen reparieren. Ein unverschlüsseltes KPAR2-Fehlerkorrekturprofil verwendet weiterhin `ContainerVersion = 0` und stellt keine Authentizitätsbehauptung auf.

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

Die Containerpipeline hält genau zwei 16-MiB-Slots. Der parallele Container-MAC verwendet 1-MiB-Blätter und höchstens 64 Worker. Poly1305 wechselt ab 1 MiB auf höchstens 64 blockausgerichtete Worker und behält einen seriellen Differenzpfad. ZPAQ-Worker sind ebenfalls auf 64 begrenzt. Für den Pipe-Pfad gelten pro Frame 24 MiB komprimiert, 32 MiB unkomprimiert und 128 MiB Modellgröße sowie insgesamt höchstens 512 MiB wartende komprimierte Frames. Der gemeinsame native Verarbeitungsrahmen beträgt 6 GiB; ein Kompressionsjob reserviert 384 MiB, ein regulärer Job 592 MiB. Reguläre Jobs sind auf 64 MiB Ausgabe und 512 MiB Modellgröße begrenzt. Ein bereits authentifiziertes reguläres Archiv auf stdin darf höchstens 512 GiB groß sein. Für Entpackziele gelten 500 GiB insgesamt, 500 GiB pro Datei, 500.000 Einträge, 512 MiB Index und höchstens 2^26 Fragmente. Diese Werte sind Format- beziehungsweise Ressourcengrenzen und dürfen nicht durch unbeschränkte Queues oder stilles Resynchronisieren umgangen werden.

KPAR2-Parität, Shardprüfsummen, Verifikation und Rekonstruktion verteilen unabhängige Stripes beziehungsweise Shards auf höchstens 64 Worker. Jeder Worker schreibt ausschließlich in disjunkte Bereiche; Manifest, Locator und reparierter Container bleiben kanonisch geordnet. Der Ein-Worker-Pfad und der Produktionspfad müssen byteidentische Parität und Rekonstruktion liefern.

## Pflichtgates

Vor einem Release müssen auf echter Apple-Hardware mit dem durch `global.json` exakt festgelegten offiziellen SDK 10.0.400 alle folgenden Gates erfolgreich sein. Das macOS-arm64-SDK-Archiv ist zusätzlich auf SHA-512 `e440e9a58d4ff7741c8342ac3e086fa9ee2dadc25e01c0449a88317a74cfbd63625b8092c3b2a131ae14b16ab3401e9cc470e578e4c65a72a0b5786bd2308cde` festgelegt und vor sowie nach dem Entpacken zu prüfen. Restore, Build, Publish und Testausführung müssen einen frisch erzeugten, auf Besitzer, Modus und Geräte-/Inodenummer gebundenen privaten NuGet-, SDK- und Artefaktbaum verwenden. Weder `obj` noch `bin` aus dem Repository dürfen in einen Releaseprozess einfließen.

1. Locked Restore, Release-Build und Native-Build für arm64 und x86_64 beziehungsweise Universal. Die Test-Natives werden erst nach dem letzten Projektbuild in das Testausgabeverzeichnis gestaged. Danach laufen die Tests mit `--no-build --no-restore`.
2. Spec-Lint ohne aktive v11-Produktionsklasse, v11-Domain, Versionskonstante oder v11-Native-Export.
3. Statische KATs und unabhängige Referenztests für KDF, MACs, alle Cipher und die zehn Suite-Kompositionen.
4. Der vollständige Testlauf einmal mit `--parallel 1` und einmal mit einer sicher ermittelten parallelen Workerzahl. Beide Läufe müssen dieselbe Testmenge erfolgreich abschließen.
5. Der ausdrücklich ausgewählte Produktions-KAT `containers.v12-production-worker-equivalence`.
6. Der manuelle Performance-Lauf `performance.cipher-suites` misst alle zehn Cipher Suites und Kaskaden als 256-MiB-Rohprimitive sowie je dreimal über den vollständigen v12-Containerpfad für Verschlüsselung und Authentifizieren-vor-Klartext plus Entschlüsselung. Die Containerwerte verwenden das reale Produktions-Argon2id und werden als Median ausgegeben. Zusätzlich muss `performance.paranoia-256mib-e2e` exakt 256 MiB mit Kompressionsstufe 5, Paranoia und dem realen Produktions-Argon2id vollständig archivieren, verschlüsseln, KPAR2 prüfen, entschlüsseln und entpacken. Beide laufen mit `--performance --parallel 1` auf einem sonst ruhenden Host und dürfen keine Sicherheitsprüfung auslassen.
7. KPAR2-v4-Commit-, Reparatur-, Fault-Injection- und Objektbindungstests sowie Container/ZPAQ-End-to-End-Tests für Erstellen, Authentifizieren, Entschlüsseln und Entpacken.
8. Bundle-, Native-Slice-, Entitlements-, Hybrid-Signatur-, QR-Companion- und Installationsprüfung. Private Schlüssel, Passwörter und Wrapping Keys werden weder ausgegeben noch protokolliert oder in das Repository kopiert.
9. Ein öffentliches Release benötigt eine gültige Developer-ID-Application-Signatur, erfolgreiche Apple-Notarisierung, ein gestapeltes Ticket und erfolgreiche Prüfungen mit `stapler validate` sowie `spctl`. Eine Apple-Development-Signatur ist kein veröffentlichbares Ergebnis.

Der letzte funktionale Releasegate ist `performance.paranoia-complex-tree-e2e`: eine heterogene tiefe Ordnerstruktur mit leeren, versteckten und Unicode-Pfaden sowie stark unterschiedlichen Dateigrößen wird mit Kompressionsstufe 5, Paranoia und realem Produktions-Argon2id verarbeitet. Anschließend wird ein authentifizierter KPAR2-Schaden repariert und die vollständige Pfad-, Typ-, Größen- und SHA-256-Menge nach Entschlüsselung und Entpacken verglichen. Nach diesem Gate dürfen nur noch unverändernde Paket-, Git- und Veröffentlichungsprüfungen stattfinden; jede Code- oder Artefaktänderung macht den Gate ungültig.

Der Build darf erst als veröffentlicht bezeichnet werden, wenn der signierte und notarisierte Inhalt exakt dem geprüften Archiv entspricht, der Tag `v5.0.0` auf dem geprüften Commit liegt und das öffentliche Release genau diese Artefakte enthält. Existiert außerhalb der sichtbaren Git-Historie bereits eine verteilte Version 5.0.0 oder Build 12, muss vor Veröffentlichung eine neue monotone Versions- beziehungsweise Buildnummer gewählt werden.

## Vertraulicher Ausdruck

Der physische Schlüsselzetteldruck schreibt keine App-PDF. Trotzdem können CUPS, Drucker, Netzwerk-Druckserver oder Gerätespeicher den geheimen Auftrag zwischenspeichern. Vor dem Spoolen muss die App ausdrücklich warnen und eine Bestätigung verlangen. Gedruckt werden darf nur an einen vertrauenswürdigen, physisch kontrollierten Drucker. Keep Vault kann Kopien außerhalb des eigenen Prozesses nicht löschen.
