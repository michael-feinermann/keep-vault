# Keep Vault 5.0.3 Build 22: öffentliches KDF-/Schlüsselübergabe-Addendum

Status: GUI_PENDING. Keine Gesamtfreigabe und keine stabile Releasefreigabe. Die 15 realen installierten GUI-Kampagnen und der nachfolgende letzte Structure512-Test bleiben offen. Dieses Addendum führt keine neuen Produkttests aus.

Die Original-Laufzeitdaten stammen aus Phase 1 des tatsächlichen BA-Buildlaufs vom 14. Oktober 2026, mit 319/319 PASS und echtem Phase1-Exit 0. Quellstand: `ba9949ad1b93a89f75dd8078414371d1a1b7ad0d`. Das Addendum wurde am 17. Oktober zusammengestellt. Die alten Builder-/Wrapperexits bleiben UNOBSERVED; der Phase1-Nachweis beweist keine vollständige Releasefreigabe.

## Tatsächlich aufgezeichnete Laufzeitdetails

| Nachweis | Umfang | Aufzeichnungsgranularität |
|---|---:|---|
| KDF-Matrix über zwölf Suites | 626 Boundaries × vier Faultklassen = 2504 Injektionen | Konkrete Boundarynamen und je Suite/global aufgezeichnete Zähler |
| Suite-Consumer | 336 Fälle | Vollständige einzelne Laufzeit-Fallobjekte |
| MAC-Consumer | 80 Fälle | Vollständige einzelne Laufzeit-Fallobjekte |
| Recovery-Consumer | 24 Fälle | Vollständige einzelne Laufzeit-Fallobjekte |
| Owner-Lifecycle | sechs Fälle über drei Ownertypen | Ursprüngliches zusammengefasstes Laufzeitobjekt |
| ausgewählte Sicherheitsgruppen | 17 PASS-Gruppen | Originale Testresultate mit Zeiten/Seed/Status |

00 bedeutet wiederholtes Byte0x00, 01 wiederholtes Byte0x01 und FF wiederholtes Byte0xFF. missing-output simuliert einen fehlgeschlagenen Producer am tatsächlichen Managed-Handoff. Die KDF-Matrix benutzt ausdrücklich das interne 8-MiB-Fault-Injection-Profil; sie ist kein 2504-facher Produktionskosten-KDF-Lauf. Es werden keine Schlüsselbytes oder Adressen protokolliert.

Der KDF-Record enthält 626 konkrete Boundarynamen und die vier tatsächlich durchlaufenen Faultklassen. Er enthält keine 2504 separat serialisierten Einzelfallreceipts; die 2504 sind die tatsächlichen per-Suite/globalen Runtimezähler. Die Consumer-Records enthalten dagegen tatsächlich 440 einzelne Fallobjekte. In jedem sind InjectionHits=1, NoCompletedResult, CallerOwnedAliasesErased und LockAllocationBaselineRestored aufgezeichnet und geprüft. MAC wurde mit einem und zwei Workern beobachtet.

[Bytegleiche frühere BA-Auswertung](derived/original-ba-extraction/security-groups-extraction.json), [neu abgeleitete kompakte Auswertung](derived/runtime-summary.json), [exakte Originalrecord-Adressen](originals/stdout-records/record-index.json). Die frühere BA-Auswertung trägt SHA256 `752552b363a28b416b487a41c76575f2ff7ca20c08b1bd8d31f2db467578166e` und bleibt unverändert. Ihre Aussagen über damals noch laufende spätere Gates sind historische Beobachtungsgrenzen, keine aktuelle Statusbehauptung.

## Rohrecords und Herkunft

Fünf relevante Original-stdoutzeilen sind unredigiert bytegleich einschließlich Prefix und LF abgelegt. Daneben liegt jeweils der unveränderte JSON-Payload-Slice. Der Index bindet die aktuelle vollständige Originaldatei per SHA256/Bytezahl sowie jede Zeile mit 1-basierter LF-Zeilennummer, Byteoffset, Länge und SHA256. Der bereits früher gepinnte Phase1-Präfix wurde frisch byteweise nachgeprüft. Unterschiedliche CR/LF-Anzeige in Texteditoren ändert die maßgeblichen Byteoffsets nicht. Der vollständige Builderstdout wird nicht veröffentlicht.

[KDF-Record](originals/stdout-records/kdf-handoff-matrix.json), [Suite-Consumer](originals/stdout-records/suite-consumer-matrix.json), [MAC-Consumer](originals/stdout-records/mac-consumer-matrix.json), [Recovery-Consumer](originals/stdout-records/recovery-consumer-matrix.json), [Owner-Lifecycle](originals/stdout-records/owner-lifecycle.json).

## Sourcezählungen und Grenzen

Die 48 Destination-Cleanup-Fälle sind ausschließlich aus den eingefrorenen Source-Schleifen enumeriert. Die zugehörige Gruppe bestand tatsächlich; ein eigener Runtimecounter48 wurde nicht ausgegeben. Die volle relevante öffentliche Testsource und der ältere Cleanup-Methodenauszug sind deshalb getrennt unter [source](source/) abgelegt. Originale Runtimegruppenresultate stehen unter [Phase1](originals/phase1/).

Managed null/default beziehungsweise missing-output vor NativeDispatch ist von einem tatsächlichen NULL-Pointer am nativen ABI zu unterscheiden. Das Addendum behauptet die separaten 322/214 nativen ABI-Kampagnen nicht aus diesen Managed-Daten. Deren Originalbelege liegen in der getrennten öffentlichen Build22-Nachweissammlung. Gültige konstante primitive Testschlüssel bleiben positive mathematische Referenztests; degenerierte produktabgeleitete Ausgaben werden an den aufgezeichneten Übergaben verworfen.

Die Beobachtung deckt deklarierte caller-sichtbare Aliase, Ownereigentum und Lock-Buchhaltung ab. Sie beweist keine vollständige Löschung beliebiger interner Spans oder physischen RAMs und keine generelle Absicherung gegen beliebige Pointerkorruption. Sourcezählung, Gruppenzähler und einzelne Runtime-Fallobjekte werden nicht vermischt. Keine Windows-, physische Mehr-TiB- oder externe Auditgarantie.

## Inhaltsprüfung und Dateiverifikation

Nur öffentliche synthetische Testdaten. Keine privaten Schlüssel, Passwörter, Keychain-/VeraCrypt-Speicherpfade, Roh-Maus-/Entropierecords, Screenshots oder fremden App-/Prozesslogs. Private steuernde Buildbelege werden nicht kopiert. Die originale BA-Auswertung referenziert einen builder-start-Dateihash, veröffentlicht aber dessen Inhalt nicht. Diese Sammlung ist eine kuratierte Teilmenge, keine vollständige portable Wiederholung des zentralen Live-Proofs.

[Herkunftsmanifest](ORIGIN-MANIFEST.json), [Inhaltsprüfung](PRIVACY-REVIEW.json), [Scope](SCOPE.json), [SHA256SUMS](SHA256SUMS).
