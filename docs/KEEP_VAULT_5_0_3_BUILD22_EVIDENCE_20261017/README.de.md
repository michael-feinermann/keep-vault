# Keep Vault 5.0.3 Build 22: Teilnachweise vom 17. Oktober 2026

Status: GUI_PENDING. Keine Gesamtfreigabe und keine stabile Releasefreigabe. Die 15 realen installierten GUI-Kampagnen und der anschließende letzte Structure512-Test stehen noch aus.

Kompilierter Quellstand: `ba9949ad1b93a89f75dd8078414371d1a1b7ad0d`. Builddatum 14. Oktober 2026; neue Messungen und ABI-Prüfungen vom 17. Oktober 2026. AOT-Core-SHA256: `a52e743157b1930c0a922a6e76230751801b6820c0b7e401ea766f6c4060e509`. Version 5.0.3, Build 22.

Die Kampagne übernimmt 39 erhaltene tatsächliche Originalphasen und ergänzt 10 fehlende Gate-Rollen.16 neue Prozesse umfassen 12 frische Messungen und 4 weitere Prüfgruppen. Neuer Worker 63573: tatsächlicher Exit 0. Alte Builder-/Wrapperexits bleiben UNOBSERVED;49 ursprüngliche Phasen oder deren Exit 0 werden nicht behauptet. [Scope](SCOPE.json), [Originalkampagne](originals/provenance/recovery-campaign-result.json).

## Zwölf neue 1-GiB-Messungen bei Kompressionsstufe 3

Jede Zeile verarbeitet 1073741824 Byte, also 1024 MiB Quelle. Erhaltener Managed-Release-Harness mit endgültigen signierten Native-Bibliotheken, kein Ersatz für die installierte AOT-GUI. Ein vollständiger Lauf je Suite, kein Warmup, keine Wiederholungsmediane und keine statistische/kausale Geschwindigkeitsrangliste. Frische Faktoren und Salze können die KDF-Arbeit ändern.

| Suite | Archiv s | MiB/s | Extraktion s | MiB/s | Gesamtworkflow s | MiB/s |
|---|---:|---:|---:|---:|---:|---:|
| Standard | 306,171 | 3,345 | 316,519 | 3,235 | 663,555 | 1,543 |
| XChaCha über AES | 384,736 | 2,662 | 348,749 | 2,936 | 778,581 | 1,315 |
| Mixed | 288,834 | 3,545 | 253,347 | 4,042 | 582,959 | 1,757 |
| Paranoia | 288,799 | 3,546 | 259,811 | 3,941 | 592,782 | 1,727 |
| Threefish-1024 | 278,125 | 3,682 | 253,262 | 4,043 | 573,247 | 1,786 |
| Kalyna-512/512 | 277,165 | 3,695 | 255,929 | 4,001 | 574,591 | 1,782 |
| SHACAL-2/512 | 279,866 | 3,659 | 250,939 | 4,081 | 571,486 | 1,792 |
| MARS-448 | 285,664 | 3,585 | 253,365 | 4,042 | 578,524 | 1,770 |
| AES-256 | 285,073 | 3,592 | 252,917 | 4,049 | 577,765 | 1,772 |
| Camellia-256 | 278,609 | 3,675 | 253,423 | 4,041 | 573,228 | 1,786 |
| Serpent-256 | 279,542 | 3,663 | 253,094 | 4,046 | 573,567 | 1,785 |
| XChaCha20-Poly1305 | 276,726 | 3,700 | 251,897 | 4,065 | 570,061 | 1,796 |

Archiv/Extraktion sind Servicezeiten. Gesamt enthält KPAR2-Erstellung, gesunde Recoveryprüfung, Struktur-/Hashvergleich und Cleanup. Setup/Faktorvorbereitung liegen außerhalb. Durchsatz zählt die ursprüngliche Quelle einmal; komprimierte Bytes und wiederholte Prüflesevorgänge erhöhen den Quellnenner nicht. [Kompakte Daten](derived/measurements.json), [Originalprofile](originals/measurements/), [vollständige abgeleitete Formattabelle](derived/formatter-output/one-gib-tables.json).

## Acht additive äußere Makroabschnitte

A1 Speicherzulassung/ursprünglicher Snapshot; A2 Archivieren/Verschlüsseln; A3 zusätzlicher Containerhash; A4 KPAR2-Erstellung; A5 gesunde Recoveryprüfung; A6 Entschlüsseln/Extrahieren; A7 ursprünglicher Vergleich und unabhängiger Struktur-/Hashvergleich; A8 Ressourcen-/Fixture-Cleanup. Nur diese acht zusammenhängenden Intervalle addieren sich zum Gesamtworkflow. Anzeige gerundet, ungerundete Summe innerhalb dokumentierter Numeriktoleranz.

| Suite | A1 s | A2 s | A3 s | A4 s | A5 s | A6 s | A7 s | A8 s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Standard | 0,008 | 306,175 | 0,544 | 27,338 | 11,383 | 316,519 | 1,499 | 0,090 |
| XChaCha über AES | 0,009 | 384,747 | 0,535 | 30,209 | 12,758 | 348,749 | 1,490 | 0,085 |
| Mixed | 0,009 | 288,843 | 0,527 | 27,414 | 11,422 | 253,347 | 1,345 | 0,052 |
| Paranoia | 0,009 | 288,803 | 0,525 | 29,498 | 12,675 | 259,811 | 1,367 | 0,097 |
| Threefish-1024 | 0,008 | 278,129 | 0,548 | 28,050 | 11,808 | 253,262 | 1,350 | 0,091 |
| Kalyna-512/512 | 0,009 | 277,169 | 0,522 | 27,767 | 11,670 | 255,929 | 1,412 | 0,113 |
| SHACAL-2/512 | 0,009 | 279,870 | 0,524 | 27,407 | 11,317 | 250,939 | 1,336 | 0,085 |
| MARS-448 | 0,008 | 285,668 | 0,518 | 26,547 | 10,966 | 253,365 | 1,358 | 0,093 |
| AES-256 | 0,008 | 285,077 | 0,524 | 26,746 | 10,996 | 252,917 | 1,445 | 0,052 |
| Camellia-256 | 0,009 | 278,611 | 0,518 | 27,576 | 11,520 | 253,423 | 1,459 | 0,112 |
| Serpent-256 | 0,008 | 279,545 | 0,525 | 27,503 | 11,363 | 253,094 | 1,447 | 0,082 |
| XChaCha20-Poly1305 | 0,008 | 276,729 | 0,537 | 27,748 | 11,562 | 251,897 | 1,502 | 0,078 |

Die 48 inneren Aggregate sowie Cipher-, Pipe-, Payload-, KDF-, Native-Callback- und MAC-Unterphasen überlappen verschachtelt/parallel. Nicht zu Gesamtzeit oder CPU-Aufteilung addieren. ZpaqArchive misst den Streamingaufruf samt Pipeline; ZpaqNativeExitWait ist Warten auf das Prozessende, keine reine Kompressions-CPU. Zusätzliche Paranoia-Stufen und zweite KDF-Runde wurden ausgeführt; Einzelzeiten begründen keine kausale Suite-Rangliste.

Die Profile selbst melden Energiezustand NOT OBSERVED. Separat erhaltene Vor-/Während-/Nach-Strombeobachtungen zeigen für diese neue Kampagne Netzbetrieb an diskreten Punkten. Maximale Abstände stehen in den Receipts. Kontinuierlicher Netzbetrieb, gleiche Cachebedingungen oder fehlende thermische Drosselung werden nicht behauptet.

## Native ABI-Grenztests

| Gate | Architektur | Fälle | Architektur-PID | Exit | äußerer Wrapper-PID / Exit |
|---|---|---:|---:|---:|---|
| Native NULL/ABI | arm64 |161|70725|0|70676 /0|
| Native NULL/ABI | x86_64 |161|70765|0|70676 /0|
| Ergänzende leere/konstante Schlüsselgrenzen |arm64|107|einzelne Kind-PIDs im Index|0|70975 /0|
| Ergänzende leere/konstante Schlüsselgrenzen |x86_64|107|einzelne Kind-PIDs im Index|0|70975 /0|

Native322: 161 Fälle je Architektur, 322 insgesamt. Supplement214: 107 je Architektur, 214 insgesamt. Namen, Kind-PIDs/Exits und Library-SHA256: [Fall-/Bibliotheksindex](derived/native-cases-and-libraries.json), [Native322-Originale](originals/native322/), [Supplement214-Originale](originals/supplement214/). SHA3-Referenzbibliotheken stammen aus dem ursprünglichen Native-Build und sind keine ausgelieferten Produktbibliotheken. Gültige konstante öffentliche Testschlüssel dürfen mathematische Referenztests passieren; degenerierte produktabgeleitete Schlüssel sind davon zu unterscheiden. Dies sind exakt aufgezeichnete Fälle, keine Garantie gegen jeden Speicherfehler, kein universeller Kryptobeweis und kein externer Audit.

## Lokale Paketprüfung und Herkunft

Lokale Prüfung: Wrapper 70677, tatsächlicher Exit 0, 126 Prüfkommandos, bytegleiche Umbenennung des lokalen Asset-Satzes. GitHub-Download-/Veröffentlichungsprüfung dabei NOT_RUN. [Abgeleitete Zusammenfassung](derived/local-verification-summary.json), [Original-Outer](originals/local-verification/root-outer-terminal.json), [Original-Kit](originals/local-verification/local-kit-receipt.json).

Unter originals liegen ausgewählte bytegleiche JSONs oder JSON-Stdout-Receipts. Unter derived liegen klar abgeleitete Tabellen/Zusammenfassungen; die Formattabelle ist eine bytegleiche Kopie eines schon abgeleiteten Outputs. Große 12-MB-/7-MB--Kontrolldumps, Binärdateien und Rohlogs fehlen bewusst. Die Sammlung ist keine vollständige portable Kopie der Ausführungsumgebung. Herkunftspfade und SHA256/Bytezahlen: [Herkunftsmanifest](ORIGIN-MANIFEST.json). [Dateihashes](SHA256SUMS).

Die Inhaltsprüfung hat private Signing-Speicherpfade in builder-start.json erkannt und diese Datei vor jeglicher Kopie vollständig ausgeschlossen. Enthalten sind keine privaten Signing-/Wrapping-Schlüssel, Keychaininhalte, Passwörter, Roh-Maus-/Entropierecords, Rohscreenshots oder fremden App-/Prozesslogs. Absolute Herkunftspfade betreffen nur öffentliche Entwicklungs-/Build-/Test-/Toolchainartefakte. [Prüfprotokoll](PRIVACY-REVIEW.json).

Windows, physische Mehr-TiB-Prüfung und externer unabhängiger Audit sind nicht belegt. GUI15 und der nachfolgende letzte 512-Test bleiben offen. Keine Stable-Releasefreigabe aus diesen Teilnachweisen.

Diese kuratierte öffentliche Teilmenge ermöglicht keine vollständig eigenständige Wiederholung des zentralen Live-Proofs. Zurückgehaltene Build-/Steuerbelege sind ausschließlich mit Hash verzeichnet und werden nicht als öffentlich mitgelieferte Originale dargestellt.
