# Mitgelieferte Drittanbieterquellen

Deutsch | [English](VENDOR-PROVENANCE.md)

Diese Verzeichnisse werden mit lokalen Änderungen mitgeliefert, die für den macOS-Port erforderlich sind.
Die Git-Metadaten der Ursprungsprojekte werden absichtlich nicht versioniert; ihre Herkunft ist hier dokumentiert.

Erzeugt: 2026-08-15T15:46:48Z

## Kalyna-512/512

- Produktionsimplementierung: Crypto++ `CRYPTOPP_8_9_0`, abgedeckt durch den
  nachfolgenden Abschnitt zur Crypto++-Herkunft und Boost Software License.
- Der frühere Snapshot von `Roman-Oliynykov/Kalyna-reference` und der daraus
  abgeleitete Tabellenadapter von Keep Vault wurden vor v12 entfernt: Der
  festgelegte Upstream-Quellbaum enthielt keine Lizenzerteilung, daher werden
  weder seine Quellen noch eine daraus abgeleitete Binärdatei gebaut,
  gebündelt oder verteilt.
- Der v12-Adapter exportiert ausschließlich v12-spezifische Symbole. Ein
  offizieller Vektor aus DSTU 7624:2014, eine unabhängige Differenzmatrix mit
  Bouncy Castle, die Gleichheit von skalarem und parallelem Pfad sowie
  vollständige Container-KATs sichern die Änderung als Gates ab.

## Skein-reference

- Ursprung: Die Referenzimplementierung der Skein-1.3-Einreichungs-CD für NIST,
  dokumentiert durch die mitgelieferte `NIST/CD/README/readme.txt`;
  Spezifikation: https://www.schneier.com/wp-content/uploads/2015/01/skein.pdf
- Lokale Änderungen ohne reine Zeilenendendifferenzen: zwei Härtungsänderungen
  in `NIST/CD/Reference_Implementation/skein.c` und `skein_block.c`, mit
  Keep-Vault-Kommentaren markiert. Jede Initialisierungshilfe für 256, 512 und
  1024 Bit löscht ihre lokale Union für Konfiguration und Schlüsselableitung,
  jede Final-/Ausgabehilfe löscht ihre lokale Kopie des Verkettungszustands,
  und jede Blockhilfe löscht ihren vorübergehenden Tweak-Plan, Schlüsselplan,
  Arbeitszustand und ihre Nachrichtenwörter vor der Rückkehr durch volatile
  Schreibzugriffe vollständiger 64-Bit-Wörter. Elementtyp, vollständige
  Arrayabdeckung und Löschzeitpunkte bleiben unverändert; begrenzte
  ARM64-/x64-Tests prüfen die Nullsetzung und benachbarte Kontrollwerte.
  Dies verändert keine Skein- oder Threefish-Ausgaben; es löscht diese
  ausdrücklich benannten lokalen Arrays nach einer einzelnen MAC-/KDF-Operation.
  Es belegt keine vollständige Löschung von Registern oder vom Compiler
  ausgelagerten Werten. Offizielle Skein-KATs und das unabhängige Differenzgate
  mit Bouncy Castle decken die Ausgabegleichheit ab.

## cryptopp

- Ursprung: https://github.com/weidai11/cryptopp
- Release-Tag: `CRYPTOPP_8_9_0`
- Quellarchiv: https://github.com/weidai11/cryptopp/archive/refs/tags/CRYPTOPP_8_9_0.tar.gz
- Archiv-SHA-256: `ab5174b9b5c6236588e15a1aa1aaecb6658cdbe09501c7981ac8db276a24d9ab`
- Lokale Änderungen ohne reine Zeilenendendifferenzen: eine, in
  `cryptopp/cpu.cpp`, vor Ort mit `KEEP VAULT LOCAL CHANGE` markiert. Siehe
  nachfolgend „Lokale Änderung: Fähigkeitserkennung auf Apple Silicon“.
  Jede andere Datei entspricht unverändert dem Upstream-Release.
- Lizenz: Boost Software License 1.0 für die Zusammenstellung; die einzelnen
  Algorithmusdateien wurden von ihren Autoren als gemeinfrei veröffentlicht.
  Siehe `cryptopp/License.txt`.

### Lokale Änderung: Fähigkeitserkennung auf Apple Silicon

`AppleMachineInfo` in `cpu.cpp` entscheidet anhand eines Vergleichs von
`machdep.cpu.brand_string` mit der wörtlichen Zeichenfolge `"Apple M1"`,
welchen Befehlssatz ein arm64-Mac besitzt. Alles andere nimmt den unbekannten
Zweig und wird als einfaches ARMv8 gemeldet. Jede Aufrufstelle in dieser Datei,
die AES, PMULL, SHA-1, SHA-2 und CRC32 abfragt, verlangt ARMv8.2. Deshalb meldet
Crypto++ auf einem M2, M3, M4 oder M5 und auf einem M1 Pro, dessen
Modellzeichenfolge nicht `"Apple M1"` ist, diese Befehle als nicht vorhanden
und wählt seine portablen C++-Pfade auf Hardware, die sie alle implementiert.
Gemessen auf einem M5: AES-256-CTR lief mit 1876 MB/s statt 8862 MB/s.

Die Änderung fragt den Kernel statt des Marketingnamens ab:
`hw.optional.arm.FEAT_AES`, `FEAT_PMULL` und `FEAT_SHA256` über `sysctlbyname`.
Sie ist in beide Richtungen konservativ: Ein Kern ohne diese Fähigkeiten
wird wie beim bisherigen Standardverhalten als ARMv8 gemeldet. ARMv8.3 wird
niemals behauptet und von keiner Stelle in der Datei abgefragt. Veröffentlicht
ein Kernel diese Schlüssel nicht, schlägt die Abfrage fehl. Dies entspricht
der Antwort „nicht vorhanden“, sodass das bisherige Verhalten erhalten bleibt.

Außerhalb der Erkennung von CPU-Fähigkeiten wird nichts angefasst; kein
Algorithmus, keine Konstante und kein Codepfad wird verändert. Es ändert sich,
welche Implementierung einer Chiffre läuft, nicht aber ihr Ergebnis. Das
absichernde Buildgate besteht aus `tools/Build-Native-macOS.sh` und dem
Differenztest: Jede Chiffre wurde vor und nach der Änderung über 448
Kombinationen aus Schlüssel, Nonce und Länge ohne Chiffretextunterschied
verglichen; `KeepVaultMac/Packaging/NativeKats.c` besteht auf beiden Slices.

Das Ursprungsprojekt enthält denselben Fehler in `CRYPTOPP_8_9_0`, dem
aktuellen Release. Um diese Änderung zu entfernen, muss ein Release übernommen
werden, dessen `AppleMachineInfo` den Befehlssatz nicht mehr anhand der
Modellzeichenfolge bestimmt.

Die Quellen werden vollständig statt Datei für Datei mitgeliefert. Die
Algorithmusquellen können nicht einzeln herausgelöst werden: `rijndael.cpp`
und die verwandten Dateien hängen alle von `cryptlib.h`, `config.h`,
`secblock.h` und `misc.h` ab. Eine von Hand ausgewählte Teilmenge würde daher
nicht kompilieren und müsste bei jedem Update manuell gepflegt werden. Nur
die nachfolgend aufgeführten Dateien werden tatsächlich gebaut; der Rest wird
mitgeführt, damit die Ausgabe dem Upstream-Release entspricht und seine
Prüfsumme aussagekräftig bleibt.

Verwendet für:

- MARS-448 (`mars.cpp`), SHACAL-2-512 (`shacal2.cpp`),
  ChaCha20-Poly1305 (`chachapoly.cpp`, `chacha.cpp`) und den
  AES-256-Referenzfallback (`rijndael.cpp`), also Primitive, für die es zuvor
  keine Referenzimplementierung in diesem Repository gab.
- SHA-512 (`sha.cpp`) für die zweite Argon2id-Runde, die eine Referenz zum
  Vergleich mit der Plattformimplementierung benötigt; zuvor hatte nur
  SHA3-512 eine solche Referenz.
- Die Produktionsimplementierung von Kalyna-512/512 (`kalyna.cpp`) und eine
  unabhängige Testimplementierung von Threefish-1024 (`threefish.cpp`). Kalyna
  wird gegen offizielle DSTU-7624:2014-Vektoren und die separate verwaltete
  Implementierung von Bouncy Castle geprüft. Threefish läuft weiterhin mit
  den oben beschriebenen Skein-Referenzquellen und verwendet Crypto++ als
  unabhängiges Differenzorakel.

## argon2id

- Ursprung: https://github.com/alexedwards/argon2id
- Basis-Commit: `493d7dead70e0797a6cc1a189d96f7c115e073e8`
- Lokale Änderungen ohne reine Zeilenendendifferenzen: keine, ausschließlich
  CRLF-Normalisierung

## phc-winner-argon2

- Ursprung: https://github.com/P-H-C/phc-winner-argon2
- Basis-Commit: `f57e61e19229e23c4445b85494dbf7c07de721cb`
- Lokale Änderungen ohne reine Zeilenendendifferenzen: 1 Datei geändert,
  16 Einfügungen(+)

## zpaq

- Ursprung: https://github.com/zpaq/zpaq
- Basis-Commit: `9ab539f644e364f0d92e2918b90ce2534c75653f`
- Lokale Änderungen ohne reine Zeilenendendifferenzen: 3 Dateien geändert,
  2213 Einfügungen(+), 366 Löschungen(-)
  (`zpaq.cpp` +2181/-350, `libzpaq.cpp` +8/-8, `libzpaq.h` +24/-8).

Jeder native Build des Projekts prüft vor der Kompilation das geprüfte
Inventar der Drittanbieterquellen in `NATIVE_SOURCE_SHA256SUMS`. Das Manifest
verhindert außerdem, dass eine neu abgelegte Crypto++-Übersetzungseinheit
über einen Platzhalter in den Build gelangt.
