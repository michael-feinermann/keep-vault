# Native Analyse für Windows 5.0.2

Stand: 15. September 2026. Dieser Bericht dokumentiert einen begrenzten
Quellcode- und Fehlerpfad-Review mit MSVC 19.44 / Visual Studio 2022
17.14.40. Er ersetzt weder die vollständigen Laufzeittests noch die Prüfung
der tatsächlich veröffentlichten, signierten Artefakte.

## Behobene Befunde

**Argon2: vorzeitige Freigabe nach spätem Threadfehler.** Der Fehlerpfad in
`external/phc-winner-argon2/src/core.c` verglich den kumulativen
Completion-Zähler mit der Zahl noch gehaltener Workerhandles. Bereits
erfolgreich gejointe Worker erhöhten weiter den ersten Wert, während der
zweite sank. Nach einem späteren Create-/Join-Fehler konnte deshalb die
Warteschleife übersprungen werden, obwohl ein Worker noch auf Instanz,
Jobtabelle und Completion-Zähler zugreifen konnte. Wenn auch die erneuten
Join-/Detach-Aufrufe scheiterten, durfte die Freigabe zu früh beginnen.

Der Fehlerpfad wartet jetzt auf die Gesamtzahl erfolgreich gestarteter
Worker. Die Lane-/Threadzahlen werden vor den Allokationen validiert und
unveränderlich übernommen. Verbleibende Joins arbeiten über die tatsächlich
gesetzten `started`-Einträge. Das Argon2-Verfahren und seine Parameter sind
unverändert.

**Feste Stacklast reduziert.** Die Threefish-Tabellen für maximal 1024
Worker, der Windows-ZPAQ-Testpfad sowie die großen ZPAQ-Eingabe-, LZ- und
Modellpuffer belegen keinen entsprechend großen festen Stackframe mehr.
Threefish allokiert Tabellen für die tatsächlich benötigte Workerzahl vor
dem ersten Threadstart; Allokationsfehler können daher keine laufenden
Worker zurücklassen. Die Tabellen werden erst nach dem Completion-Nachweis
gelöscht und freigegeben. Kryptografische Block-/Schlüsselberechnung und
Workeraufteilung wurden nicht verändert. ZPAQ verwendet für den
Eingabepuffer den bereits vorhandenen löschenden `StringBuffer`; der
LZ-Ausgabepuffer wird beim Destruktoraufruf ebenfalls überschrieben.

**Nicht rückkehrende Fehlerfunktionen korrekt deklariert.** `libzpaq::error`
wirft in der gemeinsamen Windows-/macOS-Implementierung immer eine
Ausnahme. Der Header verlangt bereits, dass die Funktion nicht zurückkehrt;
`[[noreturn]]` bildet diesen Vertrag jetzt ab. Der Argon2-CLI-Fehlerhandler
ruft `exit(1)` auf und trägt die entsprechende Compilerannotation. Die
vorherigen NULL-Pointer-Warnungen C6011/C6387 entstanden hinter diesen
Fehlerpfaden; das Laufzeitverhalten wurde nicht gelockert.

**ZPAQ-Pivotrechnung ohne unnötige Verengung.** Die Differenz zweier
Arrayzeiger bleibt jetzt `std::ptrdiff_t`. Die beanstandete Verdoppelung
war nach der vorherigen Division durch acht bereits begrenzt; ein
Überlauf dieser Verdoppelung wurde nicht reproduziert. Die Änderung
entfernt die vorherige Verengung auf `int` vor der Pointerarithmetik.

## Reproduzierbare Prüfung

`tools/Analyze-Native.cmd` erzeugt ausschließlich Objektdateien und
Analyselogs. Es analysiert 23 Übersetzungseinheiten: zwei ZPAQ-Dateien,
Threefish plus zwei Skein-Dateien, Argon2-Adapter/CLI plus sechs
Referenzdateien sowie ML-DSA-Adapter plus neun Referenzdateien. Fehler
stoppen nicht mehr die nachfolgenden Übersetzungseinheiten; der gesamte
Lauf liefert bei einem Compiler- oder strikten Adapter-Warnungsfehler
weiterhin einen Fehlercode. Die zuvor ausgelassenen Argon2- und
Skein-Implementierungen sind jetzt enthalten. Dieser Lauf umfasst nicht
das vollständige Crypto++-Archiv.

Der vollständige Lauf am 15. September endete mit Exitcode 0. Das lokale
Log heißt `work/v502-native-static-analysis-20260915-final.log`. Alle drei
Adapter wurden mit `/W4 /WX` geprüft. Für Vendorquellen bleiben Warnungen
sichtbar; Exitcode 0 bedeutet ausdrücklich nicht Warnungsfreiheit.

`tools/Test-Argon2-ThreadLifecycle.ps1` baut ein isoliertes Testprogramm aus
`native/argon2_thread_lifecycle_test.c`. Es verwendet echte Windows-Threads
mit kontrolliert blockierter Arbeit. Eine ausschließlich im Testverzeichnis
erzeugte Negativvariante stellt nur das falsche Completion-Ziel wieder her.
Das Testprogramm erkennt eine Freigabe bei noch blockiertem Worker und
beendet diesen vor der tatsächlichen Freigabe, damit der Negativtest selbst
keinen Zugriff auf freigegebenen Speicher ausführt.

| Variante | Später Joinfehler | Später Createfehler | Exitcode |
| --- | --- | --- | --- |
| Negativkontrolle | Vorzeitige Freigabe erkannt, keine Completion-Wartephase | Vorzeitige Freigabe erkannt, keine Completion-Wartephase | 1 |
| Korrigierter Core | Alle Worker vor Freigabe fertig | Alle Worker vor Freigabe fertig | 0 |

Beide Varianten starteten drei Worker; vor dem Fehler waren bereits ein
bzw. zwei Joins erfolgreich. Kompilierung mit `/W4 /WX`: keine Warnungen
oder Fehler. Lokales Laufprotokoll: `work/argon2-lifecycle/test-final.log`.

## Sichtbare verbleibende Meldungen

- C6246 an drei ZPAQ-Stellen: unabhängige lokale Schleifen verwenden erneut
  den Namen `i`. Der äußere Header-Parserindex wird danach nicht für diese
  Schleifen verwendet. Keine Verhaltensänderung oder Unterdrückung.
- C6287 in der Argon2-CLI: die separaten Obergrenzen für Threads und Lanes
  sind im aktuellen Referenzstand gleich. Beide fachlichen Prüfungen
  bleiben erhalten.
- C6385 beim Argon2-Join-Scan auf `started[l]`: der Analyzer meldet noch
  eine Bereichsverletzung. Im geprüften Quellstand werden exakt `lanes`
  Byte allokiert und alle Zugriffe über den unveränderlichen Grenzwert
  `0 <= l < lanes` geführt. Dieser verbleibende Diagnosepfad wird als
  Analyzer-Fehlalarm eingeordnet und bleibt im Log sichtbar.
- C6262 in der unveränderten ML-DSA-Referenz: die festen, nichtrekursiven
  Frames für Keygen, Signatur und Verifikation betragen laut Analyzer
  96.488, 121.408 und 91.628 Byte. Diese Referenz wurde in diesem Review
  nicht auf andere Speicherverwaltung umgestellt. Die Stackdiagnostik
  und ihre Standardgrenze wurden nicht abgeschaltet oder erhöht. Die
  Laufzeittests müssen die tatsächlichen Windows-Aufrufpfade weiterhin
  abdecken. C6262 meldet eine voreingestellte Framegrenze und ist allein
  kein Nachweis eines bereits eingetretenen Stacküberlaufs; Microsoft
  beschreibt die Grenze und ihre Einschränkungen in der
  [C6262-Dokumentation](https://learn.microsoft.com/en-us/cpp/code-quality/c6262?view=msvc-170).

Die weiteren Compilerwarnungen zu Konvertierungen und älterem Vendorstil
stehen ebenfalls im vollständigen Log. Dieser Bericht behauptet keine
vollständige Fehler- oder Schwachstellenfreiheit.

## Quellenbindung

`Verify-NativeSources.ps1` bestand für 431 Vendor-Dateien, drei zusätzliche
native Dateien und das Inventar von 202 Crypto++-Übersetzungseinheiten.
Für die betroffenen Dateien stimmen `git hash-object --no-filters` und
`git hash-object --path` überein; ihre vorhandenen Zeilenenden wurden nicht
großflächig normalisiert. `.gitattributes` verhindert eine nachträgliche
Zeilenendenkonvertierung dieser gepinnten Bytes.

| Datei | SHA-256 des geprüften aktuellen Quellstands |
| --- | --- |
| `external/zpaq/zpaq.cpp` | `5F2F23827D63623107FFEC075CCEC6F18553832EA781878810E152F7D6331037` |
| `external/zpaq/libzpaq.cpp` | `E4D6E41A0ED0369797D9DB973E66631385670B8D6D81D21E23A8004AF89CA99D` |
| `external/zpaq/libzpaq.h` | `2C62981D078505460FA212AE9A81821EEF036C34317303F7608E60825CE7E0D2` |
| `external/phc-winner-argon2/src/core.c` | `0A1996B290338CF8B949DDB2ABE29F5BCA1A2D8A66627D668F7F21642AD0F6E9` |
| `external/phc-winner-argon2/src/run.c` | `5717C4C7FDC7740717902EBEB9680344CDC706D77F7A024E1C8C2A05A8AE9D46` |
| `native/windows_zpaq_output.hpp` | `9FC632D515824A85ADF2A813AE597EBC9CEA666E5C04532A91675B9739405EA5` |
| `native/threefish_ref_export.c` | `CCCD4639477381D3C5253F1C32FA2239837E42697E5ABA2BC286B4CE1C62B008` |
| `native/argon2_thread_lifecycle_test.c` | `30B1E774E7842E822234E4B4941628BF7CD08B681D7376C74CB9C0947A9677FB` |

Analyseobjekte und synthetische Fehlerpfadtests sind von produktiven
Artefakten zu unterscheiden. Frühere Binärtests vom 9. September decken
diese späteren Quellenänderungen nicht ab; finale Build-, Signatur- und
Laufzeitnachweise müssen dem neuen Quellstand zugeordnet werden.
