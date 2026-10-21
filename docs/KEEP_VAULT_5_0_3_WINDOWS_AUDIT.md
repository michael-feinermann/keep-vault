# Keep Vault 5.0.3: Windows-Prüfbericht

Stand: 22. Oktober 2026. Der signierte Windows-x64-Build des Produktquellstands
`103e87fd6335bdc4ef8a2ffafa2384ecaad6504b`, seine Vollsuite und die finale
Paketabnahme sind bestanden. Auch die vier separaten Leistungsgruppen dieses
Kandidaten sind mit tatsächlichem Exit 0 und unveränderten Eingaben **PASS**.
Die Veröffentlichung ist weiterhin `PENDING`; ein Upload oder öffentlicher
Download wird noch nicht behauptet. Der abgelehnte c5-Kandidat und der gesonderte
Entwicklungsvergleich bleiben unten als eigene Nachweise erhalten.

Die Umsetzung folgt dem GitHub-v13-Stand
`ba9949ad1b93a89f75dd8078414371d1a1b7ad0d` mit den unten beschriebenen
Windows-Korrekturen. Gebaut und geprüft wurde unter `C:\Dev\Kalyna` in einem
unveränderlichen Quellsnapshot. Der vorhandene macOS-Release `v5.0.3` bleibt
einschließlich seiner sechs Assets und der Latest-Auswahl erhalten. Für Windows
ist das getrennte Tag `v5.0.3-windows` am tatsächlich kompilierten
Produktquellstand vorgesehen.

## Änderungen

- Windows-Kompilierungsfehler der WPF- und nativen Komponenten behoben; native
  Sicherheitsflags und Warnungsfehler für Adapter bleiben erhalten.
- Das signierte Installationsinventar verlangt die kompilierte Produktversion
  5.0.3. Authentisch signierte Inventare mit 5.0.2 oder 5.0.4 werden abgelehnt.
- Der native ZPAQ-Kontrollkanal verwendet getrennte überlappte Windows-I/O-
  Vorgänge und wartet deren Ende vor dem Freigeben der Handles ab. Abschluss-
  Antworten werden streng nach Typ, Sequenz und leeren Feldern geprüft.
- Die verwaltete Windows-Pipe benötigt nach vollständig abgewarteten Schreib-
  vorgängen keinen weiteren Flush. Eine sofort nach der gültigen Antwort
  schließende Gegenstelle löst dadurch keinen nachträglichen Fehler aus.
  Echte Schreibfehler bleiben Fehler; das macOS-Verhalten ist unverändert.
- Extraktions-Staging übernimmt eine reduzierte Kopie des bereits gebundenen
  Verzeichnishandles. Identität, Umbenennungs- und Reparse-Schutz bleiben erhalten.
- Die globale Prüfung eines reparierten Archivs übernimmt einen nur lesenden
  Handle des exklusiv gebundenen Reparaturkandidaten. Die ursprüngliche
  Transaktion behält ihre Commit-/Löschrechte; ein erneutes Öffnen über den Pfad
  oder eine Lockerung der Dateifreigaben entfällt.
- Vier eingefrorene v13-JSON-Referenzen behalten auf Windows ihre ursprünglichen
  LF-Bytes. Vektoren und kryptografische Hash-Pins werden nicht geändert.
- Die Entropie-Testdaten werden abwechselnd in die elf Pools geschrieben.
  Anzahl und Inhalt der Prüfungen bleiben erhalten; dadurch entfällt die
  künstlich erzwungene ungenutzte Windows-Speicherreservierung bei jedem
  einzelnen Ereignis. Der gesonderte Test einer schiefen Poolverteilung bleibt
  bestehen. Alle elf Suite-Pläne, der direkte Plan sowie Ergebnis-, Fehler-
  und Abbruchregressionen bestehen mit unverändertem Produktcode.
- Die abgeleiteten Faktorfelder erhalten den vorhandenen dunklen WPF-Stil.
- Die Folgekorrektur der Auto-Pipeline sammelt zunächst eine warme Ein-Slot-
  Referenz, berücksichtigt vorherige Planungs- und Fensteranpassungszeiten in
  folgenden abgeschlossenen Batches und begrenzt neue Wachstumsversuche durch
  eine konservative Anlaufkostenschätzung und verbleibende Arbeit.
  CPU-/Speicher-/Warteschlangengrenzen und die 90-%-Leistungsschwelle bleiben
  erhalten. Die gezielten Planungsregressionen und der unveränderte komplette
  Pipeline-Vergleich bestehen im Entwicklungsbuild: 97,6 % des besten festen
  Fensters. Die davon getrennte finale Leistungsprüfung des signierten Pakets
  ist unten belegt. Schlüsselableitung, globale MACs und die abschließende
  Bereinigung bleiben nur in der Gesamtworkflowzeit enthalten.
- SDK `10.0.402`, Laufzeit und PKCS-Abhängigkeit `10.0.13` ersetzen den
  verwundbaren Zwischenstand. Release-Restores behandeln NuGet-Meldungen
  NU1901 bis NU1904 als Fehler.

## Tatsächlich geprüfte Ergebnisse und Umfang

| Prüfung | Ergebnis und Grenze |
| --- | --- |
| Signierter 103e87f-Build | Erfolgreich; alle **4861** inventarisierten Quelldateien nach Build, Abnahme, Vollsuite und erneuter Belegübernahme unverändert |
| Vollsuite | **109/109 Gruppen PASS** in **578,8 s**, null FAIL/BLOCKED, tatsächlicher Prozess-Exit 0; Ergebnis-Head exakt `103e87fd6335bdc4ef8a2ffafa2384ecaad6504b`, Windows x64 |
| Finale Paketabnahme | **40/40 Fälle, 81 tatsächlich abgewartete Verifier-/Setup-Aufrufe**, Exit 0. Paket, ZIP, externe Verifier-Dateien und isolierte Installation ohne neue Verknüpfungen geprüft; fehlende/veränderte/zusätzliche Dateien, Sidecars, ZIP-Manipulation sowie Reparse-/Hardlink-Fälle abgewehrt |
| Separate Leistungsprüfung | **4/4 Gruppen PASS**, jeweils tatsächlicher Prozess-Exit 0, frische Ergebnisse und erfolgreiche Prozessbereinigung; alle fünf Erhaltungsprüfungen bestanden, keine Erhaltungsfehler |
| Erhaltung | Originalpaket, alle zwölf externen Assets, Quellen und vorhandene Benutzerverknüpfungen unverändert; alle sieben Erhaltungsprüfungen bestanden |
| QR-Scanner | **151 Arbiter-/Decoder-Prüfungen** im erfolgreichen 103e87f-Releasebuild; kein realer Kameratest |
| Native Quellprüfung | Im 103e87f-Build 433 externe Dateien, drei Windows-Pins und 202 Crypto++-Übersetzungseinheiten geprüft |
| Kontrollkanal | Im frischen 103e87f-Build **224 erfolgreiche aktuelle Lebenszyklen** über echte Windows-Pipes; Handle-Zahlen stabil. Der verzögerte historische Negativfall erreicht nachweislich den Abschluss und läuft erwartungsgemäß ins Zeitlimit |
| Native Windows-CI | Exakt `103e87fd6335bdc4ef8a2ffafa2384ecaad6504b`, [Run 39678610034 / Job 119494906876](https://github.com/michael-feinermann/keep-vault/actions/runs/39678610034/job/119494906876): Build, aktiver Defender und Kontrollkanal erfolgreich |
| Windows-Pipe und Reparaturleser | Abschluss-/Schreibfehler-, Dateifreigabe-, Identitäts-, Abbruch- und Reparaturregressionen bestehen in der 103e87f-Vollsuite |
| WPF | Alle fünf GUI-Gruppen bestehen in der 103e87f-Vollsuite. Die gesonderte frühere Stilprüfung umfasst acht statische DE/EN-Renderings am damaligen Head `c00ee8d409f33c685a9f23231c28ed71634e8c10`; ihr begrenzter Umfang bleibt erhalten |
| Realer Desktopstart | Die signierte installierte 103e87f-Testkopie startet tatsächlich: Version 5.0.3, Integrität und gepinnter QR-Begleiter bestanden, Capture-Status „active“ über Accessibility beobachtet. Navigation ist **NOT_CONFIRMED**, visuelle Hardwarefreigabe **NOT_RUN**; dies ist keine unabhängige Messung der Capture-Blockade |
| Acht Windows-Projekte | Frühere Komponentenprüfung mit SDK 10.0.402/Laufzeit 10.0.13: Locked Restores und Produktionsbuilds ohne Compilerwarnungen/-fehler; direkte/transitive NuGet-Abfragen ohne gemeldete Schwachstellen. Der Releasefehler-Gate wurde mit einem verwundbaren synthetischen Paket geprüft |
| Native Analyse | Frühere Komponentenprüfung: Exit 0, null Fehler, **300 erhaltene Herstellerwarnungen**, Adapterprüfung mit `/WX` bestanden. Keine Behauptung eines warnungsfreien nativen Builds; der Produktions-Kontrollheader ist unverändert |

Die Quellinventare vor und nach dem Build besitzen denselben SHA-256:
`5E364288B8C5D29415FDEB8C8212D976F6FC76C578AE3B9DCAE47FEBE09D4BE4`.
Die Erhaltungsaussage umfasst inventarisierte, eingecheckte Eingaben und deren
Bytes; zulässige Build-/Testausgabeverzeichnisse sind getrennt davon.

Die kompakten, hashgebundenen Nachweise stehen unter
[evidence/windows-5.0.3-20261021](evidence/windows-5.0.3-20261021/README.md).
[Vollsuite](evidence/windows-5.0.3-20261021/final-full-results.json),
[Vorlauf mit Quell-/Test-DLL-Bindung](evidence/windows-5.0.3-20261021/final-full-preflight.json),
[Paketabnahme](evidence/windows-5.0.3-20261021/acceptance-summary.json),
[Erhaltung](evidence/windows-5.0.3-20261021/acceptance-preservation.json) und
[Status](evidence/windows-5.0.3-20261021/gate-status.json) behalten ihren tatsächlichen
Umfang. Der Vollsuite-Ergebnis-SHA-256 ist
`13C10B1018D5B376BC961E14D164683790671BD44181C9A135EE1787849A53A2`,
der Abnahme-Ergebnis-SHA-256
`DE824CD8A5C666166E7A2E725EC34093CCC6FE4D35DAA7396A1C303E8CAD6933`.
Alle Belegdateien und die bytegleichen verwendeten Runner sind zusätzlich im
lokalen Dateiinventar gebunden. Skripttext allein gilt nicht als Ausführungsbeleg.

Frühere Komponentenbelege behalten ihren ursprünglichen Head und Umfang und
werden nicht nachträglich als 103e87f-Läufe bezeichnet.
Überholte oder fehlgeschlagene Kandidatenläufe zählen nicht als Abschlussprüfung.
Die historische macOS-Serie mit 49 Gates liegt außerhalb dieses Windows-Berichts.

## Finale separate Leistungsprüfung

Die vier Gruppen wurden nacheinander am signierten 103e87f-Kandidaten
abgeschlossen. Die folgenden Zeiten sind die vom begrenzten Runner beobachteten
Prozesslaufzeiten einschließlich dessen Start-/Abschlussaufwand, keine reinen
Cipherzeiten oder addierbaren inneren Phasen:

| Gruppe | Ergebnis | Prozesslaufzeit |
| --- | --- | --- |
| `performance.cipher-suites` | PASS, Exit 0 | 1583,4531944 s |
| `release.paranoia-256mib-level5` | PASS, Exit 0 | 325,7240935 s |
| `performance.entropy-rev9-phases` | PASS, Exit 0 | 341,7440902 s |
| `release.paranoia-complex-tree-level5-repair` | PASS, Exit 0 | 301,183492 s |

Der unveränderte Pipelinevergleich umfasst elf Einstellungen, je eine vollständige
Aufwärmrunde und fünf verschachtelte Messrunden: **55 Messwerte und elf
Aufwärmwerte**. Auto erreicht im Median **202,0067476566428 MiB/s**, die beste
feste Einstellung mit einem Slot **194,56591091237354 MiB/s**. Das sind
**103,824327 % der besten festen Einstellung**. Das tatsächliche unveränderte
90-%-Gate verwendet das Maximum aller Kandidaten einschließlich Auto; weil
Auto hier am schnellsten ist, beträgt sein Verhältnis zu diesem Maximum
**100 %**. Die vollständigen Messwerte bleiben erhalten.

Der komplexe Paranoia-Baum umfasst **21 Dateien, 20 Verzeichnisse und
221328174 Quellbytes**. Beschädigung und Reparatur eines Shards sowie der
abschließende Struktur-/Hashvergleich sind bestanden. Der innere Gesamtworkflow
dieses Falls dauert 290,4293251 s; die Prozesslaufzeit in der Tabelle ist davon
getrennt.

Der historische Vergleich ist ausschließlich für die zwölf Primitivmediane
gegenüber dem abgelehnten c5-Kandidaten auf demselben Rechner **PASS**. Der
niedrigste relative Durchsatz ist SHACAL-2 mit **87,0555 %** der c5-Referenz und
liegt über der unveränderten Mindestgrenze von **75 %**. Dies ist kein Vergleich
mit einer früher freigegebenen Windows-Version und kein unabhängiger nativer
historischer Benchmark; beide bleiben **NOT_RUN**.

[Gesamtbeleg](evidence/windows-5.0.3-20261021/performance-summary.json),
[Erhaltung](evidence/windows-5.0.3-20261021/performance-preservation.json),
[Cipher-/Pipelinewerte](evidence/windows-5.0.3-20261021/performance-01-metric-extracts.json),
[Entropiephasen](evidence/windows-5.0.3-20261021/performance-03-entropy-phase-metrics.json)
und [Baum-/Reparaturwerte](evidence/windows-5.0.3-20261021/performance-04-metric-extracts.json)
binden die tatsächlichen Ergebnisse. Der SHA-256 des Gesamtbelegs ist
`20AEE76F4EC3A9EA185D97E8CBD0E44538A53E4B45B2823E633C5CB0685FB36C`.
Alle fünf Erhaltungsfelder für Quellen, zwölf Assets, kompilierte Testeingaben,
Manifeste und freigegebene Handles sind wahr; die Fehlerliste ist leer.

## Lokale Artefakte vor der Veröffentlichung

| Datei | SHA-256 |
| --- | --- |
| `Keep Vault-portable-win-x64.zip` | `107B0242BF2B0B771635EA6CF4765D7B952C52CBA3147BA79F3DD102966B05DC` |
| `Keep Vault Release Verifier-win-x64.exe` | `82B47263B849475B8990CFFCC66D393CE44B18E0DB57A33E19BE22F818B678A6` |

Alle zwölf Dateien einschließlich Sidecars stehen mit Größen sowie SHA-256 und
SHA-512 im [lokalen Artefaktinventar](evidence/windows-5.0.3-20261021/normalized-publication-assets.json).
Die Namen mit Punkten sind für den GitHub-Upload vorbereitet. Noch wird kein
Upload oder erfolgreicher öffentlicher Download behauptet.

## Signierung und Public Keys

Der Windows-Release verwendet die getrennt gepinnte RSA-4096-/ML-DSA-87-
Produktionsidentität. Zertifikat-Thumbprint:
`7BA65B5130F34AB9F15C0D074699D46D9BCCD21C`.
RSA-SPKI-SHA-256:
`D0C5454E2C122FFD03D6F265876468E3935537FF6BB312EEEE48D883A889CFBB`.
ML-DSA-Public-Key-SHA-256:
`B3CF5B4465033351222AC5D6E1CC20F66432BB18AEC623EF76BB2C7823812219`.
Die vollständigen öffentlichen Pins stehen in
`WindowsRelease/Signing/Directory.Build.props`.

Die gewünschten öffentlichen Dateien liegen unter `A:\Keep Vault Keys`:
Zertifikat, RSA-PEM, ML-DSA-Public-Key, öffentliche Build-Pins, SHA-256-Inventar
und Erläuterung. Ihre Bytes wurden erneut geprüft. Private Schlüssel wurden
nicht dorthin exportiert. Das selbstsignierte Zertifikat installiert keine
allgemeine Windows-Vertrauenswurzel.

## Noch offene Abschlussprüfungen

| Gate | Aktueller Stand / nachzutragender Beleg |
| --- | --- |
| GitHub-Veröffentlichung | **PENDING**; Release-URL, Windows-Tagziel, tatsächliche Assetnamen/-IDs/-Digests und Prüfung aller zwölf authentifiziert sowie anonym frisch heruntergeladenen Dateien ergänzen; `--latest=false`, macOS-Tag/-Assets unverändert nachweisen |

Der frühere Kandidat `c5f4f256c9494147d08055a1deb5f9513a11af26` bleibt
[historisch abgelehnt](evidence/windows-5.0.3-20261021/superseded-c5-performance-summary.json):
Auto erreichte 156,14 MiB/s gegenüber 190,31 MiB/s mit einem festen Slot,
also **82,0 % statt mindestens 90 %**. Die vor diesem Auto-Fehler abgeschlossenen
zwölf c5-Primitivmediane bleiben ausschließlich als Vergleichsreferenz auf
demselben Rechner mit höchstens 25 % zulässigem Durchsatzrückgang erhalten.
Das macht den abgelehnten c5-Gesamtlauf nicht erfolgreich. Auch der separate
[Entwicklungsvergleich mit 97,6 %](evidence/windows-5.0.3-20261021/planner-development-summary.json)
bleibt ein Entwicklungsnachweis. Die inzwischen bestandenen vier Abschlussgruppen
des signierten 103e87f-Kandidaten sind davon unabhängig oben dokumentiert.

Ein Vergleich mit einer früher freigegebenen Windows-Version oder einem
unabhängigen nativen historischen Benchmark, reale Kamera- und Papierprüfungen,
andere DPI-/Hardwarekonfigurationen, physische Mehr-TiB-Läufe, ein externer
Kryptografie-/Sicherheitsaudit sowie vollständige interaktive Navigation und
Benutzer-Sichtfreigabe sind **NOT_RUN**. Der beobachtete Start und Accessibility-
Status ersetzen diese Abläufe nicht.

v13-Archive, KPAR2-Dateien und Schlüsselzettel sind inkompatibel zu v12.
Für vorhandene v12-Daten ist eine passende frühere Version erforderlich;
eine automatische Konvertierung findet nicht statt.
