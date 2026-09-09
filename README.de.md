# Keep Vault

[Deutsch](README.de.md) · [English](README.md) · [Dokumentationsverzeichnis](docs/README.md)

Archivierung, Entpackung und kryptografische Löschung von ZPAQ-Archiven. Die aktuelle
Veröffentlichung richtet sich an macOS und verwendet das Containerformat v12:
eine wählbare Kaskade aus bis zu sechs unabhängigen Chiffren über dem komprimierten
Datenstrom, Schlüssel aus zwei Argon2id-Zweigen, deren Speicherbedarf aus deinen
Zugangsdaten abgeleitet wird, zwei getrennte MACs und vier Zugangsfaktoren:
eine Passphrase, eine PIN und zwei von der App erzeugte 1024-Bit-Faktoren.

Die Anwendung wird weiterentwickelt. Sie ersetzt weder ein externes
kryptografisches Audit noch ein HSM oder die Absicherung des Betriebssystems.

> Die Plattformen werden getrennt geprüft. macOS-Versionen werden auf echter
> Apple-Hardware gebaut und getestet. Die Windows-WPF-Anwendung und ihr eigener
> QR-Scanner werden in einem späteren, getrennten Schritt auf v12 portiert und
> veröffentlicht. Der aktuelle Windows-Entwicklungsstand gehört nicht zu dieser
> v12-Veröffentlichung; bestandene macOS-Tests gelten niemals als Windows-Nachweis.

---

## Installation

Keep Vault 5.0.2 (Build 13) ist als stabile macOS-Version veröffentlicht.
Alle 153 Testgruppen, zusätzliche Release-Prüfungen, echte Installer- und
GUI-Prüfungen auf Deutsch und Englisch sowie der abschließende installierte
Paranoia/KPAR2-Ablauf wurden bestanden. Apple hat alle drei Apps akzeptiert;
Stapling, Gatekeeper und Prüfungen des exakten endgültigen Pakets waren erfolgreich.
Auch ein neuer vollständiger Ablauf des produktiven Kerns wurde bei abgeschaltetem
WLAN und unabhängiger IPv4/IPv6-Überwachung bestanden. Die Nachweise für Kern und
echte GUI sind im [macOS-Audit](docs/KEEP_VAULT_5_0_2_MACOS_AUDIT.md) getrennt dokumentiert.

Die stabile [Veröffentlichung v5.0.2](https://github.com/michael-feinermann/keep-vault/releases/tag/v5.0.2)
ist seit dem 9. September 2026 öffentlich und enthält die sechs geprüften Dateien.
Der Release-Tag zeigt auf den geprüften Commit `8df29a9e13eb65c0769666c3835b4cf0b96dad20`;
die hochgeladenen Dateien wurden erneut heruntergeladen und bytegenau verifiziert.
Spätere reine Dokumentationsänderungen ändern diesen Tag und die notarisierten
Programme nicht. Version 5.0.1 bleibt ein separater historischer Entwurf.

Fertige Pakete findest du auf der
[Releases-Seite](https://github.com/michael-feinermann/keep-vault/releases).
Voraussetzung: macOS 14 oder neuer, Apple Silicon oder Intel (Universal Binary).

Die folgenden Befehle betreffen den getrennten, unveröffentlichten
Windows-Entwicklungsstand und gehören nicht zur macOS-Veröffentlichung von v12.
Für einen lokalen Windows-x64-Build führst du `tools/Build-Portable.ps1` und danach
`tools/Install-KeepVaultShortcuts.ps1` aus. Die verbindliche Portierungscheckliste steht in
[`docs/KEEP_VAULT_V12_WINDOWS_UPDATE.md`](docs/KEEP_VAULT_V12_WINDOWS_UPDATE.md);
sie muss auf echter Windows-Hardware vollständig abgearbeitet werden, bevor eine
Windows-Veröffentlichung behauptet werden darf. Die Verknüpfungen zeigen auf den
verifizierten portablen Verzeichnisbaum in diesem Workspace. Ein neuer erfolgreicher
portabler Build wird damit ohne zweite veränderbare Kopie zur lokal installierten
Version. Derselbe Baum enthält den separat gebauten und signierten
`QR-Scanner\QR-Scanner.exe`; Keep Vault prüft dieses Begleitprogramm beim Start.
Der Scanner bleibt der einzige Windows-Prozess des Releases mit Kamerazugriff.

Das macOS-Paket enthält `Keep Vault.app`, `QR-Scanner.app` und die separate
`Keep Vault Installer.app`. Der Scanner liest die QR-Codes der ausgedruckten
Schlüsselzettel. Er ist ein eigenständiges Programm in einer Sandbox mit eigener
Bundle-Kennung. Keep Vault selbst fordert niemals Kamerazugriff an und deklariert
überhaupt keine Hardwareberechtigung.

1. Lade die vollständige Veröffentlichung `Keep Vault-macOS-universal.zip` herunter und entpacke sie.
2. Prüfe den Installer mit den unten beschriebenen macOS-Werkzeugen.
3. Öffne `Keep Vault Installer.app`, wähle Installieren und bestätige die lokalen
   macOS-Administratorabfragen. Starte ihn als angemeldeter Benutzer ohne `sudo`.
   Falls eine Ordnerauswahl erscheint, wähle den vollständigen entpackten
   Installationsordner. Der Installer prüft diesen Ordner genauso vollständig.
4. Starte Keep Vault und QR-Scanner nach der Installation aus `/Applications`.

Der Installer authentifiziert das gesamte Paket, schützt seine Installationsdateien
vor Austausch und installiert beide Apps sowie die erforderliche ZPAQ-Komponente
im Eigentum von root. Nur die Apps nach Programme zu ziehen richtet diese Komponente
nicht ein. Der Ziel-Mac benötigt weder .NET SDK noch Xcode oder Compiler.
Apples Distributionsprüfungen während der Installation können Netzwerkzugriff
erfordern; Zugangsdaten und Inhalte der Archive werden nicht an Apple gesendet.

Die Dateien `Keep Vault.app.launcher.*` gehören neben `Keep Vault.app` und müssen
dort bleiben: Der Launcher prüft bei jedem Start seine eigene Doppelsignatur und
startet ohne diese Dateien nicht. Dasselbe gilt für `QR-Scanner.app.*`.

Bei jedem Start prüft die App Apples Codesignatur, ihre einkompilierten cdhash-Pins
und die Doppelsignatur jeder ausführbaren Datei im Bundle. Scheitert eine dieser
Prüfungen, startet sie nicht.

### Download prüfen

Vor dem Öffnen des Installers kann macOS dessen signierte Identität und die
aktuelle Distributionsrichtlinie prüfen. Führe diese Befehle im entpackten
Paketverzeichnis aus:

```sh
/usr/bin/codesign --verify --strict --deep \
  -R='identifier "de.michael-feinermann.keep-vault.installer" and anchor apple generic and certificate leaf[subject.OU] = "2T6K9PGS55" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists' \
  "Keep Vault Installer.app"
/usr/bin/syspolicy_check distribution "Keep Vault Installer.app"
```

Anschließend verlangt der Installer sowohl RSA-PSS- als auch ML-DSA-87-Signaturen
über sein vollständiges Installationsinventar. Es bindet jeden Nutzlastpfad,
Dateityp, Dateimodus, jede Größe und jeden Hashwert, einschließlich der exakten
Tickets, die Apples stapler beim Release-Build validiert hat. Die
Distributionsrichtlinie des Systems allein gilt nicht als Prüfung der
Byteintegrität eines angehefteten Tickets. Fehlende oder veränderte Paketdateien
stoppen die Installation, bevor eine App oder ihre geschützte Laufzeitkomponente
ersetzt wird. Belasse `installation-manifest.json` und alle fünf begleitenden
Signatur-/Hashdateien im Paket. Der signierte native Verifier liegt im Installer-Bundle.

Ein Prüfprogramm, das gemeinsam mit dem zu prüfenden Gegenstand geliefert wird,
kann zunächst nur die innere Konsistenz des Pakets belegen. Für einen Nachweis
gegen einen entschlossenen Angreifer musst du den Verifier und seine Pins über
einen getrennten vertrauenswürdigen Kanal beziehen.

---

## Formatregeln

Die App schreibt und liest ausschließlich Containerformat Version 12. Jede andere
Version wird abgelehnt, auch Version 11. Es gibt keinen Entschlüsselungspfad für
Altformate und es ist keiner geplant. Mit v11 oder älter erstellte Archive lassen
sich mit dieser Version nicht öffnen. Der Leser nennt diesen Grund ausdrücklich,
anstatt ein falsches Passwort zu melden.

Das ist eine bewusste Entscheidung. Eine aus Kompatibilitätsgründen beibehaltene
ältere Ableitung wäre eine zweite angreifbare Konstruktion, ein weiterer Satz
fehleranfälliger Domänen und ein dauerhafter Grund, die jeweils schwächere Variante
beizubehalten. Diese Formatentscheidung fiel während der Entwicklung, als keine
aufzubewahrenden Archive gegen die Entfernung sprachen.

Die Domänentrenner der Schlüsselableitung enthalten `v12`; im Header benennt eine
explizite Zeichenfolge `KdfMode` die Konstruktion. Eine Versionsnummer allein
reichte nicht aus: 4.0.0/4.0.1 und 4.0.2 schrieben beide `"Version": 9`, leiteten
aber unterschiedliche Paranoia-Schlüssel ab. Mit `KdfMode` ändert eine künftige
Korrektur einen direkt lesbaren Wert statt eines nur indirekt erschließbaren Werts.

### Die zehn Optionen

Sie werden in dieser Reihenfolge angeboten:

| # | Option | Schichten, äußerste zuerst | Nonce | Chiffrenschlüssel |
|---|---|---|---|---|
| 1 | Standard | Threefish-1024 → Kalyna-512/512 | 192 B | 192 B |
| 2 | Schnell | ChaCha20-Poly1305 → AES-256 | 28 B | 64 B |
| 3 | Gemischt | ChaCha20-Poly1305 → Threefish-1024 → AES-256 | 156 B | 192 B |
| 4 | Paranoia | ChaCha20-Poly1305 → Threefish-1024 → Kalyna-512/512 → SHACAL-2-512 → MARS-448 → AES-256 | 268 B | 376 B |
| 5 | Threefish-1024 | einzelne Chiffre | 128 B | 128 B |
| 6 | Kalyna-512/512 | einzelne Chiffre | 64 B | 64 B |
| 7 | SHACAL-2-512 | einzelne Chiffre | 32 B | 64 B |
| 8 | MARS-448 | einzelne Chiffre | 16 B | 56 B |
| 9 | AES-256 | einzelne Chiffre | 16 B | 32 B |
| 10 | ChaCha20-Poly1305 | einzelne Chiffre | 12 B | 32 B |

Die vier Kaskaden stehen zuerst, von der Alltagsoption bis zur aufwendigsten
Variante. Wer die Liste überfliegt, wählt den ersten passenden Eintrag. Die Option
mit sechs Datendurchläufen steht am Ende, sodass sie bewusst gewählt wird.
Die sechs einzelnen Chiffren folgen nach absteigender Schlüsselgröße.

Die App und die ausgedruckten Zettel zeigen die Namen in Klammernotation, je nach
ausgewählter Sprache auf Deutsch oder Englisch, zum Beispiel
`Paranoia: ChaCha20-Poly1305(Threefish 1024(Kalyna 512/512(SHACAL-2 512(MARS 448(AES 256(Data))))))`.

#### Gemessene Leistung auf Apple M5 (macOS)

Keep Vault 5.0.2, Build 13, gemessen am 8. September 2026: Apple M5,
10 logische CPUs, 16 GiB RAM, macOS 26.6.2, nativ arm64. Jeder Wert ist der
Median aus drei Durchläufen mit 256 MiB, in MiB/s (1 MiB = 1.048.576 Byte).

| Option | Reine Kryptografie (MiB/s) | Container verschlüsseln (MiB/s) | Prüfen + entschlüsseln (MiB/s) |
|---|---:|---:|---:|
| Standard | 988,0 | 111,16 | 106,66 |
| Schnell | 2.438,8 | 93,88 | 90,00 |
| Gemischt | 1.289,3 | 142,50 | 135,69 |
| Paranoia | 384,6 | 46,74 | 45,09 |
| Threefish-1024 | 3.194,3 | 105,76 | 104,90 |
| Kalyna-512/512 | 1.705,0 | 155,50 | 146,69 |
| SHACAL-2-512 | 1.802,4 | 103,75 | 101,55 |
| MARS-448 | 1.546,9 | 116,56 | 115,00 |
| AES-256 | 23.194,1 | 146,91 | 135,57 |
| ChaCha20-Poly1305 | 2.551,5 | 96,93 | 94,92 |

Bei kleinen Datenmengen kann der feste Aufwand der Schlüsselableitung (KDF)
die Laufzeit dominieren. Dieser begrenzende Effekt ist beabsichtigt:
Argon2id verlangt bei jedem Ableitungsversuch
Zeit und Arbeitsspeicher und verteuert dadurch das Durchprobieren von
Zugangsdaten. Dieser Aufwand fällt für jeden Ver- oder Entschlüsselungsvorgang
an und wächst bei gleicher Suite und gleichem KDF-Profil nicht mit der
Dateigröße. Er ist in „Container verschlüsseln“ und
„Prüfen + entschlüsseln“ enthalten und trägt wesentlich dazu bei, dass diese
MiB/s-Werte deutlich unter der reinen Kryptografieleistung liegen. Bei größeren
Datenmengen verteilt sich der KDF-Aufwand auf mehr Bytes; andere
Verarbeitungsschritte können dann den Durchsatz begrenzen.

Reine Kryptografie misst die Chiffre oder Kaskade im RAM nach einem
16-MiB-Aufwärmlauf, ohne Argon2id oder die beiden globalen Container-MACs.
Die Containermessungen schließen das produktive Argon2id (`t=4`, `p=4`) und
beide MACs ein. Verschlüsseln umfasst das Schreiben der verschlüsselten Datei;
Prüfen und Entschlüsseln umfassen den privaten Eingabesnapshot und das
laufende SHA-256-Hashen der Ausgabe, ohne entpackte Dateien zu schreiben. ZPAQ-Kompression,
Entpackung und KPAR2 liegen außerhalb dieser Messungen.

Die KDF-Salts bleiben innerhalb der drei Durchläufe einer Suite gleich,
unterscheiden sich aber zwischen Suites. Der abgeleitete Argon2id-Speicherbedarf
kann deshalb abweichen. Die Containerwerte beschreiben diese Testfälle und
Datengröße; sie sind keine isolierte Chiffrenrangliste und keine Zusage für die
Geschwindigkeit einer vollständigen Archivierung. [Messwerte und Herkunft](docs/benchmarks/keep-vault-5.0.2-m5.json),
[Benchmarkimplementierung](KalynaArchiver.Tests/CipherSuitePerformanceTests.cs)
und [Release-Prüfbericht](docs/KEEP_VAULT_5_0_2_MACOS_AUDIT.md).

Eine Windows-Übersicht mit Messungen auf einem Intel Core i9-13900K wird später ergänzt.

### Funktionsweise einer Kaskade

Jede Schicht erhält einen eigenen Schlüssel und einen eigenen Abschnitt der Nonce.
Bei der Standardkaskade sind das je 64 Byte Schlüssel und Nonce für die innere
Kalyna-Schicht sowie je 128 Byte für die äußere Threefish-Schicht.

Ein früherer Entwurf schnitt diese Schlüssel aus einer einzigen flachen
Argon2id-Ausgabe aus. Der Schlüssel hing damit von seiner Position im Puffer ab;
dieselbe Chiffre konnte an zwei Positionen strukturelle Gemeinsamkeiten aufweisen.
v12 leitet jeden Schlüssel getrennt aus einem kanonischen Kontext ab: Algorithmus,
Stufenindex, Chiffre, Zweck und Schlüsselbreite. Dieser Kontext durchläuft zwei
PRF-Familien, deren Ergebnisse kombiniert werden:

```
U = HKDF-Expand(HMAC-SHA3-512) over the two master halves     128 B
V = Skein-MAC-1024-1024(key = master, pers = domain, msg = context)
Z = U XOR V                                                    128 B
```

Erst danach wird `Z` auf die Schlüsselbreite der Schicht gekürzt. Früheres Kürzen
würde breite Schichten auf die Breite der erzeugenden Primitive begrenzen.
Die XOR-Kombination verbindet zwei 1024-Bit-PRF-Ausgaben unter der Annahme, dass
beide Familien die vorausgesetzten Eigenschaften besitzen und die Kontexte
eindeutig sind. Sie ist kein robuster Kombinator gegen beliebige oder bösartig
korrelierte Primitive.

Die Reihenfolge ist entscheidend. Das Brechen nur der äußeren Schicht liefert den
Geheimtext der inneren Schicht, weder Klartext noch Archivstruktur. Jedes Nutzdatenbyte
sowie Dateinamen, Größen und Zeitstempel liegen im ZPAQ-Datenstrom innerhalb aller
Schichten. Ein automatisierter Test belegt das, indem er die äußere Schicht mit
dem richtigen Schlüssel entfernt und das Ergebnis nach einer bekannten Markierung
durchsucht.

Alle Schichten außer dem äußersten ChaCha20-Poly1305 sind Schlüsselstromkonstruktionen.
Die Sicherheit bleibt daher erhalten, solange mindestens eine davon ungebrochen ist.

### Nonces pro Datenblock

Bei jeder Option erhält jeder 16-MiB-Datenblock eine eigene Nonce, die aus Basisnonce
und Blockindex mit SHA3-512 abgeleitet wird. Ein fortlaufender CTR-Zähler über
beliebig große Archive würde sich irgendwann wiederholen. Ein wiederholter
Zählerblock unter demselben Schlüssel verrät das XOR zweier Klartexte.

### Ableitung des Hauptschlüssels

v12 leitet die Schlüssel aus vier Zugangsfaktoren ab: Benutzerpassphrase, PIN und
den zwei 1024-Bit-Faktoren der gedruckten Schlüsselzettel. Neue Archive verlangen
24 bis 256 UTF-16-Codeeinheiten für die Passphrase und eine PIN aus 6 bis 16 Ziffern
(nur ASCII). Diese Auswahlgrenzen gelten nicht beim Lesen vorhandener v12-Archive.
Es gibt weder einen reduzierten KDF-Modus noch eine Suite, die einen Zugangsfaktor
überspringt.

Zunächst entstehen zwei unterschiedlich konstruierte Verarbeitungspfade. Der
SHA3-Pfad teilt jeden Faktor in zwei binäre 512-Bit-Hälften und verknüpft sie
über beide Zettel hinweg:

```
A1 = A[0..64)   A2 = A[64..128)
B1 = B[0..64)   B2 = B[64..128)

Q_S1 = SHA3-512(LP(D_S1) || LP(pass) || LP(pin) || LP(A1) || LP(B1))     64 B
Q_S2 = SHA3-512(LP(D_S2) || LP(pass) || LP(pin) || LP(A2) || LP(B2))     64 B
Q_S  = Q_S1 || Q_S2                                                     128 B

Q_K  = Skein-MAC-1024-1024(key = A || B, pers = D_SK, msg = LP(pass) || LP(pin))
```

Die Faktoren gehen als rohe Bytes ein, nicht als Hexadezimaltext. Beide Hälften von
`Q_S` hängen von beiden Schlüsselzetteln ab. Genau dazu dient die Aufteilung:
Wird ein 1024-Bit-Faktor kompromittiert, beruht jede 512-Bit-SHA3-Hälfte weiterhin
auf 512 nicht kompromittierten Bits des anderen Faktors. Der Skein-Pfad wird nicht
geteilt; der vollständige 2048-Bit-Wert `A || B` dient als MAC-Schlüssel.

`LP` ist eine Rahmung mit Längenpräfix, keine einfache Verkettung. Ohne sie würden
die Passphrase `"ab"` mit PIN `"1"` und die Passphrase `"a"` mit PIN `"b1"` dieselben
Bytes hashen und denselben Schlüssel ableiten.

Beide Ergebnisse werden nacheinander mit getrennten Salts und getrennten
assoziierten Daten an Argon2id übergeben:

```
L = Argon2id(P = Q_S, S = salt_sha3,  X = "...SHA3-Branch/Round-1",  m, 4, 4, 64)
R = Argon2id(P = Q_K, S = salt_skein, X = "...Skein-Branch/Round-1", m, 4, 4, 64)
M = interleave(L, R)                                                      128 B
```

Die Zweige laufen strikt nacheinander. Jede Matrix wird freigegeben, bevor die
nächste angelegt wird. Der Spitzenspeicherbedarf bleibt so bei einer statt zwei
Matrizen. Das Interleaving ist eine Permutation, keine Durchmischung. Es verhindert,
dass eine einzelne 512-Bit-Argon2id-Ausgabe die Breite des Hauptschlüssels bestimmt.
Die eigentliche Durchmischung erfolgt anschließend bei der Ableitung der Rollenschlüssel.

Daraus folgen keine zwei unabhängigen Argon2-Grundkonstruktionen: Beide Zweige
verwenden denselben BLAKE2b-Kern und unterscheiden sich in Eingaben und Domänen.
Auch das Interleaving fügt keine Entropie hinzu.

#### Der Speicherbedarf wird abgeleitet und nicht gespeichert

`m` ist keine Konstante und wird nicht abgelegt. Es ergibt sich aus den Zugangsdaten:

```
PMI = BE16(SHA3-512(LP(domain, Q_S, Q_K, [M1,] salt_sha3, salt_skein))[0..1])
m   = 1 GiB + 16 * PMI KiB          -- 1,048,576 to 2,097,136 KiB
```

Ohne Kenntnis der Zugangsdaten weiß ein Angreifer nicht, welches der 65.536
Speicherprofile anzulegen ist. PMI fügt keine Entropie hinzu, denn es ist eine
deterministische Funktion der Zugangsdaten. Ein beobachtender Prozess kann den
Wert weiterhin anhand des residenten Speichers oder der Laufzeit abschätzen.
Er steht nicht auf dem Datenträger, ist aber nicht unsichtbar.

Das Headerfeld `Argon2MemoryKiB` ist deshalb `0`. Der Leser lehnt Container ab,
die dort einen anderen Wert eintragen. Auch KPAR2 enthält den Wert nicht.

#### Paranoia führt die gesamte Ableitung zweimal aus

Die Paranoia-Kaskade führt eine zweite Runde aus. Deren Argon2id-Eingabe `secret`
ist der vollständige 1024-Bit-Hauptschlüssel der ersten Runde:

```
M2 = round(Q_S, Q_K, salt_sha3_2, salt_skein_2, secret = M1, m2)
```

Runde zwei kann erst nach Abschluss von Runde eins beginnen. Es sind vier
aufeinanderfolgende Argon2id-Aufrufe mit jeweils mindestens einem Gibibyte,
keine vier parallel ausführbaren Aufrufe. Die Zugangsdaten stehen in beiden
Runden an derselben Position; nur das Secret und die Salts ändern sich.

Das ersetzt eine frühere Anordnung, bei der beide Runden denselben 128-Byte-Vorhash
der Zugangsdaten verwendeten. Weil der PHC-Adapter das übergebene Passwort löscht,
führten 4.0.0 und 4.0.1 ihre zweite Runde über 128 Nullbytes aus. v12 teilt überhaupt
keinen Puffer zwischen den Runden. Der Regressionstest ändert ein Bit aus Runde eins
und prüft, dass sich Runde zwei dadurch ändert. Ein bloßer Ver- und Entschlüsselungstest
würde auch dann bestehen, wenn beide Seiten denselben Fehler hätten.

Alle vier Salts stehen als zwei 1024-Bit-Paare im Header. Ein Archiv, dessen Header
nur die erste Runde enthielte, könnte niemand entschlüsseln, auch nicht der
Computer, der es geschrieben hat.

### Der Container

- Magic `KZPAQ2\0`, UTF-8-JSON-Header, 64-Byte-HMAC-SHA3-512-Baum-Tag,
  128-Byte-Skein-1024-MAC-Tag, danach Geheimtext
- Passwortmodus `UserPassword24to256+PIN6to16+GeneratedHex1024x2`
- KDF-Eingabemodus `DualBranch-v12: SplitFactorsSHA3-512-1024 || KeyedSkeinMAC-1024-1024`
- KDF-Modus `DualArgon2id-SplitSHA3+Skein1024-Sequential-Master1024`
- Ein 1024-Bit-Saltpaar pro Runde; Argon2id 0x13 mit `t=4`, `p=4` und aus den
  Zugangsdaten abgeleitetem Speicherbedarf; `Argon2MemoryKiB` wird als `0` gespeichert
- 1024-Bit-Hauptschlüssel, aus dem jeder Rollenschlüssel getrennt abgeleitet wird
- Encrypt-then-MAC mit zwei getrennten Schlüsseln; beide Tags sind verpflichtend

Der authentifizierte Header bindet Version, Suite, Blockgröße, beide Saltpaare,
Nonce, Tweak, KDF-Modus, KDF-Eingabemodus, Hauptschlüsselbreite und Passwortmodell.
Beide MACs decken dieselbe Magic, Headerlänge, denselben Header und den vollständigen
Geheimtext ab. Beide Tags werden vollständig und ohne vorzeitigen Abbruch verglichen,
bevor Klartext die ZPAQ-Pipe erreicht.

Der v12-Leser akzeptiert nur `t=4`, `p=4` und ein Speicherfeld mit Wert null.
Abweichende Headerwerte werden vor der KDF abgelehnt. Ein manipuliertes Archiv kann
damit weder schwächere noch höhere Argon2-Kosten erzwingen. Der Speicherbedarf steht
überhaupt nicht im Header; dafür existiert kein manipulierbares Feld. Der native
Adapter prüft seine Grenzen ein zweites Mal unabhängig und verlangt, dass die
gesamte Argon2-Matrix gegen Auslagerung gesperrt ist. Scheitert die Sperre, bricht
die KDF ab. Nach der KDF wird die Matrix vor dem Entsperren und Freigeben genullt.

---

## Verwendung

Das Fenster hat drei Registerkarten.

Archivieren: Wähle Dateien und Ordner aus oder ziehe sie hinein, wähle ein Ziel,
aktiviere die Verschlüsselung und wähle eine Option. Vorgeschlagene Archiv- und
Ausgabenamen erhalten immer mindestens den Zusatz `(1)`. Vor dem Verschlüsseln
muss die aktuelle Kombination aus Archivpfad, Suite und beiden Faktoren gedruckt
oder ausdrücklich als Test-PDF exportiert werden.

Originaldateien löschen: Diese optionale Funktion verlangt einen Nachweis.
Das Archiv wird erneut in ein privates Verzeichnis entpackt und in beiden
Richtungen Byte für Byte mit den Originalen verglichen: Jedes Original muss im
Archiv enthalten sein, und das Archiv darf nichts Zusätzliches enthalten.
Unmittelbar vor einer Löschung werden zwei Dinge erneut geprüft. Länge und
SHA-512 identifizieren das Archiv, damit ein Austausch zwischen Prüfung und
Löschung auffällt. Außerdem wird jedes Original erneut gelesen und mit dem
geprüften Stand verglichen: gleiche Dateimenge, Längen, Änderungszeiten und
Hashwerte sowie keine seitdem hinzugekommene Datei. Bei irgendeiner Abweichung
wird nichts gelöscht.

Danach wird jede geprüfte Datei einzeln gelöscht. Absichtlich wird nicht
`Directory.Delete(recursive: true)` verwendet: Dieser Aufruf löscht alles, was er
vorfindet, auch möglicherweise ungeprüfte und nie archivierte Dateien.
Ordner werden anschließend nur entfernt, wenn sie leer sind.

Entpacken: Ziehe eine `.zpaq` oder `.kzpaq` hinein. Zunächst wird die Suite aus dem
noch nicht authentifizierten Header angezeigt. Vor jeder Klartextausgabe wird sie
durch beide MACs authentifiziert. Entpackt wird ausschließlich in einen neuen oder
leeren Ordner. Eine `.kzpaq` ohne gültigen Containerheader und ohne nutzbare
KPAR2-Daten wird vollständig abgelehnt und niemals als einfaches ZPAQ an den
nativen Parser übergeben.

Kryptografisch löschen: Analysiere einen gültigen verschlüsselten v12-Container.
Zuerst wird die rekonstruierbare Wiederherstellungsdatei zerstört, anschließend
wird der Container über denselben exklusiven Dateihandle beschädigt und gelöscht.
Die Schaltfläche bleibt gesperrt, bis du die SSD/APFS-Einschränkung ausdrücklich
bestätigt hast.

Erfolgreiches Archivieren oder Entpacken leert die zugehörigen Passwort- und
Faktorfelder. Beide Bereiche haben außerdem eine Schaltfläche zum manuellen
Leeren der Geheimnisse. Fehlgeschlagene Archivläufe entfernen alle unvollständigen
Archive, Manifeste und Wiederherstellungsobjekte, deren Identität die App erfolgreich
gebunden hat. Scheitert ein nativer Erzeuger, bevor die Eigentümerschaft seiner
Ausgabe gebunden werden konnte, bleibt der ungeprüfte temporäre Pfad erhalten
und wird gemeldet. So wird kein möglicherweise ausgetauschtes fremdes Objekt
nur anhand seines Pfades gelöscht. Fehlgeschlagene oder abgebrochene Entpackläufe
entfernen ihren gebundenen unvollständigen Ausgabeordner.

Sprache, zuletzt gewählte Suite und ZPAQ-Kompressionsstufe werden als streng
validierte Komforteinstellungen im Benutzerprofil gespeichert, begrenzt auf
64 Byte. Ungültige Werte führen zurück zu Englisch, Standardsuite und Stufe 1.
Passwörter, Faktoren, Salt und Nonce werden dort niemals gespeichert. Beim
Entpacken bestimmt ausschließlich der authentifizierte Archivheader die Suite;
die gemerkte GUI-Auswahl hat darauf keinen Einfluss.

---

## Passwortmodell

Zum Entpacken werden alle vier Zugangsfaktoren benötigt:

1. Die ursprüngliche Benutzerpassphrase in unveränderter UTF-8-Kodierung.
2. Die ursprüngliche PIN aus ASCII-Ziffern einschließlich führender Nullen.
3. Faktor A: 256 Hexzeichen = 128 Byte = 1024 Bit.
4. Faktor B: 256 Hexzeichen = 128 Byte = 1024 Bit.

Keiner davon steht im Header. Dieser speichert nur erforderliche öffentliche
Parameter: Salt, Nonce, Tweak, Suite, Format-/KDF-Kennungen und Rahmungslängen.
PMI16 und der daraus folgende Argon2id-Speicherbedarf werden aus den Zugangsdaten
abgeleitet und nicht im Header veröffentlicht. Der optionale Hinweis ist öffentlich,
darf kein Passwortmaterial enthalten und wird ausdrücklich als nicht authentifizierter
Headertext angezeigt, bis beide MACs erfolgreich geprüft wurden.

### Regeln für Benutzerpasswörter beim Erstellen von Archiven

- mindestens 24 und höchstens 256 Zeichen
- mindestens 3 Zeichengruppen
- mindestens 12 verschiedene Zeichen
- mindestens 12 Zeichen außerhalb von `0-9`, `A-F`, `a-f`
- keine zusammenhängende Hexfolge aus 8 oder mehr Zeichen
- nicht identisch mit Faktor A oder B; auch A und B müssen verschieden sein
- mindestens 128 Bit nach einer konservativen lokalen Schätzung

Die bisherige Berechnung und alle bisherigen Ablehnungsregeln bleiben aktiv.
In 5.0.2 können vollständige Offline-Modelle für Sprache, Wortlisten und Muster
diesen Wert ausschließlich senken. Der endgültige Wert muss weiterhin 128 erreichen.
EFF Englisch (7.776 Wörter), dys2p Deutsch (7.776 Wörter) und die ursprünglichen
englischen BIP39-Indizes (2.048 Wörter, einschließlich Prüfsummenvalidierung)
liegen als Analysedaten bei. Weder die Größe einer Wortliste noch ein unkalibrierter
Modellwert beweist Entropie einer menschlichen Auswahl.

Die vollständige PIN darf nicht wörtlich im unverarbeiteten Passwort vorkommen
und nicht dem aktuellen lokalen Datum im Format DDMMYY, DDMMYYYY, MMDDYY oder
MMDDYYYY entsprechen. Unmittelbar vor der Erstellung werden beide Werte und das
lokale Datum erneut geprüft. Bestehende PIN-Regeln bleiben unverändert.

Entpacken, Auflisten und Wiederherstellen führen weder diese alten noch die neuen
Auswahlregeln aus und benötigen keine Passwortmodelldaten. Es gelten nur die
ursprüngliche Kodierung, die Faktorformate, eine separate technische Grenze von
1.048.576 UTF-16-Codeeinheiten je Benutzerzugangsdatenfeld und die kryptografische
Verifikation. Es erfolgt keine Netzwerkabfrage zur Laufzeit. Die
[v12-Zugangsdatenregeln und der Windows-Vertrag](docs/KEEP_VAULT_V12_CREDENTIAL_POLICY.md)
beschreiben die genauen Grenzen, Datenherkunft, Unsicherheit und erforderlichen Nachweise.

### Die vier Zugangsfaktoren

Die kanonischen SHA3- und Skein-Zweige mit Längenpräfix sind unter
[Ableitung des Hauptschlüssels](#ableitung-des-hauptschlüssels) beschrieben.
Beide verwenden Passphrase, PIN und beide 1024-Bit-Faktoren, kombinieren sie aber
bewusst unterschiedlich. Kein Zweig lässt sich aus der Ausgabe des anderen berechnen.

`Q_S` und `Q_K` gehen ungekürzt in ihren jeweiligen Argon2id-Zweig ein, jeweils mit
einem eigenen 512-Bit-Salt. Die App kompiliert die unveränderten PHC-Argon2-Referenzquellen.
Tests vergleichen den nativen Adapter mit der PHC-CLI; den v12-Zweig prüfen sie
zusätzlich gegen die unabhängige Argon2id-Implementierung von Bouncy Castle.

Jeder Zwischenpuffer wird vor dem ersten Schreibzugriff gegen Auslagerung gesperrt
und noch im gesperrten Zustand genullt: Kodierungsziele, Längenrahmen, beide
Zugangsdatenhashes, jede Kopie für einen einzelnen Argon2id-Aufruf und beide
Rundenhauptschlüssel. Jeder Argon2id-Aufruf erhält eine frische Kopie, weil die
native Seite ihre Eingabe löscht. Genau hier lag der Fehler einer früheren Fassung.

Der Skein-MAC verwendet Bouncy Castles `SkeinMac` mit Skeins eigenen Schlüssel- und
Personalisierungsparametern, nicht `Skein1024(key || message)`. HKDF-Expand verwendet
Bouncy Castles `HkdfBytesGenerator` mit `SkipExtractParameters`, keine selbst geschriebene
HMAC-Kette. Beide wurden vor ihrem Einsatz gegen unabhängige zweite Implementierungen geprüft.

Ein Salt verhindert vorberechnete Tabellen für identisches Passwortmaterial.
Es macht ein schwaches Benutzerpasswort allein nicht stark. Den Schutz tragen
hier die beiden unabhängigen Faktoren und die speicheraufwendige KDF.

---

## Zufall, Salt, Nonce und Tweak

Neun getrennte Pools sammeln Mausmesswerte: A1, A2, B1, B2, SHA3-Salt, Skein-Salt
und drei Nonce-Teile. Ein 1024-Bit-Faktor entsteht durch Aneinanderreihen zweier
Pools, A = A1 ‖ A2. Das ist zusätzliche Absicherung, keine Behauptung, jeder Pool
enthalte 512 Bit reale Entropie. Jeder Pool benötigt mindestens 1024 Messwerte,
bevor Archivzufallsdaten erzeugt werden können. Bei der zyklischen Verteilung sind
das mindestens 9216 Mausereignisse pro Epoche; die neun Zähler unterscheiden sich
höchstens um eins.

Die Oberfläche zeigt alle neun Zähler. Sie gruppiert A1/A2 und B1/B2 visuell;
es bleiben aber zwei Benutzerfaktoren, keine vier.

Diese Anzahl belegt keine 512 Bit physikalischer Mausentropie. Die Sicherheit kann
bereits allein auf dem CSPRNG des Betriebssystems beruhen; Mausdaten liefern
zusätzliche Vielfalt. Jede Ausgabe ist das XOR zweier unabhängiger Beiträge:

- `SecRandomCopyBytes` als primärer CSPRNG
- eine domänengetrennte SHA3-512-Erweiterung des jeweiligen Mauspools

Faktoren, beide Salts und alle drei Nonce-Teile werden gemeinsam und atomar aus
einer Epoche erzeugt, jeweils aus dem eigenen Pool. Danach wird jeder Pool ersetzt,
noch gesperrt genullt und sein Zähler auf null gesetzt. Null bedeutet in diesem
Zustand verbraucht, nicht unzureichend. Beide Salts und die vollständige Nonce
bleiben bis zum Verschlüsselungsbeginn im gesperrten RAM und werden genau einmal
entnommen. Scheitert der Versuch nach der Entnahme, bleiben A und B gültig. Der
Wiederholungsversuch leitet aber aus einer neuen Epoche frische Salts und Nonces ab,
sodass eine Nonce niemals unter demselben Schlüssel wiederverwendet wird.

Jede Runde besitzt ein 1024-Bit-Saltpaar: 512 Bit für den SHA3-Zweig und 512 Bit
für den Skein-Zweig. Identische Werte werden abgelehnt. Paranoia verwendet zwei
solche Paare. Der öffentliche 16-Byte-Threefish-Tweak wird deterministisch und
domänengetrennt aus der Nonce abgeleitet und im authentifizierten Header gespeichert.
Salt, Nonce und Tweak müssen nicht geheim bleiben.

---

## Schlüsselzettel

Vor dem Verschlüsseln muss die aktuelle Kombination aus Archivpfad, Suite und
beiden Faktoren gedruckt oder ausdrücklich als Test-PDF exportiert werden.

- Physischer Druck ohne Datei ist der Standardweg.
- Offensichtliche virtuelle PDF-/XPS-/Faxdrucker werden gesperrt.
- Unter macOS entstehen zwei getrennte Druckaufträge: Faktor A mit öffentlicher
  Installationsseite, danach Faktor B mit eigener öffentlicher Installationsseite.
  Jeder Auftrag hat zwei Seiten. Die getrennte Windows-Entwicklungsimplementierung
  behält ihr dreiseitiges Layout A / öffentliche Trennseite / B und benötigt
  eigene Release-Prüfungen.
- Jede geheime Seite nennt Suite, Gerätename, Archivpfad, genau einen
  1024-Bit-Faktor in 32 Gruppen aus acht Hexzeichen, ein leeres handschriftliches
  Feld für das Benutzerpasswort und zweimal den QR-Code dieses Faktors. Unter
  macOS 5.0.2 enthält der Titel die Keep-Vault-Version und das Passwortfeld
  mindestens drei Zeilen. Bezeichnungen einschließlich Doppelpunkt sind in beiden
  Sprachfassungen fett gesetzt.
- Die PIN steht bewusst nicht auf dem Zettel; der Zettel weist darauf hin.
  Schon das Handschriftfeld für die Passphrase ist ein Kompromiss. Ein Zettel
  mit Passphrase, PIN und einem Faktor enthielte drei der vier Zugangsfaktoren.
- A und B sollen getrennt und offline aufbewahrt werden.
- Test-PDF speichern schreibt unter macOS bewusst zwei getrennte Dateien, eine
  je Faktor mit zugehöriger öffentlicher Installationsseite. Beide Faktoren liegen
  damit dauerhaft auf dem gewählten Datenträger; das ist kein sicherer Standardweg.

Das Begleitprogramm derselben Veröffentlichung (`QR-Scanner.app` unter macOS,
`QR-Scanner.exe` unter Windows) liest die Codes wieder ein. Druckspooler, Treiber
und Drucker können außerhalb der App eigene temporäre Daten erzeugen.

---

## Streaming und Parallelität

ZPAQ liegt unter `external/zpaq`, die lizenzierte v12-Kalyna-Implementierung in
Crypto++ 8.9.0 unter `external/cryptopp` und der offizielle Skein-1.3-/Threefish-Code
unter `external/Skein-reference`. Der frühere unlizenzierte Kalyna-Referenzstand
und alle daraus abgeleiteten Tabellenadapter wurden vor dieser Veröffentlichung
entfernt. Sie werden weder gebaut noch verteilt.

Die angepasste ZPAQ-Schnittstelle `--pipe` überträgt das unverschlüsselte
ZPAQ-Archiv direkt im RAM zwischen ZPAQ und dem Containerdienst. Es wird niemals
ein unverschlüsseltes Zwischenarchiv auf den Datenträger geschrieben. Der endgültige
Container wird unter zufälligem Namen bereits als Geheimtext geschrieben, vollständig
gespeichert und anschließend atomar ohne Überschreiben auf den Zielnamen verschoben.

Beim Entpacken lehnt die lokale ZPAQ-Anpassung absolute Pfade, `..`, mehrdeutige
abschließende Punkte und Leerzeichen sowie reservierte Gerätenamen ab. Archiveinträge
können den leeren Zielordner daher nicht durch Pfadtraversierung verlassen. Entpackt
wird in einen zufälligen versteckten Nachbarordner, der erst nach Erfolg per
Verzeichnisumbenennung an den endgültigen Ort gelangt.

Direkte Eingabedateien bleiben während des gesamten ZPAQ-Aufrufs über einen Handle
gebunden, der ein Umbenennen oder Löschen währenddessen verhindert; Symlink-Aliasse
werden abgelehnt. Archivziele dürfen weder einer Eingabe entsprechen noch innerhalb
eines gelesenen Verzeichnisbaums liegen. Der native ZPAQ-JIT ist deaktiviert;
Modell- und Indexgrößen sind fest begrenzt.

Das verschlüsselte Streamingformat gilt ausschließlich für v12 (`KVP12ZP1`).
Jeder unabhängig komprimierte ZPAQ-Block liegt in einem kanonischen Rahmen mit
exakter komprimierter und unkomprimierter Länge sowie Prüfsumme. Rahmen werden in
Indexreihenfolge erzeugt und verarbeitet; begrenzte Arbeitsgruppen komprimieren
oder dekomprimieren unabhängige Blöcke parallel. Ein Rahmen ist auf 24 MiB
komprimierte Daten, 32 MiB unkomprimierte Daten und ein 128-MiB-Modell begrenzt.
Höchstens 512 MiB komprimierte Pipe-Daten dürfen auf geordnete Verarbeitung warten.
Reguläre Archive verwenden pro Auftrag eine Ausgabegrenze von 64 MiB und ein
Modelllimit von 512 MiB. Ein gemeinsames Verarbeitungsbudget von 6 GiB lässt nur so
viele Kompressionsaufträge zu je 384 MiB oder reguläre Aufträge zu je 592 MiB zu,
wie hineinpassen; die angeforderte Zahl von Arbeitern ist zusätzlich auf 64 begrenzt.
Abgeschnittene, vertauschte, nicht kanonische oder prüfsummenfehlerhafte Rahmen
werden abgelehnt, ohne hinter der Beschädigung erneut zu synchronisieren.

Ein bereits authentifiziertes reguläres `.zpaq` auf der Standardeingabe wird
in einer internen `KV12VM`-Hülle mit zwei Nullbytes und einer 64-Bit-Länge in
Big-Endian-Reihenfolge übertragen. Der native Prozess prüft Magic, Grenzen,
exakte Länge und EOF und hält das Archiv anschließend in anonymem privatem
VM-Speicher. Vor dem Parserzugriff werden sowohl aktueller als auch maximaler
Speicherschutz auf nur lesend gesetzt. Der Parser kann mit `mprotect` keinen
Schreibzugriff wiederherstellen. Das ermöglicht positionsunabhängiges paralleles
Lesen ohne benanntes Shared-Memory-Objekt; benanntes POSIX-SHM ist in den Profilen
verboten. Die Grenze für verifizierte Eingaben beträgt 512 GiB. Daraus folgen
weder unbegrenzt verfügbarer physischer RAM noch ein Ausschluss von Betriebssystem-Swap. Das Entpacken
ist außerdem auf insgesamt 500 GiB, 500 GiB je Datei, 500.000 Einträge, einen
512-MiB-Index und 2^26 Fragmente begrenzt. Verschlüsselte Container verwenden diese
Zwischenablage des gesamten Archivs nicht: Ihre entschlüsselten `KVP12ZP1`-Rahmen
bleiben in der begrenzten vorwärts gerichteten Pipe.

Die Containerschicht verarbeitet begrenzte Gruppen aus 16-MiB-Blöcken. Die
Slotgrenze beginnt bei einem Slot pro vier logischen Prozessoren, mindestens einem
und höchstens 64. Ein Speicherbudget aus einem Sechzehntel des gemeldeten verfügbaren
Speichers begrenzt sie weiter; mindestens ein Slot bleibt möglich. Slots werden bei
Bedarf angelegt. Jeder besitzt zwei gesperrte 16-MiB-Puffer sowie Zähler-, Nonce- und
Tag-Speicher. Nach dem Lesen einer Gruppe arbeiten die Blockarbeiter parallel.
Alle werden zusammengeführt, bevor der Schreiber die Gruppe in kanonischer
Reihenfolge ausgibt. Er beendet die Ausgabe vor dem Lesen der nächsten Gruppe.
Native Transformationsgruppen sind über gleichzeitige Containeroperationen hinweg
begrenzt; jede nutzt höchstens 64 Arbeiter. Kaskadenschichten bleiben sequenziell,
weil jede die Ausgabe der vorherigen verarbeitet. Innerhalb einer Schicht verteilen
die nativen CTR- und ChaCha20-Treiber disjunkte Zählerbereiche auf Arbeiter.
Umordnung wird abgelehnt, alle gestarteten Arbeiter werden auf jedem Beendigungspfad
zusammengeführt, und eine fehlgeschlagene Operation veröffentlicht keinen Teilcontainer.

Auch Poly1305 arbeitet parallel. Ab 1 MiB verarbeiten bis zu 64 Arbeiter
zusammenhängende, an 16 Byte ausgerichtete Teile des exakten RFC-8439-Transkripts.
Ihre Feldelemente werden in Nachrichtenreihenfolge mit der passenden Potenz des
maskierten Einmalschlüssels zusammengeführt. Eine erhaltene skalare Implementierung,
umfassende Vergleiche an Padding-Grenzen, der RFC-Vektor und ein differentieller
256-MiB-Test prüfen Bytegleichheit mit dem seriellen Authentifikator.
Beim Entschlüsseln wird der Tag geprüft, bevor Klartext in den Ausgabepuffer des
Aufrufers geschrieben wird.

Die beiden globalen Containerauthentifikatoren verwenden einen für v12
domänengetrennten Baum über 1-MiB-Blätter. Jedes Blatt bindet Index und exakte
Länge; die geordnete Wurzel bindet logische Gesamtlänge, Blattzahl, Blattgröße
und beide vollständigen Blatttags. HMAC-SHA3-512 und Skein-MAC-1024 verwenden
getrennt abgeleitete Blatt- und Wurzelschlüssel. Blätter laufen über die durch
Hardwaregrenzen beschränkte Arbeitsgruppe; nur das kleine kanonische
Wurzeltranskript bleibt seriell. Die Authentifizierung des gesamten Containers
endet weiterhin, bevor entschlüsselte Archivbytes an ZPAQ freigegeben werden.

Der Threefish-Adapter übernimmt die 80 Runden, Rotationen und Schlüsselableitung
der offiziellen Referenz `Skein1024_Process_Block` unverändert. Nur die
Skein-UBI-Rückkopplung wird entfernt, um den reinen Threefish-Block zu erhalten.

CTR authentifiziert allein nichts. Manipulationsschutz liefern HMAC-SHA3-512
mit je 64 Byte Schlüssel und Tag sowie Skeins nativer Schlüsselmodus mit je
128 Byte Schlüssel und Tag. Jeder MAC-Schlüssel wird aus seinem eigenen Rollenkontext
nach demselben Schema wie die Chiffrenschlüssel abgeleitet. Er wird weder aus einem
gemeinsamen Puffer ausgeschnitten noch lässt er sich aus einem Chiffrenschlüssel ableiten.

Unverschlüsselte `.zpaq`-Archive erhalten stattdessen verpflichtend die
Begleitdateien `<archive>.sha3` und `<archive>.skein`. Diese erkennen Beschädigungen,
schützen ohne privaten Signaturschlüssel aber nicht gegen einen aktiven Angreifer,
der Archiv und beide Begleitdateien ersetzt.

---

## Korrektur von Bitfehlern

Jedes Archiv erhält eine KPAR2-v4-Begleitdatei `<archive>.kpar2`:

- Reed-Solomon `RS(20,3)`: 20 Daten- und 3 Paritätsscherben, 15 Prozent Zusatzbedarf
- getrennte Paritätsbereiche für Header und Archivinhalt
- auf 4096 Byte ausgerichtete Archivscherben mit SHA3-512- und Skein-1024-Hashwerten
- acht räumlich getrennte, selbst doppelt gehashte 4096-Byte-Locators,
  vier am Anfang und vier am Ende; mindestens fünf identische gültige Kopien sind nötig
- ein Metadatenbereich aus Blöcken von genau 4096 Byte, selbst streifenweise durch
  `RS(20,3)` geschützt; er enthält das kanonische Manifest, beide Zertifikate,
  Suite, Salt, Argon2id-Profil und sämtliche Scherbenhashes

Einzelne Bits und vollständig unlesbare 4-KiB-Blöcke lassen sich reparieren,
solange höchstens drei Datenscherben je Streifen betroffen sind. Blockweises Lesen
behandelt vom Dateisystem gemeldete E/A-Fehler als Auslöschungen.

Paritätserzeugung, Scherbenhashing, Prüfung und Rekonstruktion verteilen unabhängige
Streifen und Scherben auf eine hardwareabhängig begrenzte Gruppe mit höchstens
64 Arbeitern. Jeder schreibt in disjunkte Ergebnisbereiche; die Reihenfolge von
Manifest, Locators und Ausgabe bleibt kanonisch. Ein eigener Wiederherstellungstest
vergleicht den Pfad mit einem Arbeiter und den produktiven Mehrarbeiterpfad auf Bytegleichheit.

Bei verschlüsselten Archiven wird das KPAR2-Manifest immer doppelt authentifiziert:
HMAC-SHA3-512 und der Schlüsselmodus von Skein-1024 verwenden eigene
Wiederherstellungsschlüssel, domänengetrennt aus den Archiv-MAC-Schlüsseln und einer
zufälligen Archiv-ID abgeleitet. Falsche Zugangsfaktoren oder eine ausgetauschte
KPAR2-Datei werden abgelehnt, bevor ein Reparaturkandidat entsteht. Jede Suite des
Katalogs wird abgedeckt. Eine frühere Version prüfte die Suite-ID des Locators
gegen einen fest codierten Bereich, der nur die ersten beiden zuließ. Die meisten
Suites erzeugten deshalb ein Archiv, das die App zwar verschlüsseln, anschließend
aber nicht schützen konnte.

KPAR2 verwendet v4; ältere Versionen werden nicht gelesen. Der Start der
Schlüsselableitung entspricht dem Container: Jedes verwendete Saltpaar wird
rundenweise gespeichert, und es läuft genau dieselbe Ableitung, einschließlich
beider Paranoia-Runden. Ein früheres Entwicklungsformat speicherte nur ein
64-Byte-Salt und leitete die übergeordneten Wiederherstellungs-MAC-Schlüssel auch
für Paranoia mit einer Argon2id-Runde ab. Wer beide Schlüsselzettelfaktoren besaß,
erhielt damit über die Wiederherstellungsdatei ein billigeres Offline-Prüforakel
für die Passphrase als über den geschützten Container. Die Zertifizierungsschlüssel
bleiben von den Containerschlüsseln getrennt: Sie entstammen eigenen Rollenzwecken
desselben Ableitungsschemas. Ihre Ableitung ist lediglich gleich teuer anzugreifen.

v4 bindet außerdem die Containerversion in den authentifizierten
Wiederherstellungskontext, sowohl bei der Schlüsselableitung als auch im
Zertifizierungspräfix. Das nicht schlüsselgebundene Versionsfeld im Locator kann damit
keine andere Schlüsselableitung auswählen. Da nur Containerversion 12 existiert,
wird jeder andere Wert unmittelbar abgelehnt.

Die Argon2id-Kostenfelder wurden aus Locator und Manifest entfernt; vorhandene
Felder werden abgelehnt. Der Speicherbedarf wird aus den Zugangsdaten abgeleitet.
Ihn neben dem Salt zu veröffentlichen würde diese Eigenschaft aufheben.

Bei unverschlüsselten Archiven sind dieselben SHA3- und Skein-Werte ausdrücklich
schlüssellose Fehlererkennungswerte. Eine Reparatur schreibt daher immer in einen
neuen konfliktfreien Dateinamen und lässt das beschädigte Original unverändert.

Der separate Notfallmodus überspringt die Authentifizierung der KPAR2-Metadaten,
schreibt immer eine neue Datei und verändert niemals das Original. Für ein
verschlüsseltes Archiv bleiben alle vier Zugangsfaktoren erforderlich. Der fertige
Kandidat muss beide MACs des Containers bestehen. Es gibt keinen automatischen
Rückfall vom normalen Modus in den Notfallmodus.

---

## Integrität und Signierung

Das Paket kombiniert Apples Codesignaturen mit hybriden Signaturen aus
RSA-PSS/SHA-512 (RSA-4096) und ML-DSA-87 (NIST FIPS 204). Beide hybriden Komponenten
müssen gültig sein; es gibt keinen ODER-Rückfall. Haupt-App, Scanner und
Installer-Helfer besitzen Komponentensignaturen. Die hybride Bindung des
Installer-Einstiegspunkts erfolgt über das signierte vollständige Release-ZIP;
Apples Bundle-Siegel schützt seine Codeidentität. Das endgültige macOS-Paket
5.0.2 enthält neunzehn Mach-O-Dateien mit 38 Architekturslices:

- `Keep Vault`, `Keep Vault Launcher`, `Keep Vault Supervisor`
- `zpaq`, `argon2`
- `libargon2_ref`, `libkalyna_v12`, `libthreefish_ref`, `libaes_ref`,
  `libmars_ref`, `libshacal2_ref`, `libchachapoly_ref`
- `libAvaloniaNative`, `libHarfBuzzSharp`, `libSkiaSharp`
- `Keep Vault Release Verifier`
- `QR-Scanner`
- `Keep Vault Installer`, `InstallerBoundDelete`

Die Signaturziele der Haupt-App werden aus ihrem Bundle ermittelt und nicht von
Hand aufgelistet. Sowohl Launcher als auch eigenständiger Verifier lehnen jede
Mach-O-Datei in diesem App-Bundle ab, der eine Signatur fehlt. Eine manuelle Liste deckt nur ab, woran jemand gedacht
hat: Die drei Avalonia- und Skia-Bibliotheken waren früher nur von Apple signiert
und von der Doppelsignatur ausgenommen. Sie liefen im Prozess mit den Archivschlüsseln
und stützten sich allein auf Apples Signatur, obwohl die App gerade diese einzelne
Abhängigkeit vermeiden soll.

Zwei Signaturen können nicht innerhalb des Bundles liegen, das sie abdecken.
Sie werden deshalb daneben veröffentlicht:

- die Signatur des Launchers, weil codesign das Bundle-Siegel in den Launcher
  selbst schreibt und eine Signatur über dessen eigene Bytes sich damit selbst ungültig machen würde;
- die Signatur des Scanners, weil Apples Siegel `Contents/Resources` abdeckt
  und eine dort nachträglich ergänzte Datei dieses Siegel brechen würde.

Keep Vault prüft `QR-Scanner.app` bei jedem Start gegen dieselben fest verankerten
Schlüssel und protokolliert das Ergebnis im Sicherheitsprotokoll. Der Scanner liest
die zwei geheimen Faktoren von den gedruckten Zetteln und kann nicht für sich selbst
bürgen: Eine ausgetauschte App könnte einfach behaupten, alles sei korrekt. Ein
Fehler wird deutlich gemeldet, stoppt Keep Vault aber nicht. Der Scanner ist ein
separates Programm, dessen Code Keep Vault niemals lädt.

Beide öffentlichen Schlüssel sind jeweils dreifach verankert. Alle sechs
Fingerabdrücke müssen exakt übereinstimmen:

- SHA-256
- SHA3-512
- Skein-1024

Mehrere Hashfunktionen addieren keine Sicherheitsbits. Sie vermeiden bei der
Schlüsselidentifikation die Abhängigkeit von einer einzelnen Hashfunktion oder
einem einzelnen Anbieter. macOS prüft nur die Apple-Signatur. ML-DSA-87 prüfen
Launcher, App und eigenständiger Verifier. Das ist eine hybride Anwendungssignatur,
kein doppeltes X.509-Zertifikat. ML-KEM-1024 aus FIPS 203 ist ein KEM und kann keine
Software signieren; deshalb liefert ML-DSA-87 aus FIPS 204 den Post-Quanten-Anteil.

Die importierten Referenzquellen von `pq-crystals/dilithium` sind auf Commit
`d35ba3fe5449bee3e6d43e1f296c3ca818bd36be` festgelegt. Der native Build verlangt
passende SHA-256-, SHA3-512- und Skein-1024-Quellmanifeste für genau die
21 eingebundenen Referenzdateien.

### Schutz der Signierschlüssel

Eine hybride Signatur ist eine gemeinsame Entscheidung: Sie gilt nur, wenn
RSA-PSS und ML-DSA-87 beide erfolgreich geprüft wurden. Ihr Schutz bei der Speicherung
bleibt unabhängig. Der private ML-DSA-87-Schlüssel und das RSA-PFX-Passwort verwenden
zwei getrennt erzeugte 32-Byte-Verpackungsschlüssel. Im standardmäßigen
Schlüsselbundmodus nutzen diese zwei verschiedene Dienste, zwei verschiedene
Konten und zwei unabhängig angelegte Zugriffslisten. Der Signierer lehnt auch unterschiedlich benannte Einträge ab,
wenn deren Schlüsselbytes gleich sind.

Die beiden AES-256-GCM-Formate sind absichtlich inkompatibel. `KVMDSA12` akzeptiert
nur einen privaten ML-DSA-87-Schlüssel exakter Länge; `KVPFXP12` nur ein
längenbegrenztes UTF-8-PFX-Passwort. Typ, Version und kanonische Nutzlastlänge werden
als assoziierte Daten authentifiziert. Jeder Typ hat einen eigenen Lese- und
Schreibpfad. Weder alte noch zwischen Rollen vertauschte Hüllen werden akzeptiert.

Im standardmäßigen Schlüsselbundmodus liegt jeder Verpackungsschlüssel in einem
eigenen Eintrag im Anmeldeschlüsselbund,
der ohne vertrauenswürdige Anwendung angelegt wird. Jeder Signieraufruf erzeugt
somit zwei unabhängige Bestätigungsabfragen. Eine zusätzliche Abfrage bedeutet eine
nicht selbst gestartete Verwendung. Wähle Erlauben, niemals Immer erlauben:
Letzteres trägt das anfragende Programm in die Zugriffsliste ein und entfernt die
Abfrage. Die Release-Vorprüfung untersucht beide Zugriffslisten, ohne Geheimnisse
zu lesen, und lehnt vertrauenswürdige Anwendungen, Rollenabweichungen, gemeinsame
Identitäten oder fehlende Einträge ab.

`tools/Protect-HybridKeys-macOS.sh` richtet diesen ausschließlich für v12 geltenden
Zustand ein oder prüft ihn. Im Schlüsselbundmodus erzeugt Security.framework jeden Verpackungsschlüssel
unabhängig. Rohe Verpackungsschlüsselwerte werden niemals aus Umgebungsvariablen
oder der Befehlszeile übernommen; einen gemeinsamen Ersatzpfad gibt es nicht. Das Skript ver- und
entschlüsselt über den rollenspezifischen Code des Signierers. Es belegt jeden
Rundlauf über denselben exklusiv erzeugten Dateideskriptor mit Modus 0600, bevor
die Datei ohne Ersetzen veröffentlicht wird.

Als ausdrückliche Alternative werden zwei geschützte lokale Schlüsseldateien
gemeinsam über `KEEPVAULT_MLDSA_WRAPPING_KEY_FILE` und
`KEEPVAULT_PFX_WRAPPING_KEY_FILE` gewählt. Nur ihre Pfade sind Konfigurationswerte.
Jede enthält eine kanonische Base64-Kodierung von 32 Byte. Die Schlüssel müssen
verschieden sein und dem aktuellen Benutzer gehören. Die Dateien müssen genau
einen Link sowie Modus 0600 besitzen und in privaten Verzeichnissen mit Modus
0700 auf lokalen Datenträgern mit aktivierter Eigentümerprüfung liegen.
Symlinks werden abgelehnt. Es gibt keinen stillen Wechsel zwischen Datei- und
Schlüsselbundmodus. Der Dateimodus bietet die beiden Schlüsselbundabfragen nicht.
Vorhandene Hüllen müssen zu den gewählten Schlüsseln passen. Siehe die
[Paketierungsanleitung](KeepVaultMac/Packaging/README.md).

Geheime Eingaben werden mit `O_NOFOLLOW_ANY` geöffnet, anhand von `fstat` begrenzt,
über den gehaltenen Deskriptor gelesen und anhand von Gerät, Inode, Eigentümer,
Modus, Linkzahl, Größe und Änderungsmetadaten erneut geprüft. Verpackungsschlüssel
des Signierers, entschlüsselte ML-DSA-Quelldaten und das dekodierte PFX-Passwort
bleiben in fixierten, durch `mlock` geschützten Puffern, die vor dem Entsperren
genullt werden. Geheime Schlüsselbund-Standardausgabe wird als begrenzte Bytefolge
statt als verwalteter String gelesen. Das PFX-Passwort wird in gesperrten
UTF-16-Speicher dekodiert. ML-DSA-Anbieter erzeugen beim Signieren kurzlebige
Parameterobjekte. Jede zugängliche kodierte Kopie des privaten Schlüssels wird
genullt; interne Kopien des Anbieters liegen außerhalb der Kontrolle des Aufrufers.
Apples externer Prozess `security` und der native PKCS#12-Import sind ebenfalls
unvermeidbare undurchsichtige Plattformgrenzen. Deren interne native Kopien kann
der Signierer nicht löschen.

Speicherverschlüsselung schützt kopierte Hüllen nur, solange die Verpackungsschlüssel
getrennt geschützt bleiben. Ein Backup oder kopierter Datenträger mit Hüllen und
nutzbaren Verpackungsschlüsseln besitzt diesen Schutz nicht. Sie stoppt keine
Schadsoftware mit denselben Benutzerrechten, die den Schlüsselbund wie der Signierer
ansprechen kann.
Im Schlüsselbundmodus erhöht die Bestätigungsabfrage hier die Hürde. Der
Dateimodus stützt sich stattdessen auf den Schutz des gewählten lokalen Datenträgers
und der Dateien.

Ein root gehörender Rückrollschutz unter
`/Library/Application Support/Keep Vault/minimum-version` speichert die niedrigste
akzeptable Buildnummer. Ein Angreifer mit Benutzerrechten kann damit keine ältere,
schwächere Version wieder einsetzen.

---

## Aus dem Quelltext bauen

Erforderlich sind die Xcode-Kommandozeilenwerkzeuge und das festgelegte .NET-10-SDK.
Zum Signieren einer Veröffentlichung brauchst du einen eigenen RSA-4096-Schlüssel
für Codesignierung und ein ML-DSA-87-Schlüsselpaar. Release-Builds akzeptieren nur
die externe PFX-Datei und die beiden v12-Hüllen, konfiguriert über
`KEEPVAULT_HYBRID_PFX`, `KEEPVAULT_MLDSA_PRIVATE_KEY_ENCRYPTED` und
`KEEPVAULT_PFX_PASSWORD_ENCRYPTED`.

```sh
./tools/Build-Native-macOS.sh          # reference ciphers, Argon2, ZPAQ
./QrCodeScanner/tools/Build-QrScanner-macOS.sh --version 5.0.2 --build-number 13
./tools/Build-KeepVault-macOS.sh --version 5.0.2 --build-number 13
./tools/Build-Portable-macOS.sh        # portable folder and ZIP
./tools/Install-KeepVault-macOS.sh     # verify and install to /Applications
./tools/Verify-KeepVault-macOS.sh      # check an installed or built bundle
./tools/Protect-HybridKeys-macOS.sh    # create the two independent v12 envelopes
```

Ein öffentlich verteilbarer Build verlangt zusätzlich eine ausdrücklich gewählte
Developer-ID-Identität, `--release` und entweder `--notary-profile PROFILE` für im
Schlüsselbund gespeicherte Zugangsdaten oder `--notarize-in-xcode`. Beide Alternativen
dürfen nicht kombiniert werden. Letztere bewahrt den vollständigen signierten
Kandidaten unverändert und pausiert den Build, damit genau dessen ZIP separat mit
Xcodes `notarytool` eingereicht werden kann. Außerdem erzeugt sie Xcode-Archive zur
Prüfung. Nachdem Apple den vollständigen Kandidaten akzeptiert hat, gibst du im
wartenden Build `NOTARIZED` ein. Signiere die Original-Apps nicht erneut und ersetze
sie nicht durch einen Xcode-Export. Vor der Fortsetzung heftet der Build Tickets
unabhängig an alle drei Original-Apps an und validiert sie. Ein Apple-Development-Build
ist ausschließlich ein lokaler Testnachweis.

QR-Scanner und Keep Vault müssen dieselbe Marketingversion und Buildnummer tragen.
Die Prüfung des portablen Releases verlangt den Scanner, prüft beide Bundle-Kennungen
und lehnt ein fehlendes oder nicht passendes Begleitprogramm vor dem Signieren ab.

Der Build kompiliert alle sechs Fingerabdrücke ein, signiert die App und jede
native Datei und erzeugt anschließend SHA3-512- und Skein-1024-Manifeste sowie eine
`.khsig` je Release-Artefakt. Die Abschlussprüfung führt den mitgelieferten Verifier
gegen ZIP, App und vollständigen Paketordner aus. Eine Veröffentlichung darf erst
erfolgen, wenn ihr eigenes Prüfwerkzeug sie akzeptiert.

---

## Tests

```sh
./tools/Stage-TestNatives-macOS.sh
cd KeepVaultMac.Tests
dotnet run -c Release -- --full
```

`--list` gibt das verbindliche Inventar der Smoke-, umfassenden und manuellen
Leistungsprüfungen aus. `--only <stable-id>` begrenzt einen Lauf auf genau eine Gruppe;
manuelle Leistungsprüfungen verlangen zusätzlich `--performance`.

Die Tests decken ab: macOS-Prozesshärtung; Vertrauen in signierte native Komponenten
und Manipulationsablehnung; hybride Signaturabdeckung aller Mach-O-Dateien im gebauten
Bundle; Prüfung des Begleitscanners einschließlich beschädigter, veränderter und
fehlender Signaturen; SHA3-, Skein-, Kalyna- und Threefish-Referenzvektoren;
ML-DSA-87-Interoperabilität mit dem kompilierten Referenzadapter in beiden Richtungen;
randomisierte differentielle Tests gegen alle Referenzbibliotheken; das feste
Argon2id-Profil gegen PHC und Bouncy Castle; ZPAQ-Stufen, Streaming, Pfadtraversierung
und einen Korpus fehlerhafter Eingaben; v12-Rundläufe und Manipulationsablehnung;
den Nachweis, dass die äußere Kaskadenschicht allein nichts offenlegt;
Zweirundenableitung aus einem Poolverbrauch; blockeigene Nonces über mehrere
Archivblöcke; Salt und Nonce für jede Einrundensuite; veröffentlichte MARS- und
SHACAL-2-Vektoren; KPAR2-Reparatur, Authentifizierung, Ablehnung übertragener fremder
Daten und Abdeckung aller katalogisierten Suites; Reihenfolge beim kryptografischen
Löschen und Ablehnung harter Links; verifizierte Originallöschung einschließlich
der erneuten Originalprüfung vor dem Löschen; sowie GUI-Steuerung über Avalonias
Backend ohne sichtbares Fenster.

---

## Sicherheitsgrenzen

- Empfindliche verwaltete Puffer werden genullt und gegen Auslagerung gesperrt.
  Scheitert eine Sperre, bricht die Operation ab. Dasselbe gilt für die gesamte
  native Argon2-Matrix ab 1 GiB.
- Die App läuft mit Hardened Runtime ohne Entitlements; die Bibliotheksvalidierung
  ist aktiv. Ein öffentliches macOS-Release wird erst akzeptiert, nachdem jedes
  Mach-O mit Developer ID Application signiert, das Distributionsarchiv von Apple
  notarisiert und das Ticket angeheftet und validiert wurde. Lokale
  Apple-Development-Builds bleiben Entwicklungsartefakte und werden nicht veröffentlicht.
- Der Schutz vor Bildschirmaufnahmen ist bestmöglich, aber nicht vollständig.
  Er kann nicht jedes Aufnahmeprogramm, jede Fernzugriffskonfiguration oder
  Hardwarekamera blockieren.
- Passwörter existieren vorübergehend als verwaltete Strings. Auslagerungsdateien,
  Ruhezustand, Debugger, Schadsoftware mit Benutzerrechten sowie Hardware- oder
  Zeitangriffe kann eine .NET-Desktop-Anwendung nicht vollständig ausschließen.
- Die Speichersperre erfasst nur ausdrücklich gesperrte Puffer. CPU-Register,
  native Arbeitsstapel und interne Zustände kryptografischer Betriebssystemanbieter
  lassen sich aus der Anwendung nicht zuverlässig sperren oder nullen.
- Threefish und ChaCha20 verwenden ARX-Operationen ohne geheime Tabellen.
  Auf Apple Silicon lehnt der produktive AES-Adapter jeden Anbieter außer dem
  ArmV8-Hardwarepfad von Crypto++ ab. Kalyna, MARS und SHACAL-2 bleiben tabellenbasiert
  und bieten keinen beweisbaren Schutz gegen Cache-Seitenkanäle auf einem
  kompromittierten gemeinsam genutzten System.
- Ein 1024-Bit-Threefish-Schlüssel und ein 1024-Bit-Skein-Tag bedeuten nicht,
  dass die Gesamtkonstruktion 1024 Bit Sicherheit besitzt. KDF, Passwortmaterial,
  Chiffren, beide MACs und Implementierung begrenzen gemeinsam die reale Stärke;
  Sicherheitsbits addieren sich nicht. Auch sechs Chiffren machen die Kaskade
  nicht sechsmal stärker. Ein Angreifer muss jede Schicht überwinden; die
  Einzelstärken werden nicht summiert.
- Zwei schlüssellose Hashes sind keine digitale Signatur. Aktiven Fälschungswiderstand
  erhalten Release-Manifeste erst durch ihre verpflichtenden RSA-PSS-/ML-DSA-
  `.khsig`-Signaturen und den Schutz beider privater Schlüssel.
- Die hybride Codesignatur bleibt gegenüber einem kryptografisch relevanten
  Quantenangreifer nur fälschungsresistent, wenn ML-DSA-87, seine Implementierung
  und der außerhalb des Pakets verankerte Pin standhalten. RSA-4096 allein ist
  nicht quantensicher. Die UND-Konstruktion erlaubt allerdings keinen Rückfall
  auf RSA, wenn dieses durch Shor gebrochen wird.
- `.khsig` besitzt keinen eigenen RFC-3161-Zeitstempel und keinen eigenen
  Widerrufsstatus. Langfristige Release-Archivierung muss Schlüsselkompromittierung
  und Pinwechsel organisatorisch behandeln.
- Die aktuellen Signierschlüssel liegen in einem lokalen Schlüsselspeicher,
  nicht in einem HSM. Ein öffentliches Release benötigt zwei getrennt geschützte
  Signierschlüssel und einen unabhängig verteilten Verifier.
- Eine Selbstprüfung kann einen vollständig ersetzten Anwendungsstart nicht dazu
  zwingen, seinen eigenen Prüfcode auszuführen. Launcher, cdhash-Pins und
  Rückrollschutz erhöhen die Hürde, beseitigen diese Klasse lokaler Startangriffe aber nicht.
- KPAR2 bietet Authentizität gegen Angreifer nur bei verschlüsselten Archiven
  und erst nach erfolgreicher Prüfung beider domänengetrennter Wiederherstellungs-MACs.
  Das unverschlüsselte Profil und der Notfallmodus bieten ausschließlich Fehlerkorrektur.
- `KPAR2` ist ein anwendungsspezifisches Format und nicht mit Standard-PAR2-Werkzeugen
  kompatibel. Bei 1 TiB benötigt die Parität allein bei 15 Prozent 153,6 GiB
  Begleitdateispeicher zuzüglich Metadaten und mehrere vollständige Lese-/Schreibdurchläufe.
- Dateiweises Überschreiben garantiert keine physische Löschung auf SSDs.
  Echtes ATA/NVMe Secure Erase und Crypto Erase sind Firmwareaktionen für ganze Laufwerke.
- Cloudversionierung, Backups, Snapshots und vorhandene PDF- oder Druckspoolerdateien
  können weiterhin gelöschte Archive oder Schlüsselzettel enthalten.
- ZPAQ ist ein großer nativer C++-Parser. Unter macOS läuft er über
  operationsspezifische Seatbelt-Profile, die standardmäßig verweigern und
  Netzwerkzugriff sowie das Abspalten von Prozessen untersagen. Diese separate
  Prozesseinschränkung ist kein App-Sandbox-Entitlement der Hauptanwendung.
  Pfadtests, ein deterministischer Mutationskorpus und Prozessgrenzen senken das
  Risiko, ersetzen aber weder kontinuierliches Fuzzing noch ein unabhängiges Audit des Parsers.
- Ein physischer 1-TB-Gesamtdurchlauf, ein formaler Sicherheitsbeweis und ein
  unabhängiges externes kryptografisches Audit wurden nicht durchgeführt.

---

Quellen: [Crypto++ Kalyna](https://github.com/weidai11/cryptopp),
[PHC Argon2](https://github.com/P-H-C/phc-winner-argon2),
[ZPAQ](https://github.com/zpaq/zpaq),
[Crypto++](https://github.com/weidai11/cryptopp),
[FIPS 202 / SHA-3](https://csrc.nist.gov/pubs/fips/202/final),
[FIPS 204 / ML-DSA](https://csrc.nist.gov/pubs/fips/204/final),
[pq-crystals/dilithium](https://github.com/pq-crystals/dilithium),
[Threefish-/Skein-Autoren](https://www.schneier.com/academic/skein/threefish/),
[Skein-1.3-Fachartikel](https://www.schneier.com/wp-content/uploads/2015/01/skein.pdf),
[RFC 8439 / ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439).
