# Keep Vault 5.0.2: Passwort- und PIN-Vertrag für Container v12

Diese Spezifikation ergänzt den bestehenden v12-Vertrag. Die macOS-App erhält
Marketingversion 5.0.2 und Buildnummer 13. Container v12 und KPAR2 v4 bleiben
unverändert. Die getrennt geprüfte Version 5.0.1 ist im Tag `v5.0.1` erhalten.
Der abschließende Prüfbericht für 5.0.2 muss die Umsetzung dieses Vertrags
belegen. Eine Spezifikation allein bestätigt keine bestandenen Tests.

## Archivierung und Wiederherstellung

Passwort und PIN werden vom Nutzer gewählt. Die zwei unabhängigen generierten
Schlüsselzettelfaktoren A und B behalten ihre bisherigen Prüfungen. Es gibt
keinen Passwort- oder PIN-Generator und keine Ausnahme für behauptete zufällige
Herkunft einer Eingabe.

Alle bisherigen und zusätzlichen Auswahl- und Stärkeregeln gelten ausschließlich
bei der Erstellung eines Archivs. Der gemeinsame Containerdienst prüft sie vor
Ausgabemutation gegen die endgültigen Werte. Eine GUI-Vorprüfung ersetzt diese
Prüfung nicht. Änderungen von Passwort, PIN oder lokalem Datum dürfen keine
veraltete positive Paarprüfung übernehmen.

Beim Entpacken, Auflisten, Authentifizieren und Reparieren gelten weder alte
noch neue Auswahlregeln: keine 24-Zeichen-Mindestlänge, keine 256-Zeichen-
Passwortgrenze, keine 6-bis-16-Ziffern-PIN-Grenze, keine Kompositionsregeln,
Blocklists, Muster-, Datums-, Teilstring- oder Modellbewertung. Die benötigten
Modellressourcen dürfen dort weder geladen noch ausgewertet werden müssen.
Auch kryptografisch korrekte leere oder kurze Werte werden nicht wegen ihrer
Qualität gesperrt.

Technische Verarbeitung bleibt erforderlich: nicht-null Zeichenfolgen,
ASCII-Ziffern für die PIN, unveränderte UTF-8-Kodierung des Passworts,
Faktorformatsyntax, sichere Ressourcenallokation und kryptografische Prüfung.
Passwort und PIN haben getrennt eine technische Obergrenze von jeweils
1.048.576 UTF-16-Codeeinheiten. Diese Begrenzung schützt die Allokationen; sie
ist keine Annahmeregel für neue Geheimnisse. Führende Nullen, Leerzeichen im
Passwort und dessen originale Unicode-Darstellung bleiben erhalten. Keine
Normalisierung, kein Trimmen und keine Groß-/Kleinschreibung ändern KDF-Bytes.

Das bestehende Headerfeld
`UserPassword24to256+PIN6to16+GeneratedHex1024x2` bleibt als v12-Protokollkennung
bytegleich. Seine Bezeichnung beschreibt das Erstellungsprofil und darf nicht
als erneute Qualitätsprüfung beim Lesen verwendet werden. Ein Modellupdate
ändert weder Magic, Version, Headerreihenfolge, Domains, Length-Prefixes,
Salts, Nonces, Rollen noch die Authentifizierungs- und KDF-Verfahren.

## Unveränderte Passwortregeln bei Erstellung

Es gelten weiterhin 24 bis 256 UTF-16-Codeeinheiten, mindestens drei
Zeichenklassen, zwölf unterschiedliche `char`-Werte, zwölf Nicht-Hex-Vorkommen,
höchstens sieben zusammenhängende ASCII-Hex-Zeichen, keine Steuerzeichen und
keine ungültigen UTF-16-Folgen. Passwortbestätigung und Faktorvergleiche bleiben
erhalten. Die beiden generierten Faktoren müssen unterschiedlich sein.

Die bisherige Berechnung mit Faktor 0,70 und sämtlichen Abzügen bleibt erhalten.
Der endgültige Wert ist das Minimum aus diesem bisherigen Wert und allen
anwendbaren zusätzlichen, vollständig beschriebenen Modellwerten. Eine
bisherige Ablehnung darf niemals in eine Annahme wechseln. Die Grenze bleibt
`MinimumConservativeEntropyBits = 128.0`.

Zusatzmodelle betrachten die vollständige Eingabe einschließlich Wortfolgen,
mehrdeutiger Segmentierung, Verkettung, Komposita, Flexion, Leetspeak,
Schreibvarianten, Namen, Tastaturwegen, Wiederholung, Datum/Jahr, Suffixen und
unbekannten Resten. Worttreffer werden nicht mehrfach als zusätzliche Stärke
gezählt. Ein einzelnes Wörterbuchwort allein sperrt kein Passwort. Fehlende
Worterkennung beweist keine Zufallsherkunft.

Alle Daten werden offline mitgeliefert, versioniert, auf Anzahl, Duplikate und
Hashes geprüft und durch die signierte App authentifiziert. Das gilt ab dem
ersten Start. Ein fehlender oder beschädigter Bestand verhindert eine positive
Archivierungsentscheidung und löst keinen Netzwerkersatz aus. Bei fehlerhaften
Daten bleibt die Wiederherstellung verfügbar. Laufzeitupdates sind keine
Voraussetzung und dürfen den überprüften Bestand nicht ungeprüft ersetzen.
Diese Trennung hebt die App-Integritätsprüfung nicht auf. Eine manipulierte
signierte Anwendung darf weiterhin insgesamt beim Start abgewiesen werden;
der Reader selbst benötigt in einer intakten App keinen Modellbestand.

Die festen Erkennungsbestände sind:

| Bestand | Größe | Behandlung |
| --- | ---: | --- |
| EFF Englisch, lange Liste | 7.776 | Listenraum mit `log2(7776)` pro frei kombinierbarem Wort |
| dys2p Deutsch nach EFF-Vorbild | 7.776 | Eigenständige deutsche Quelle, keine vermeintliche deutsche EFF-Ausgabe |
| BIP39 Englisch | 2.048 | Originalreihenfolge, Wortindizes und Prüfsumme erhalten |

Für gültige vollständige BIP39-Folgen mit 12, 15, 18, 21 oder 24 Wörtern
gelten Obergrenzen von 128, 160, 192, 224 beziehungsweise 256 ursprünglichen
Entropiebits. Prüfsummenbits werden nicht hinzugezählt. Nicht gültige
Wortfolgen erhalten keinen gültigen Mnemonic-Status. Varianten und zusätzliche
Zeichen müssen als vollständige Konstruktion bewertet werden. Es wird kein
Wallet-Seed berechnet. Diese Räume belegen keine Entropie menschlicher Auswahl.

Weitere Daten, feste Versionen, Lizenzen, Transformationen und Modellgrenzen
stehen bei den [mitgelieferten Modelldaten](../KalynaArchiver/Resources/PasswordModel/README.md).
Ein exakter Treffer in der ausgewählten lokalen Passwortsperrliste wird
abgelehnt. Der begrenzte Bestand darf nicht als vollständiger HIBP-Snapshot
ausgegeben werden. Keine PIN, kein Passwort, kein Eingabehash und keine
personenbezogenen Eingabeteile verlassen für diese Prüfungen den Prozess.

## Unveränderte und zusätzliche PIN-Regeln bei Erstellung

Es bleiben sechs bis sechzehn ASCII-Ziffern, mindestens vier verschiedene
Ziffern, Bestätigung, die vollständige bisherige Sperrliste sowie sämtliche
Dreierfolgen-, Sequenz-, Keypad-, Wiederholungs- und Doppelgruppenregeln.
Die zusätzlichen Modelle können ausschließlich weitere Ablehnungen bewirken.

Die gesamte PIN darf kein zusammenhängender wörtlicher Teilstring des rohen
Passworts sein. Führende Nullen zählen mit. Ziffern werden für diese Regel
weder getrennt noch zusammengesetzt. Die endgültige Paarprüfung benötigt beide
Werte; eine isolierte PIN-Vorprüfung darf keine Paarfreigabe behaupten.

Die PIN darf nicht dem heutigen lokalen Kalenderdatum in `DDMMYY`, `DDMMYYYY`,
`MMDDYY` oder `MMDDYYYY` entsprechen. Am 06.09.2026 sind das `060926`,
`06092026`, `090626` und `09062026`. Die Regel verwendet Gleichheit des gesamten
Werts und wird unmittelbar bei der finalen Erstellungsprüfung neu ausgewertet.
Die Gerätezeitzone entscheidet; ohne Netzwerkzeit kann eine falsche lokale
Uhr das Datum beeinflussen. Doppelte Formatwerte sind derselbe Sperrwert.

Weitere Kalenderprüfungen validieren echte Tage einschließlich Schaltjahren.
Das versionierte Referenzjahr ist 2026, der anfängliche vierstellige Bereich
1900 bis 2056. Er ist unabhängig vom aktuellen lokalen Tagesdatum. Zusätzliche
numerische Muster dürfen nicht frühere Ablehnungen aufheben. Ein Datumssegment
in einer längeren PIN ist kein Treffer der heutigen Datumsgleichheitsregel.

Die in der Vorlage diskutierten 17-bis-30-Bit-Schwellen und HIBP-Counts von 10
oder 20 sind unkalibrierte Entwurfswerte. Sie sind keine nachgewiesenen
Sicherheitsgrenzen. Ohne unabhängige Kalibrierung wird kein entsprechender
empirischer Guess-Rank oder garantierter Mindestschutz behauptet.

## Anzeige und Version

Direkt unter dem deutschen beziehungsweise englischen Untertitel steht die
Marketingversion, beispielsweise `Version 5.0.2`, aus derselben Versionierung
wie der Build. Die Versionszeile und der umbrochene Untertitel müssen bei der
kleinsten unterstützten Fenstergröße lesbar bleiben.

Anzeige und Entscheidung verwenden denselben korrigierten Modellwert. Die
Anzeige wird auf ganze Modellbits abgerundet, damit etwa 127,9 nicht als 128
erscheint. Der Text bezeichnet ihn als Schätzung. Weder Schätzwerte noch
Wortlistenräume werden als gemessene Quellenentropie oder Entschlüsselungszeit
ausgegeben. Die ausführliche Hilfe erklärt Abdeckung und Unsicherheit.

## Angriffspfad und Nachweisgrenzen

Beide v12-Credential-Branches hängen von Passwort, PIN und beiden generierten
Faktoren ab. Normale Suiten benötigen zwei Argon2id-Aufrufe, Paranoia vier mit
vollständig abhängiger zweiter Runde. Die App führt sie speicherbegrenzt
sequentiell aus. Ein Angreifer kann unabhängige Zweige derselben Runde mit
zusätzlichem Speicher parallelisieren.

Nach vollständiger KDF kann ein Kandidat anhand kleiner authentifizierter
KPAR2-Metadaten oder geeigneter Container-Tags/Chunks geprüft werden. Der
Angreifer muss dafür nicht den gesamten GUI-Archivierungs-, Recovery- und
Entpackworkflow ausführen. GUI-Benchmarkzeiten sind keine untere Grenze seiner
Kosten. Öffentlich gespeicherte Felder und abgeleitete PMI erhalten keinen
Bonus als unabhängiges Geheimnis. Passwort- und PIN-Modellwerte werden nicht
addiert; beide sind menschlich gewählte Wissensgeheimnisse.

## Plattformübergreifende Abnahme

Vor Abschluss sind mindestens folgende Belege erforderlich:

1. Alle bisherigen Negativfälle bleiben abgelehnt; für jeden Modellkorpusfall
   gilt `Hneu <= Halt`. Die beiden dokumentierten Sommer-Wiese-Beispiele werden
   unter die unveränderte 128-Bit-Grenze korrigiert, einschließlich Verkettung,
   Schreibvarianten und typischer Anhänge.
2. Wortlistenanzahl, Duplikate, Normalisierungsvarianten, unabhängige
   BIP39-Prüfsummenvektoren aller fünf Längen, Negativfälle und überlappende
   Segmentierungen sind geprüft. 256-Zeichen-Grenzfälle bleiben zeitbegrenzt.
3. PIN-Paarregeln am Anfang, in der Mitte und am Ende, führende Nullen,
   getrennte Ziffern, Datumswechsel, Zeitzonen, Schaltjahre und ergänzende
   Muster besitzen positive und negative Gegenproben.
4. Statische synthetische v12-Archive mit kryptografisch korrekten, aber
   unzulässigen neuen Eingaben werden entpackt, aufgelistet und über KPAR2
   geprüft/repariert. Ein absichtlich fehlschlagender Modellaufruf darf diese
   Pfade nicht erreichen. KDF-Zwischenwerte belegen unveränderte Eingabebytes.
5. Fehlende und beschädigte Daten verhindern positive Archivierungsprüfung;
   keine Netzwerkabfrage ersetzt sie. Vollständiges Archivieren und Entpacken
   müssen in einem frischen Prozess bei gesperrtem externem Netzwerk bestehen,
   einschließlich Auswahlprüfung und sämtlicher benötigter lokaler Modelldaten
   ohne vorbereitenden Modelldownload. Netzwerkzustand und positive Kontrollen
   vor und nach dem vollständigen Lauf werden protokolliert. Die reale GUI wird
   unabhängig für Archivierung und Entpackung geprüft; Erststart, Modelle und
   GUI-Auswahlprüfung ohne Netz werden gesondert nachgewiesen. Ein Core-Test
   mit eingefrorenen Produktionsquellen und installierten Nativebytes ist als
   solcher zu benennen und nicht als vollständiger Offline-GUI-Lauf.
6. Vollständige macOS-Prüfung, DE/EN-GUI, identische installierte/signierte
   Artefakte und sämtliche v12-Releasegates werden für 5.0.2 erneut ausgeführt.
   Windows muss dieselben Modellressourcen, Eingabebytes, Testvektoren und
   Regeln später auf echter Windows-Hardware unabhängig bestätigen.

Diese Fassung präzisiert die Nachweisstrategie. Das Nutzerdokument
„Keep Vault: Sicherheitsmodell für PINs und Passwörter“ vom 6. September 2026
fordert in Abschnitt 3.2 vollständigen Offline-Betrieb und in Abschnitt 6
vollständige Abläufe mit gesperrtem Netzwerk. Es legt dafür keinen zwingend
zusammenhängenden GUI-Test fest. Die getrennten Offline- und GUI-Prüfungen
müssen an dieselben eingefrorenen Produktionsquellen, Modelle und signierten
Nativebytes gebunden sein. Die frühere Formulierung dieses Vertrags koppelte
beide Prüfmethoden enger als die Produktanforderung; die vorliegende Präzisierung
ändert keine Funktion, Auswahlregel oder Offline-Pflicht. Ein unvollständiger
Offline-Lauf darf durch einen GUI-Nachweis nicht als bestanden gelten.

Die bisherigen Löschregeln bleiben unverändert: Nur die konkret archivierten
und erneut verglichenen Originaldateien werden gelöscht. Ihre ursprünglichen
Verzeichnisse bleiben bestehen. Eine Qualitätsänderung erweitert diesen
destruktiven Umfang nicht.
