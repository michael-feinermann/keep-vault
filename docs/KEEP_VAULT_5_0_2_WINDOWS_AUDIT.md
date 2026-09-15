# Keep Vault 5.0.2 – Windows-Prüfbericht

Arbeitsstand vom 15. September 2026. Dieser Bericht wird um die tatsächlichen
Windows-Läufe ergänzt; offene Prüfungen sind keine bestandenen Freigaben.
Die macOS-Referenz ist `origin/master` bei
`7ff2eda764ad321ed25c88f862ee20a8a9822690`. Der bestehende öffentliche Tag
`v5.0.2` gehört zum macOS-Commit und wird durch die Windows-Ergänzung nicht
verschoben. Die sechs vorhandenen macOS-Dateien bleiben unverändert.

## Aktueller Freigabestatus

**Noch kein freigegebener Windows-Release.** Die Implementierung und die unten
abgegrenzten Teilprüfungen sind weiter fortgeschritten; ein vollständiger finaler
Build, die Ende-zu-Ende-Freigabe und die Veröffentlichung sind noch offen.

Bitdefender hat am 9. September 2026 um 12:35:59 Ortszeit die frisch kompilierte
Datei `tools/kalyna_v12.dll` als `Gen:Variant.Lazy.491499` quarantänisiert.
Der in der Quarantänemetadatei protokollierte SHA-256 lautet
`EB9C783FBC418880F0FB1B9B9ACD871731959A2BC55AAC070AC880410EA24BA1`
(573440 Bytes). Die Erkennung ist ungeklärt. Ein Vergleich der einschlägigen
Crypto++-Quellen mit dem festen Upstream-Tag `CRYPTOPP_8_9_0` ergab nur die
dokumentierte Apple-Anpassung in `cpu.cpp`; das ist kein Nachweis, dass die
erkannte Binärdatei sicher ist. Es wurde keine Ausnahme eingerichtet, keine
Quarantänedatei wiederhergestellt und kein Antimalware-Schutz verändert.

Ohne diese Bibliothek können die vollständige Kryptografie-, Archiv- und
Installationsprüfung sowie der finale Release-Build nicht bestanden werden.
Die bereits signierten neun übrigen Native-Tools sind Arbeitskandidaten;
sie ersetzen keinen neu gebauten vollständigen Satz aus einem unveränderlichen
finalen Quell-Commit.

## GUI und macOS-Referenz

Die Windows-Oberfläche übernimmt die Referenzstruktur aus `KeepVaultMac`:
1220 × 860 Ausgangsgröße, 980 × 720 Mindestgröße, Hintergrund `#08101D`,
Inter-Schrift mit mitgelieferter Lizenz, Karten, Spalten, Register, Abstände,
Statusanzeige und Zustände für Fokus, Auswahl, Hover und deaktivierte Eingaben.
Die Texte und Ansichten sind auf Deutsch und Englisch vorhanden. Native
Fensterrahmen, Datei-/Druckdialoge und die technische Monospace-Schrift sind
plattformabhängig; eine pixelgenaue Gleichheit sämtlicher Betriebssystemelemente
wird nicht behauptet.

Fünf GUI-Testgruppen bestehen mit der aktuellen verwalteten Implementierung
unter Runtime `10.0.12`, einschließlich der Installer-Oberfläche.
Darunter werden acht Ansichten aus den tatsächlichen WPF-Produktionskontrollen
gerendert. Dafür wird kein Screenshot-Schutz abgeschaltet. Diese renderbaren
Kontrollen und die automatisierten Handlerprüfungen ersetzen keinen kompletten
interaktiven Durchlauf der final signierten Anwendung.

Auch Installer und Scanner sind an den Referenzablauf angepasst. Der Installer
verwendet native Windows-Kontrollen für Bestätigung, Fortschritt und Ergebnis;
lange Meldungen erscheinen vollständig in einem begrenzten, schreibgeschützten
und auswählbaren Detailfeld. Der Scanner übernimmt 760 × 800, 430 Pixel
Vorschaubereich, einen 120 Pixel hohen Ergebnisbereich mit internem Scrollen
und die Aktionen und Sprachsegmente am unteren Rand. Seine 151 Prüfungen
bestehen mit null Buildwarnungen/-fehlern. Weitere acht DE/EN-Renderings zeigen
kurze/lange Installer-Meldungen und den Scanner bei Standard-/Mindestgröße.
Alle 16 aktuellen Haupt-/Installer-/Scanner-Ansichten wurden zusätzlich
unabhängig gesichtet; in diesen Ansichten wurde kein verbleibender konkreter
Darstellungsfehler gefunden. Das ist keine Prüfung aller Hover-, DPI- oder
physischer Kamerazustände.

Die Schlüsselzettel verwenden das Referenzlayout mit getrennten Faktoren A/B,
je zwei identischen QR-Codes, drei PIN-Schreibzeilen und einer separaten
Anleitungsseite. Die vier aktuellen DE/EN-PDFs haben jeweils zwei Seiten.
Eine unabhängige Prüfung mit PyMuPDF und zxing-cpp bestätigt die vorgesehenen
256-stelligen Testfaktoren und alle 24 QR-Payloads in PDF- und Druckrenderings.
Alle dafür verwendeten Faktoren sind ausdrücklich synthetische Testwerte.
Ein tatsächlicher Papierausdruck mit anschließendem Kamerascan ist noch offen.

## Behobene Fehler und Sicherheitsprüfung

- WPF-Eingaben werden vor dem Wechsel in Arbeits-Threads übernommen; direkte
  Zugriffe auf threadgebundene Kontrollen aus den Callbacks sind entfernt.
- Die Erzeugungsrichtlinie für Passwort/PIN bleibt von der technischen
  Entschlüsselungskompatibilität getrennt. Referenzmodelle und eingefrorene
  Kompatibilitätsfixtures behalten durch `.gitattributes` ihre exakten Bytes.
  Zeilenendenkonvertierung hatte zuvor die gepinnten Modellhashes beschädigt.
- Native ZPAQ-Ausgaben werden relativ zu gehaltenen Verzeichnis-Handles neu
  angelegt. Junctions, fremde Vorbelegungen, Namensaliasse und Pfadwechsel
  werden abgewiesen; ergänzende Unicode-Zeichen und Streaming-Metadaten bleiben
  erhalten. Thread-Infrastrukturfehler beenden den Native-Prozess kontrolliert,
  ohne durch noch laufende Worker zurückzuspringen.
- Dateiinspektion hält einen echten Lesezugriff und verhindert konkurrierende
  Schreib-/Umbenennungszugriffe. Mehrdateioperationen und Shortcut-Erstellung
  binden auch den Rollback an die tatsächlich erzeugten Objekte.
- Installerprüfung und -kopie halten Quelle und Ziel während der Übergänge;
  unzulässige Pfade, zusätzliche Dateien, Hardlinks, Reparse Points und
  Änderungen während der Kopie werden abgewiesen.
- Die Native-Quellprüfung kontrolliert 431 Vendor-Dateien, drei zusätzliche
  Windows-Änderungen und die vollständige Menge von 202 Crypto++-Übersetzungseinheiten
  vor dem Build. Leere Pfadsegmente und andere mehrdeutige Einträge werden
  zurückgewiesen.
- Die Argon2-Fehlerbereinigung wartet auf die kumulativ gestarteten Worker.
  Zuvor wurde der kumulative Abschlusszähler mit der nach erfolgreichen Joins
  sinkenden Aktivzahl verglichen. Bei einem späten Create-/Joinfehler konnte
  dadurch Speicher zu früh freigegeben werden. Der isolierte Windows-Harness
  reproduziert für beide Fehlerarten die alte vorzeitige Freigabe und bestätigt
  nach dem Fix das Ende aller Worker vor der Freigabe. Er fängt den gefährlichen
  Vorher-Fall ab, statt selbst einen Use-after-free auszuführen.

Die protokollierten Teilprüfungen umfassen 10/10 Passwortmodell-/PIN-Gruppen,
2/2 Kompatibilitäts-Provenienz-/Ablehnungsgruppen, 3/3 Dateisicherheitsgruppen,
5/5 GUI-Gruppen und 151 QR-Scanner-Prüfungen. Die sechs tatsächlichen
Kompatibilitäts-Entschlüsselungs-/Reparaturgruppen und die komplette Suite
sind damit ausdrücklich nicht als bestanden ausgewiesen.

Die sieben ZPAQ-Gruppen bestehen auch mit dem am 15. September nach den
Analysekorrekturen neu gebauten und signierten Arbeitskandidaten. Beim ersten isolierten Lauf fehlte der Test-Apphost; nach dessen
Übernahme besteht auch die Prozessabbruch-/Ausgabebegrenzungsgruppe. Das war
ein unvollständiger Testaufbau und kein erfolgreicher erster Gesamtlauf.
Am 15. September bestehen zusätzlich ML-DSA-87-Interoperabilität samt
Manipulationsablehnung, der echte Argon2id-Referenzvergleich mit 1 GiB,
ChaCha20-Parallelvergleich über 256 MiB einschließlich Countergrenzen,
Threefish-Parallelvergleich, AES-NI-Provider, unabhängiger Skein-MAC-Vergleich
und Prozesshärtung. Argon2-, Threefish- und Skein-Prüfungen wurden nach dem
gezielten Neubau ihrer geänderten Quellen erfolgreich wiederholt.

Der vollständige statische Lauf analysiert 23 Übersetzungseinheiten und endet
mit Exitcode 0. Die verbleibenden Warnungen und ihre Bewertung stehen im
[separaten Native-Analysebericht](WINDOWS_NATIVE_ANALYSIS_5.0.2.md). Ein erfolgreicher
Analyselauf wird ausdrücklich nicht mit Warnungsfreiheit gleichgesetzt.

## Build und Abhängigkeiten

Alle Windows-Projekte zielen auf .NET 10; die ausführbaren Produkte tragen
Version `5.0.2`, Dateiversion `5.0.2.0`. Hauptanwendung, Release-Verifier,
Signierwerkzeug und QR-Scanner wurden mit dem exakt gepinnten SDK `10.0.400`
im Locked Mode wiederhergestellt. Die Lockfiles wurden bewusst für die neue
TFM regeneriert. `System.Security.Cryptography.ProtectedData` ist auf
`10.0.0` aktualisiert; die unter .NET 10 WPF bereits enthaltene
`System.Security.Cryptography.Pkcs`-Paketreferenz wurde entfernt.
Der separate selbständige WPF-Installer hat einen eigenen geprüften Lockfile.

Für den abschließenden Build wurde der SDK-Pin am 15. September auf `10.0.401`
angehoben. Der vorherige SDK enthält Runtime `10.0.11`; Microsoft hat für
`10.0.12` weitere Sicherheitskorrekturen veröffentlicht. Das Windows-x64-SDK-
Archiv wurde über Microsofts offizielle Release-Metadaten bezogen und vor der
Installation gegen deren SHA-512 geprüft. Die endgültige Laufzeit soll daher
`.NET` und `WindowsDesktop` `10.0.12` enthalten; frühere Teilprüfungen unter
`10.0.11` bleiben als frühere Ergebnisse erkennbar. Quelle:
[Microsofts Sicherheitsupdate vom 8. September 2026](https://devblogs.microsoft.com/dotnet/dotnet-and-dotnet-framework-september-2026-servicing-updates/).

Die erneute NuGet-Abfrage am 15. September 2026 meldet für die fünf Graphen
Hauptanwendung/Tests, Scanner/Tests, Signierwerkzeug, Installer und Verifier
einschließlich transitiver Pakete keine bekannten anfälligen Pakete in den
abgefragten Quellen. Das ist eine Datenbankabfrage und keine Garantie gegen
unbekannte Schwachstellen.

Der neue Signierwerkzeug- und Installer-Build besteht mit null Warnungen und
null Fehlern. Ein Build allein belegt weder die vollständige Anwendung noch
GUI, Installationsablauf, native Sicherheit oder veröffentlichte Artefakte.

## Schlüssel und Signierung

Private Release-Schlüssel werden direkt vom vom Benutzer angegebenen Medium
gelesen. Weder Passwort noch Schlüsselinhalt werden als Prozessargument,
Umgebungsvariable, Logeintrag oder temporäre Klartextdatei weitergereicht.
Der RSA-PFX-Schlüssel wird mit `EphemeralKeySet` geladen. Passwort-Bytes,
Passwort-Zeichen und temporäre Schlüsselarrays werden nach Gebrauch gelöscht.
Die AES-GCM-Envelope-Typen sind ausschließlich `KVMDSA12` und `KVPFXP12`;
Typ und kanonische Länge sind authentifiziert. Die alte universelle
`KVSECRT1`-Release-Hülle wird nicht akzeptiert. Für ML-DSA und PFX bestehen
getrennte Wrapping-Key-Dateien. Reparse-Pfade, mehrfache Hardlinks und
abweichend aufgelöste Dateien sind für Release-Geheimnisse gesperrt.

Das vorhandene öffentliche RSA-Zertifikat wurde sicher geladen und geprüft:

- Subject und Issuer: `OU=Keep Vault, O=Michael Feinermann, CN=Keep Vault macOS Hybrid Release`.
- RSA 4096 Bit; Zertifikatssignatur SHA-512/RSA; EKU Code Signing.
- Gültigkeit UTC: 15. August 2026 14:48:44 bis 12. August 2036 14:48:44.
- SHA-256 des öffentlichen SPKI:
  `BCA8E666BDC632C4A1C4BE0041B8677B820FF6F21C77BA9129E5809598295DE9`.

Das Zertifikat ist selbstsigniert. Die Windows-Zertifikatskette ist damit
nicht allgemein vertrauenswürdig; weder ein Root-Zertifikat noch ein
globales Vertrauen wird installiert. Die Programme prüfen die fest
eingebauten RSA-/ML-DSA-Pins und ihre Authenticode-/Hybrid-Signaturen.
Signierung und RFC3161-Zeitstempel sind getrennte Schritte, damit signtool
keinen privaten Schlüssel und kein Passwort als Argument benötigt.

Die echte App-Prüfung hat eine SHA-256-Signatur trotz angefordertem SHA-512
im bisherigen PowerShell-Signierweg erkannt und korrekt abgewiesen.
`ReleaseAuthenticodeSigner` ruft deshalb `SignerSignEx2` mit dem numerischen
`CALG_SHA_512` und dem flüchtigen Zertifikat direkt auf. Zusätzlich werden
sowohl der PE-Inhaltsdigest als auch der primäre CMS-Signerdigest als
SHA-512 geprüft; ein SHA-512-Zertifikat oder Zeitstempel allein genügt nicht.
Alle neun verfügbaren Native-Arbeitskandidaten wurden so erneut signiert und
weisen PE-/CMS-SHA-512, 64-Byte-PE-Digest und einen RFC3161-Zeitstempel auf.
Windows bestätigt dabei ausschließlich `CERT_E_UNTRUSTEDROOT`; die echte
Anwendungsprüfung akzeptiert die korrekten eingebauten Pins.

Bestandene synthetische Regressionen verwenden frisch erzeugte Testschlüssel:

- v12-ML-DSA- und PFX-Rundlauf mit UTF-8-Passwort einschließlich Leerzeichen.
- Ablehnung falscher Geheimnistypen, manipuliertem Header, Nonce, Payload
  und Tag, falscher Länge, angehängter Bytes und ungültigem UTF-8.
- Hybride RSA-PSS/SHA-512- und ML-DSA-87-Signatur mit unabhängiger nativer
  ML-DSA-Referenzprüfung; veränderte Nutzdaten werden abgelehnt.
- `tools/Test-EphemeralAuthenticode.ps1`: Signatur aus einem rein
  speicherinternen Zertifikat; Windows bestätigt ausschließlich
  `CERT_E_UNTRUSTEDROOT`, nach einem EXE-Bitflip `TRUST_E_BAD_DIGEST`.
  PE und primärer CMS-Signer verwenden nachweislich SHA-512; eine absichtlich
  mit SHA-256 signierte Gegenprobe wird zurückgewiesen.

## Paket und Installer

Der implementierte Paketaufbau umfasst die selbständigen Programme `Keep Vault.exe`,
`QR-Scanner/QR-Scanner.exe`, `Keep Vault Release Verifier.exe` und
`Keep Vault Setup.exe`. Alle benötigten Laufzeitkomponenten sind eingebettet;
auf dem Zielgerät ist kein SDK, Compiler oder Restore erforderlich.
`RELEASE-INVENTORY.json` bindet Produkt, Version, Architektur und den gesamten
Dateisatz mit relativen Pfaden, Größen und SHA-512-Digests. Das Inventar wird
mit beiden vorhandenen Verfahren signiert und umfasst auch sämtliche bereits
erzeugten Signatur-Sidecars. Nur das Inventar und sein eigener Signatur-Sidecar
sind aus diesem nichtzirkulären Dateisatz ausgenommen.

Der Installer hält Dateien und Elternverzeichnisse während der Prüfung und
Kopie offen. Zusätze, Auslassungen, mehrdeutige Pfade, Reparse Points und
Hardlinks werden abgewiesen. Er erstellt ein neues Verzeichnis im lokalen
Programmverzeichnis des Benutzerkontos, prüft die installierte Kopie erneut
und legt danach Verknüpfungen an. Bestehende App-Dateien werden niemals
überschrieben. Vorhandene Verknüpfungen führen zu einem ausdrücklichen Abbruch
vor der Installation; dieser Fall wird nicht als Erfolg gemeldet. Es gibt
keinen privilegierten Installerprozess und keine System-Truststore-Änderung.

Ein fehlgeschlagener Vorgang lässt alte Installationen unverändert. Eine
angefangene neue, nicht verknüpfte Kopie kann als überprüfbares Restverzeichnis
zurückbleiben; es wird keine unsichere rekursive Bereinigung fremder Pfade
versucht. Tatsächliche Installer-Positiv-/Negativfälle und die reale DE/EN-GUI
sind vor Veröffentlichung zusätzlich zu protokollieren.

Die synthetische Inventarregression ist bestanden: Originalprüfung und Kopie
mit identischem Inventardigest, Ablehnung einer zweiten Kopie in ein vorhandenes
Ziel, blockierter Schreibzugriff auf eine während der Prüfung gehaltene Datei,
Zurückweisung zusätzlicher oder veränderter Dateien und unsicherer relativer
Pfade. Die Shortcut-Serialisierung erfolgt vollständig über `IShellLink` und
einen Speicherstream. Ein unabhängiger Windows-Shell-Readback der synthetischen
Verknüpfung bestätigt den beabsichtigten Zielpfad. Es wurde dabei kein Programm
über die Verknüpfung gestartet und keine Benutzerverknüpfung verändert.

## Reproduzierbare Release-Kommandos

In einem unveränderlichen Snapshot des geprüften Windows-Commits, mit dem
SDK `10.0.401` als erstem `dotnet` im PATH:

```powershell
dotnet restore KalynaArchiver.Tests/KalynaArchiver.Tests.csproj --locked-mode
dotnet restore KeepVaultInstaller/KeepVaultInstaller.csproj --locked-mode
dotnet restore KalynaReleaseVerifier/KalynaReleaseVerifier.csproj --locked-mode
dotnet restore QrCodeScannerWindows/QrScanner.Tests.csproj --locked-mode
cmd /c tools/Build-Native.cmd
dotnet build KalynaArchiver.Tests/KalynaArchiver.Tests.csproj -c Release --no-restore
dotnet run --project KalynaArchiver.Tests -c Release --no-build -- --smoke
dotnet run --project KalynaArchiver.Tests -c Release --no-build -- --full
dotnet run --project KalynaArchiver.Tests -c Release --no-build -- --performance
pwsh -NoProfile -File tools/Build-Portable.ps1 -ReleaseKeyDirectory 'A:\Keep Vault ReleaseKeys v12'
& 'dist/Keep Vault Release Verifier-win-x64.exe' 'dist/Keep Vault-portable-win-x64'
& 'dist/Keep Vault Release Verifier-win-x64.exe' 'dist/Keep Vault-portable-win-x64.zip'
pwsh -NoProfile -File tools/Test-ReleaseTamperResistance.ps1
```

Für das getrennte Signieren neugebauter Native-Tools liefert der überprüfbare
Helper nur Dateipfade und öffentliche Pins:

```powershell
$releaseSigning = & tools/New-ReleaseSigningParameters.ps1 -ReleaseKeyDirectory 'A:\Keep Vault ReleaseKeys v12'
. tools/NativeToolTargets.ps1
$nativeTargets = @(Get-NativeToolTargets -Root $PWD)
& tools/Sign-Binaries.ps1 -Path $nativeTargets @releaseSigning
& tools/Generate-ReleaseManifests.ps1 @releaseSigning
```

Der komplette Parameterfluss zu `Sign-Binaries`, `New-HybridSignature`,
`Generate-ReleaseManifests` und `Sign-ManagedOutput` ist geprüft. Die Skripte
akzeptieren keine Klartext-PFX-Passwortparameter mehr. Ein frischer
PowerShell-Prozess pro Quell-Snapshot verhindert die Wiederverwendung einer
bereits geladenen Signierassembly aus einem anderen Verzeichnis.

Zusätzlich erforderlich bleiben die nativen unabhängigen KATs und
Threadfehlerprüfungen, der echte 256-MiB-Paranoia-Lauf auf Stufe 5, der letzte
komplexe Ordnerbaum-Rundlauf, reale Installer-/GUI-Prüfungen, ZIP-Entpackprüfung,
Sicherheitsreview, Quell-/Artefakthashes und Remote-Abgleich. Veröffentlichung
und heruntergeladene finale Assetbytes werden erst nach diesen Läufen bestätigt.
