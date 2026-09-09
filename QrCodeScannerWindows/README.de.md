# QR-Scanner (Windows)

Deutsch | [English](README.md)

Eigenständige Windows-App, die einen QR-Code über die Kamera liest, den Inhalt
in einem Textfeld anzeigt und ihn auf Wunsch in die Zwischenablage legt. Der
Inhalt wird **nicht** in eine Datei geschrieben.

Sie ist von Keep Vault unabhängig: eigener Ordner, eigenes Projekt, eigene
Abhängigkeiten, eigener Build, eigene Signatur. Sie teilt keinen Quellcode mit
Keep Vault, liest nichts aus dessen Installation, und die Buildskripte von
Keep Vault fassen sie nicht an. Der Grund ist nicht bloß Ordnung: Der Scanner
braucht eine Kamera, und das Programm, das Archivschlüssel hält, darf niemals
dasjenige sein, das eine Kamera hat.

Das macOS-Gegenstück ist [`../QrCodeScanner`](../QrCodeScanner). Beide treffen
mit denselben Worten dieselbe Entscheidung darüber, welcher der beiden
gedruckten Codes übernommen wird. Denn ein auf einer Plattform gedruckter
Schlüsselzettel wird Jahre später auf der gerade verfügbaren Plattform gelesen.

## Bauen und installieren

```powershell
pwsh QrCodeScannerWindows\tools\Build-QrScanner-Windows.ps1
```

Das Skript führt zuerst die Tests aus, erzeugt das Icon, veröffentlicht eine
eigenständig lauffähige `QR-Scanner.exe` nach `QrCodeScannerWindows\dist\` und
verweigert den Abschluss, wenn eine native Keep-Vault-Komponente in dieser
Ausgabe auftaucht. Ergänze auf dem Releasegerät `-Sign`, um die abgetrennte
RSA-PSS/SHA-512- und ML-DSA-87-Signatur anzufügen.

Kopiere `QR-Scanner.exe` und ihre `.khsig` neben `Keep Vault.exe` oder in einen
Ordner `QR-Scanner` daneben. Keep Vault sucht beim Start an beiden Stellen
und schreibt das Ergebnis in sein Sicherheitsprotokoll. Es lädt niemals den
Code des Scanners, sondern bestätigt lediglich dessen Vertrauenswürdigkeit.

Bei der ersten Verwendung fragt Windows nach der Kamera. Wird der Zugriff
abgelehnt, teilt die App das mit und verweist auf Einstellungen › Datenschutz
und Sicherheit › Kamera, da eine Desktop-App keine zweite Gelegenheit zum
Nachfragen bekommt.

## Welcher der beiden QR-Codes gilt

Ein Schlüsselzettel trägt denselben Faktor in zwei QR-Codes. Das ist der Grund
für die Regel, und sie steht vollständig in
[`Sources/CodeArbiter.cs`](Sources/CodeArbiter.cs):

| Was die Kamera sieht | Was die App tut |
| --- | --- |
| Beide Codes lesbar, gleicher Inhalt | Sofort übernommen, „durch 2 Codes bestätigt“ |
| Ein Code beschädigt, einer lesbar | Der lesbare gilt, nach 8 gleichen Lesungen in Folge |
| Beide Codes lesbar, **verschiedener** Inhalt | Nichts wird übernommen; der Widerspruch wird gemeldet |
| Nichts lesbar | Weitersuchen |

Der entscheidende Punkt: „fehlerfrei“ ist nichts, was hinterher gemessen wird.
Ein QR-Code trägt Reed-Solomon-Parität, also gibt ein Decoder keinen beschädigten
Inhalt zurück. Er repariert den Schaden und gibt das Original zurück, oder er
scheitert und gibt nichts zurück. Ein geknickter, verschmierter oder
angeschnittener Code taucht deshalb erst gar nicht unter den Treffern auf.
Der lesbare Code bleibt von allein übrig.

Dass zwei decodierte Codes denselben Inhalt tragen, wird geprüft und nicht
angenommen. Widersprechen sie sich, wäre jede Wahl geraten, und geraten würde
hier die Hälfte eines Archivschlüssels. Die App meldet stattdessen den Widerspruch.

Zwei Meldungen eines einzigen Codes in einem Bild zählen nicht als zwei Codes:
Die Treffer werden nach Position gruppiert, sonst hätte die stärkste Bestätigung
der App eine doppelte Meldung als Grundlage.

### Gegen echte Codes geprüft

`QrScanner.Tests` zeichnet zwei QR-Codes in einen Bildpuffer, der genau wie der
Kamerapuffer aufgebaut ist, übergibt ihn an denselben `Decode`-Aufruf wie die
Bildverarbeitung und prüft, dass zwei getrennte Treffer zurückkommen und der
Arbiter sie als durch zwei Codes bestätigt annimmt. Die Codes werden von
QRCoder erzeugt und von ZXing gelesen. Das sind zwei verschiedene
Implementierungen, wie es auch bei einem gedruckten Zettel tatsächlich der Fall
ist. Wird ein Code übermalt, bleibt genau ein Treffer mit dem vollständigen
Faktor übrig.

```powershell
dotnet run --project QrCodeScannerWindows\QrScanner.Tests.csproj
```

## Was die App nicht auf den Datenträger schreibt

- **Keine Dateidialoge, keine Liste zuletzt verwendeter Dateien, keine Einstellungsdatei.**
  Die App hat nichts zu lesen und nichts zu schreiben.
- **Die Rechtschreibprüfung ist ausgeschaltet**, und zwar am Textfeld. Der
  Prüfer lernt Wörter in das Benutzerwörterbuch.
- **Die Rückgängig-Historie ist ausgeschaltet.** Sie ist eine weitere Kopie
  von allem, was das Textfeld jemals enthalten hat.
- **Nichts wird protokolliert.** Der Inhalt erscheint in keiner Protokollzeile,
  keiner Ausnahmemeldung und keinem Fenstertitel.
- **Strg+C im Textfeld** wird abgefangen und über denselben Kopierpfad wie
  der Knopf geleitet. So verlässt der Nutzinhalt die App statt der auf dem
  Bildschirm angezeigten maskierten Darstellung, und es gilt dieselbe
  Ablaufzeit.

## Was diese App nicht verhindern kann

Damit die Liste oben etwas wert ist, folgt hier ehrlich die andere Hälfte.

- **Die Zwischenablage.** Der Kopieren-Knopf ist die eine Stelle, an der der
  Wert die App verlässt. Die Zwischenablage gehört Windows, nicht dieser App.
  Getan wird, was möglich ist: Der Eintrag trägt `CanIncludeInClipboardHistory=0`
  und `CanUploadToCloudClipboard=0`, die ihn aus der Win+V-Historie und von den
  anderen Geräten des Benutzers fernhalten, außerdem
  `ExcludeClipboardContentFromMonitorProcessing` für Zwischenablage-Verwalter
  anderer Anbieter. Er wird ohne das Flag zum Verbleib in der Zwischenablage
  nach dem Beenden abgelegt und nach **90 Sekunden** wieder geleert. Geleert
  wird nur, wenn in der Zwischenablage noch derselbe Wert steht. Hat der
  Benutzer inzwischen etwas anderes kopiert, bleibt das unangetastet.
- **Auslagerung und Speicherabbilder bei Abstürzen.** Der Wert liegt im
  Arbeitsspeicher. Was Windows in die Auslagerungsdatei oder in ein
  Absturzabbild schreibt, entscheidet nicht diese App.
- **Die Kamera sieht den Zettel.** Ein gedruckter Zettel vor einer Linse ist
  für die Kamera und alles andere im Raum sichtbar.
- **Der Decoder ist eine Bibliothek eines anderen Anbieters.** Windows stellt
  keinen Barcode-Decoder bereit, den eine Desktop-App aufrufen darf: Die
  WinRT-Barcode-API verlangt ein Scannergerät für Kassensysteme, und die
  OCR-Engine liest keine QR-Codes. Der macOS-Scanner verwendet den
  systemeigenen Decoder; dieser verwendet ZXing, nach Version und Hash gepinnt
  wie jede andere Abhängigkeit in diesem Repository.

## Aufbau

| Datei | Inhalt |
| --- | --- |
| `Sources/CodeArbiter.cs` | Die Regel, welcher der beiden Codes gilt. Ohne UI-Typen, damit sie testbar bleibt. |
| `Sources/PayloadInspector.cs` | Längengrenze und Hinweise auf unsichtbare Zeichen im Inhalt. |
| `Sources/ScanSession.cs` | Kamera und Decodierung. |
| `Sources/VolatileClipboard.cs` | Kopieren mit Verfallsfrist. |
| `Sources/MainWindow.cs` | Das Fenster; enthält die Einstellungen gegen das Schreiben auf den Datenträger. |
| `Sources/Localization.cs` | Jede sichtbare Zeichenfolge in beiden Sprachen. |
| `Sources/Program.cs` | Start. |
| `Tests/ArbiterTests.cs` | 109 Prüfungen der Regel, des Inspectors, beider Sprachen und einer echten Decodierung. |
| `Tests/QrImage.cs` | Zeichnet Codes für diese Decodierung in ein Bild im Kameraformat. |
| `tools/Build-QrScanner-Windows.ps1` | Testen, bauen, signieren. |
| `tools/New-QrScannerIcon.ps1` | Erzeugt das Icon, das selbst ein scannbarer QR-Code ist. |
