# Keep Vault 5.0.3: Faktorimport nach Revision 12

Stand: 3. Oktober 2026. Der isolierte verwaltete Entwicklungsbuild `build-20261003T095905Z` wurde erfolgreich erstellt. Sieben strenge Faktor-GUI-Gruppen wurden anschließend einzeln ausgeführt und haben bestanden. Die Tests verwenden die echte Avalonia-Fenster-/Editorintegration mit dem Headless-Backend auf macOS arm64 sowie die unveränderten signierten nativen Bibliotheken des installierten Build 15. Das ist Entwicklungsnachweis, keine Freigabe eines neu signierten oder installierten Produkts. Die abschließende reale macOS-Bedienprüfung bleibt erforderlich. Windows wurde nur im Quellcode berücksichtigt.

## Gemeinsamer Vertrag

`KalynaArchiver/Services/FactorInput.cs` ist der gemeinsame Adapter für die zwei Faktoren. Er verlangt bei einer fachlichen Aktion genau 256 ASCII-Hexadezimalzeichen und decodiert sie in 128 Byte. Die technische Rohtextgrenze beträgt 65.536 UTF-16-Codeeinheiten. Eine Eingabe oberhalb der Grenze wird vollständig abgelehnt. Der Adapter schreibt erst nach der vollständigen Validierung in den bestehenden Zielpuffer.

Zugelassen ist das explizit festgeschriebene `char.IsWhiteSpace`-Set der gepinnten .NET-Laufzeit: U+0009 bis U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000 bis U+200A, U+2028, U+2029, U+202F, U+205F und U+3000. Der Test vergleicht alle 65.536 `char`-Werte mit diesem Set und mit der Laufzeit. U+200B, U+FEFF, NUL, Surrogates, Feldlabels sowie Unicode- oder OCR-Ersatzzeichen werden nicht entfernt oder ersetzt.

`PasswordKeyService.NormalizeGeneratedPassword` und beide `ContainerKeyDerivation.ParseFactor`-Überladungen verwenden diesen Vertrag. Der Kernpfad validiert vor der Allokation des gesperrten 128-Byte-Puffers und löscht/freigibt ihn weiterhin bei einem Fehler. Der bisherige Faktor-A/B-Bezug, die KDF-Transcripts, Cipher-/Nonce-/MAC-Verträge sowie Passwort- und PIN-Encoding bleiben unverändert.

## Eingabeoberflächen

Die beiden macOS-Importfelder verwenden `KeepVaultMac.Controls.FactorTextBox`. Die WPF-Felder verwenden `KalynaArchiver.Controls.FactorTextBox`. Nur diese Importfelder verwenden den neuen Faktoradapter. Passwort und PIN behalten ihre bisherigen Controls und Regeln.

Die Controls prüfen die vollständige Ersetzung einschließlich aktueller Selection vor der Übernahme. Sie nehmen unvollständiges manuelles Tippen an und zeigen einen nicht modalen Zähler. Ein vollständiger Faktor mit Leerraum zwischen Bytepaaren hat 383 Rohzeichen, mit Leerraum zwischen allen Hexzeichen 511 Rohzeichen. Beide werden vollständig übernommen. Bei einer überlangen oder verbotenen Einfügung bleiben der bisherige Text und die Selection erhalten. `MaxLength` wird intern auf 0 gebunden, damit das Framework keine gültigen Präfixe durch Abschneiden erzeugt. Die echte Clipboard-Paste-Ausführung wird vor dem frameworkinternen Sanitize-/Insert-Pfad übernommen. Label/HelpText/Name und die explizite Monospace-Schrift werden an den tatsächlich fokussierten privaten Editor weitergereicht. Es gibt keine globale Clipboardüberwachung und keine zusätzliche gespeicherte Geheimnishistorie.

Unter Avalonia ist der öffentliche Faktorcontrol eine kleine `UserControl`-Komposition mit privatem TextBox-Editor. Damit steht der sanitisierende `TextBox.SelectedText`-Basisklassenpfad am öffentlichen Faktorobjekt nicht mehr zur Verfügung. `Text`, Binding und `SelectedText` prüfen den vollständigen Rohwert vor jeder Editoränderung; der private Editor prüft zusätzlich seine Textproperty und tatsächlichen TextInput. Akzeptierte Änderungen benutzen weiterhin die vorhandene Undo-Verwaltung des Frameworks. Für Faktoren delegiert ein kleiner IME-Client Geometrie, Selection, Kontextaktionen und Commit, akzeptiert aber keine Inline-Preeditmutation am Faktorentwurf. Dadurch löscht der Framework-Preeditpfad ausgewählte Faktorzeichen nicht vor der abschließenden Rohtextprüfung. Es werden weder Preeditstrings noch frühere Faktorstrings im Adapter gespeichert; Passwort und PIN behalten ihren bisherigen IME-Client. Ein eventuell geposteter Presenter-Abgleich schreibt keine gespeicherten Cursor/Selection zurück und verfällt nach einer neueren Text-, Cursor- oder Selectionrevision. Ein abgelehnter Clipboardtransfer nach einer zwischenzeitlichen Text-/Selectionänderung ersetzt nicht den neueren Entwurf. Der Inputadapter speichert keine eigene Kopie vorheriger Faktorstrings. OS- und Frameworktransfers können vorübergehende Kopien anlegen; die Änderung behauptet keine Kontrolle über diese Speicherbereiche.

Die macOS-Faktorfelder verwenden nun `NoWrap` und native horizontale sowie vertikale Scrollleisten. `MaxLines=6` begrenzt ausschließlich die sichtbare Editorhöhe; die vollständigen bis zu 65.536 Rohzeichen bleiben erhalten. Dies behebt den tatsächlich reproduzierten Layoutstillstand bei maximalem Formatierungsleerraum mit anschließendem Ersetzen der Selection. Der Test der Produktkonfiguration und der tatsächliche Headless-TextInput-/Layouttest der maximalen Rohgröße wurden mit dieser Darstellung bestanden. Es wurde weder die Nutzlänge verkürzt noch eine kleinere Rohtextgrenze eingeführt.

`ClearSensitiveText` erhöht die Bearbeitungsrevision auch bei bereits leerem Text und setzt die bestehende native Undo-/Redo-Historie zurück. `ClearExtractSecrets` ruft diese Methode für beide Faktorcontrols auf. Die tatsächliche Aktion „Geheimwerte leeren“ ist mit befüllten und bereits leeren Feldern geprüft: Undo und Redo stellen die Faktoren nicht wieder her. Ein vor dem Leeren gestarteter, erst danach vollständig gelieferter Clipboardtransfer wird als veraltet abgelehnt. Es wird keine zusätzliche Geheimnishistorie angelegt.

Die Meldungen enthalten keine Faktorwerte oder Exceptiontexte. DE/EN-Wechsel übersetzt den Status, ohne das Textfeld umzuschreiben. Die Hilfetexte und Bindungen werden im gemeinsamen GUI-Änderungsumfang gepflegt.

## Geprüfte Pfade und Scanner

Die normalen Decryption-/Streamproducerpfade sowie die Recovery-Authentisierung führen über `ContainerKeyDerivation.DeriveMaster` und den gemeinsamen Parser. GUI-Vorvalidierung, Schlüsselzettel-/QR-Erstellung und Entropie-Faktorvergleich führen über denselben Parser beziehungsweise die gemeinsame Kanonisierung. Eine normalisierte Rückgabe wird nicht als Ersatz für einen abweichenden späteren Rohtextparser behandelt.

Die separaten macOS- und Windows-QR-Scanner sind allgemeine Scanner. Ihre Payload-Inspektoren behalten den vollständigen akzeptierten Originaltext für das Kopieren bei; sie führen keine Faktor-Normalisierung aus. Es existiert kein zusätzlicher Scanner-zu-KDF-Direktkanal. Die Übergabe erfolgt über die Zwischenablage und damit über das gemeinsame Faktorimportfeld. Die Scanner-Payload-Verträge und QR-Payloadbytes wurden nicht geändert.

## Regressionstests und aktueller Nachweis

| Gruppe | Inhalt |
|---|---|
| `factor.rev12-whitespace` | Gesamtes festes WhiteSpace-Set gegen Laufzeit; beide Faktoren und identische gesperrte Faktorbytes. |
| `factor.rev12-boundaries` | 255/256/257 Nutzzeichen, 65.535/65.536/65.537 Rohzeichen, keine partiellen Decode-Ausgaben, keine Faktorallokation bei ungültiger Eingabe. |
| `factor.rev12-invalid` | OCR-/Unicode-Zeichen, Zero-width/BOM/NUL, Labels, Surrogates und vertrauliche Fehlermeldungen. |
| `factor.rev12-password-pin` | Gleiche SHA3-/Skein-Credentialhashes für formatierte Faktoren; unveränderte Passwort-Leerzeichen und führende PIN-Nullen mit positiven Gegenproben. |
| `factor.rev12-allpaths` | Öffentliche 4-KiB-Standard-/Paranoiafixtures: Entschlüsselung, tatsächliche KPAR2-Beschädigung/Reparatur und A-/B-/gemeinsame Wiederholung mit formatierten Faktoren. Die bestehende testinterne Argon2-Speicherseam ist auf den Testscope begrenzt, t=4 und p=4 bleiben erhalten. |
| `gui.factor-rev12-paste` | Tatsächliches Headless-Clipboard-Paste-Ereignis für 256/383/511 Zeichen, beide echten Fensterfelder. |
| `gui.factor-rev12-atomic` | Vollständige Textproperty-/Insert-/Drop-Ablehnung, Selection und TextPresenter, maximale erlaubte Rohtextgröße, lokalisierter Status. |
| `gui.factor-rev12-edit-undo` | Tatsächlicher TextInput, partielles Tippen, Selection-Ersetzung, Undo/Redo sowie ungültige IME-Commits und delegierte Preedit-/Abbruchereignisse. |
| `gui.factor-rev12-editor-drop` | Drop auf dem privaten Editor als wirklichem Ziel: 383/511 Zeichen und CR/LF vollständig übernommen; DEL, 65.537 Rohzeichen und 257 Hexzeichen ohne Commit, Selection- oder Historyverlust abgelehnt. |
| `gui.factor-rev12-layout-spaces` | Beide echten Felder übernehmen und präsentieren 65.536 öffentliche Rohzeichen über TextInput ohne Kürzung; native horizontale Scrollbarkeit und sichtbare Höhenbegrenzung. |
| `gui.factor-rev12-clear-undo` | Tatsächliches explizites Leeren mit gefüllten sowie bereits leeren Feldern; Undo/Redo dürfen weder Faktoren noch Passwort/PIN wiederherstellen. |
| `gui.factor-rev12-clear-pending-paste` | Echte verzögerte Clipboardlieferung nach explizitem Leeren auch eines schon leeren Feldes wird abgelehnt und gelangt nicht in Undo/Redo. |

Die fünf Kerntests werden auch im Windows-Testprojekt registriert. Sie haben auf macOS im früheren isolierten Entwicklungsbuild `build-20261003T090204Z` bestanden; der gemeinsame Faktorparser, beide Services und die Kerntestdatei sind anhand ihrer SHA-256 gegenüber dem hier geprüften Build unverändert. Dieser frühere Lauf ersetzt keine erneute Gesamtprüfung des abschließenden Produkts. Die initialen vier Launcher-Kollisionen sind als nicht ausgeführte Versuche erhalten; die erfolgreichen Wiederholungen besitzen eigene eindeutige Ergebnisverzeichnisse.

Die sieben aktuellen Avalonia-GUI-Tests ergänzen die reale Prüfung und ersetzen sie nicht. Reales macOS-Clipboard-Paste/Drop, die tatsächliche native IME, Accessibility, Fokus/Selection und eine neu installierte signierte Anwendung bleiben `NOT RUN`. Für Windows bleibt die tatsächliche Ausführung außerhalb des ausdrücklich auf macOS begrenzten Durchgangs offen.

## Sieben ausgeführte Faktor-GUI-Gruppen

Die Kampagne `work/v13-evidence/rev12-development-20261003/campaign-20261003T100545Z-032583bf.json` lief am 3. Oktober 2026 von 10:05:45 bis 10:05:50 UTC. Jede der folgenden Gruppen besitzt einen eigenen Koordinatorlauf mit genau einer Gruppe, Exitcode 0 und ein anhand seines Ausführungsbelegs geprüftes Ergebnis. Der achte Kampagnenlauf `gui.rev12-console-text` ist fehlgeschlagen und gehört nicht zu diesem Faktor-PASS.

| Gruppe | Ergebnis | Gruppenzeit in s | Spitzen-RSS in MiB | Eigenes Ergebnisverzeichnis unter `build-20261003T095905Z` |
|---|---|---:|---:|---|
| `gui.factor-rev12-clear-undo` | PASS | 0.772 | 123 | `run-20261003T100545Z-edfca64c` |
| `gui.factor-rev12-clear-pending-paste` | PASS | 0.393 | 121 | `run-20261003T100546Z-6f8c8874` |
| `gui.factor-rev12-editor-drop` | PASS | 0.442 | 123 | `run-20261003T100547Z-f672ae6a` |
| `gui.factor-rev12-paste` | PASS | 0.442 | 122 | `run-20261003T100547Z-ef6cff20` |
| `gui.factor-rev12-atomic` | PASS | 0.780 | 156 | `run-20261003T100548Z-c64d1101` |
| `gui.factor-rev12-layout-spaces` | PASS | 0.446 | 132 | `run-20261003T100549Z-6e799666` |
| `gui.factor-rev12-edit-undo` | PASS | 0.408 | 122 | `run-20261003T100550Z-3cb753e2` |

Gruppenzeit und RSS umfassen den Testprozess und die öffentliche GUI-Fixture. Sie sind keine KDF-, Archivierungs- oder nativen IME-Geschwindigkeiten.

Kampagnen-SHA-256: `5f8745c7b1ad6e23a1b785259a8d08466a6bb442dae87908cbf2b5682f948794`. Das vollständige Build-Quellinventar ist vor und nach dem Build identisch, SHA-256 `a870ede85b38ac81a77bffe83de23feeba1543a5b748805316f94f1399e0e770`. Alle sieben Ausführungsbelege beziehen sich auf dieses Inventar; Ergebnis- und Loghashes wurden unabhängig geprüft. Der Git-HEAD `b41144e191d743aa4474cb3a9fe1e5c1c7c567ba` allein beschreibt wegen der uncommitteten Änderungen nicht den getesteten Stand.

## Unabhängiger Quellreview und zusätzliche Fensterbereinigung

Der read-only Review hat Abschnitt 9.8 der Revision 12 gegen den gemeinsamen Parser, das macOS-Control, die tatsächliche Credentialintegration, Recovery/Wiederholung, die unveränderten Passwort-/PIN-Encodingpfade und die zugehörigen Tests geprüft. Die Vorvalidierung ignoriert ihre kanonische Rückgabe teilweise; der spätere Kernparser interpretiert denselben vollständigen Rohtext jedoch nach genau demselben gemeinsamen Vertrag. Ein abweichender Zweitparser oder ein Scanner-zu-KDF-Direktkanal wurde dabei nicht gefunden. Die IME-Komposition gilt ausschließlich für Faktoren; Passwort/PIN bleiben normale maskierte TextBox-Felder mit ihren bisherigen Regeln.

Das Control speichert keine frühere Faktorkopie. Ein anstehender Paste prüft nach dem `await` seine Bearbeitungsrevision; Text-, Caret-, Selectionänderungen und explizites Leeren machen ihn ungültig. `TryReplaceSelection` prüft vor einer verspäteten Übernahme zusätzlich ReadOnly und effektive Freigabe. Der Adapter besitzt derzeit selbst keine terminale Disposed-Markierung. Der Schutz beim Fensterende hängt deshalb an der Ausführung von `ClearExtractSecrets`. Im damaligen Stand des Builds `095905` konnte eine Ausnahme in einem früheren `Dispose`-Schritt, insbesondere Entropie-/Create-Cleanup, die danach folgenden Faktor-Clears und das Abschalten der Controls überspringen. Der zusätzliche quellenstabile Build `build-20261003T102259Z` korrigiert diese allgemeine Fensterbereinigung: terminale Controls und Faktorinvalidierung zuerst, danach unabhängige Versuche sämtlicher eigener Bereinigungsschritte mit erhaltener Fehlerursache. Die tatsächlichen Gruppen `gui.rev12-dispose-failure` und `gui.rev12-dispose-storage-ownership` sind bestanden. Die erste umfasst eine echte ausstehende Clipboardübernahme sowie Undo nach ausgelösten Bereinigungsfehlern; die zweite prüft eigene Dateizugriffe, unabhängige Freigabe, Reentranz und kontrollierten Retry. Ergebnisdateien: `work/v13-evidence/rev12-development-20261003/build-20261003T102259Z/run-20261003T102400Z-e498b2e9/test-results.json` und `run-20261003T102401Z-ea3e49da/test-results.json`. Dies sind ergänzende Headless-Nachweise; reale installierte GUI/IME bleibt offen.

Für die nativen Passwort-/PIN-Felder behandelt das gepinnte Avalonia `Text=string.Empty` als externe Ersetzung: `CoerceText` leert die vorhandene Undo-/Redo-Historie, danach wird der neue Leerwert erfasst. `PasswordChar` allein deaktiviert Undo nicht. Der tatsächliche Extract-Clearbutton ist im bestandenen `gui.factor-rev12-clear-undo` mit gefüllten und schon leeren Passwort-/PIN-Feldern plus anschließenden Undo-/Redo-Leerassertionen ausgeführt. `ClearCreateSecrets` verwendet dieselbe direkte native Textzuweisung; seine Wirkung wurde hier zusätzlich im Quellcode geprüft, durch diese neue Testgruppe jedoch nicht ausgeführt. [Avalonia 12.1.1, CoerceText](https://github.com/AvaloniaUI/Avalonia/blob/12.1.1/src/Avalonia.Controls/TextBox.cs#L578-L600).

Die folgenden Hashes identifizieren die tatsächlich geprüften Dateien des ursprünglichen Faktor-Entwicklungsbuilds `095905`. Die spätere Fensterbereinigung hat eine eigene Bindung an die vollständige Buildinventur von `102259` und die beiden oben genannten echten Regressionen; der alte MainWindow-Hash wird hier als historische Faktortest-Provenienz erhalten.

| Quelldatei | SHA-256 |
|---|---|
| `KalynaArchiver/Services/FactorInput.cs` | `1e4d04e8cf348830bb15e6cbcd4482896abe39ded02d9ef5bfb0cb5b0d6be9e4` |
| `KalynaArchiver/Services/ContainerKeyDerivation.cs` | `fe787a868ac0e78d0ed3306ec6be9e0d59ce3f6fdcd9d63b70dd76f61bff44de` |
| `KalynaArchiver/Services/PasswordKeyService.cs` | `e17c544511780036a1c459628bb7467dfcb607177344138345d1f67de8a0ff9d` |
| `KeepVaultMac/Controls/FactorTextBox.cs` | `fd8252e83c32ffede2f1f2b07faf5b2823429b94ac5ac9c35a43bd204c98e9f8` |
| `KeepVaultMac/MainWindow.axaml` | `5aede9c1b4c609d8e7f583b48954af4ab1c067d676fc833578bd576207656cd5` |
| `KeepVaultMac/MainWindow.axaml.cs` | `7ba0767711cf7d7c99868ed0ac9d6b3ac80cfcf1c9c69dba8eb4f1bdc9a6ce29` |
| `KeepVaultMac.Tests/FactorInputRev12Tests.cs` | `7b36c7963411a11ddedb51b8e70f0a2bf599d1e5ff83d140fab52202b7fee417` |
| `KeepVaultMac.Tests/FactorInputRev12GuiTests.cs` | `487e30dda7fa77c222e11b642b991cb2dcc94e18ec9f9a4a09f6c2e56fe9a9c5` |
| `KeepVaultMac.Tests/FactorEditorDropRev12Tests.cs` | `cdb412cabf26682ef461539c56063b72300ece6710d15e2aa29eb1e3e58336cb` |

## Primärquellen

Die Eingabeseams wurden am gepinnten Frameworkquellstand geprüft: [Avalonia 12.1.1 TextBox](https://github.com/AvaloniaUI/Avalonia/blob/12.1.1/src/Avalonia.Controls/TextBox.cs), [DragDrop-Ereignisse](https://github.com/AvaloniaUI/Avalonia/blob/12.1.1/src/Avalonia.Base/Input/DragDrop.cs) und [DataTransfer](https://github.com/AvaloniaUI/Avalonia/blob/12.1.1/src/Avalonia.Base/Input/DataTransfer.cs). Maßgeblich für den fachlichen Auftrag sind die lokalen Abschnitte 9.8 und 8.12 der Revision 12; dieses Dokument ergänzt die Implementierungsnachweise.
