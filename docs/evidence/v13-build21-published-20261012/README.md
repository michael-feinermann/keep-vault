# Build 21: veröffentlichte macOS-Vorabversion

Diese Sammlung belegt die tatsächliche Veröffentlichung [v5.0.3-rc.build21](https://github.com/michael-feinermann/keep-vault/releases/tag/v5.0.3-rc.build21) am 12. Oktober 2026. Der kompilierte Quellstand ist `8c68571695ae9072555ffb462b3c0b9c500811ea`. Der [Abschlussbericht](../../PRERELEASE_BUILD21_REPORT.md) beschreibt den Umfang und die offenen Gesamtfreigaben.

| Verzeichnis | Tatsächlicher Nachweis |
|---|---|
| `builder` | Erfolgreicher dritter Builder, vollständige Funktionssuite mit 319 PASS, Originalergebnisse und Quellen-/Harness-/SDK-Bindungen; frühere NU1301-Netzwerkstörung getrennt erhalten |
| `native` | Je 161 echte ABI-Nullpointer-/Breitenfälle auf ARM64 und x86_64/Rosetta; neun exakt finale Produktbibliotheken und eine getrennte, nicht ausgelieferte SHA3-Referenz |
| `local` | Sechs lokale Release-Dateien, Apple-, Hybrid-, Ticket- und Gatekeeper-Prüfungen |
| `draft` | Frische authentifizierte Downloads des neuen Build-21-Drafts vor Veröffentlichung |
| `public` | Frische authentifizierte und anonyme Downloads aller sechs öffentlich veröffentlichten Dateien einschließlich beider unveränderter Kit-Bäume |
| `installed` | Installierte aktuelle Main-/Scanner-Bundles, byte- und namespacegleich zum Distribution-Kit; Apple-/Ticket-/Gatekeeper-Prüfung und geschützter ZPAQ-Anker |
| `administration` | Tatsächliche GitHub-Operationen, eingefrorene öffentliche Asset-Parameter, unveränderte ältere Releases sowie archivierte Prüfwerkzeuge und deren Selbstprüfungen |

`copy-binding.json` bindet jede kopierte Originaldatei an ihren Herkunftspfad, ihre Länge und SHA-256. Die Unterpakete mit `collection.json` enthalten ausschließlich die darin aufgeführten öffentlichen Belege sowie ihre Sammlung und Hashliste. Produkt-ZIPs, extrahierte App-Binaries, SDK-Binaries und private Schlüssel beziehungsweise Passwörter sind nicht Bestandteil dieser Sammlung. Archivierte Werkzeuge mit `.py.txt` sind Quelltext, keine im Repository neu aktivierten Programme. `SHA256SUMS` deckt alle Dateien dieses öffentlichen Pakets außer der Hashliste selbst ab.

Die Managed-Funktionsassembly ist kein Native-AOT-Produkt. Der Builder bindet sie und die getrennt erzeugten Universal-/AOT-Dateien an denselben kompilierten Quellstand. Ein Quellpfad mit dem bestehenden `text eol=crlf`-Vertrag wird explizit als LF-Gitblob und CRLF-Checkout gebunden; pauschale Bytegleichheit aller Checkoutdateien wird nicht behauptet.

Der reguläre CLI-Installationsvertrag installiert Main und Scanner benutzereigen (UID 501); die Bundles sind Modus 0700 und ihre Einträge nicht gruppen- oder fremdschreibbar. Der root-eigene ZPAQ-Anker ist Modus 0555, sein root-eigener Elternpfad Modus 0755; die sechs Ankerdateien sind nur lesbar und stimmen mit dem Kit überein. Die anfänglichen Prüfskriptfehler wegen einer falschen Feldannahme beziehungsweise fälschlich erwarteter root-eigener App-Bundles bleiben im installierten Ergebnis als Prüfwerkzeugfehler dokumentiert. Es wurde dadurch kein Produktfehler als PASS umgedeutet.

Der frühe native Wrapper wurde bereits vor jedem ABI-Start wegen eines zu offenen Evidenzelternverzeichnisses abgewiesen. Die folgende Korrektur 0755 auf 0700 betrifft ausschließlich dieses Verzeichnis; Originale und Klassifikation bleiben separat erhalten. Keine Prozess-ID wird für einen nicht erfassten Prozess erfunden.

Umfang: vorläufige macOS-Veröffentlichung. Der volle 49-Phasen-Releaseblock, abschließende lange vergleichbare 1-GiB-Messläufe und verbleibende reale installierte Bediengates sind offen. Windows, reale Mehr-TiB-Läufe und ein externer Sicherheitsaudit wurden nicht durchgeführt. `overallReleaseApproval` bleibt false. Version 5.0.2 bleibt Latest; der ältere Build-20-Draft und PR 3 als Draft bleiben bestehen.
