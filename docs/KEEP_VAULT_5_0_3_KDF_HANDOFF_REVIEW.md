# Keep Vault 5.0.3, Build 21: KDF- und Schlüsselübergaben

Stand: 12. Oktober 2026. Der Benutzer hat die Veröffentlichung auf eine vorläufige macOS-Version beschränkt und die Langläufe und vergleichbaren Geschwindigkeitsmessungen verschoben. Diese Prüfung erteilt keine Gesamtfreigabe.

## Gefundene Fehler und Änderung

Ein Besitzer gesperrter Schlüsselbytes konnte nach einem fehlgeschlagenen ersten Cleanup erneut seine bereits gelöschten Bytes herausgeben. Eine tatsächliche Vorher-/Nachher-Probe reproduziert dieses Verhalten mit der früheren Produktassembly. Der neue Besitzer sperrt den Getter ab Beginn der Entsorgung. Die zur echten Cleanup-Wiederholung notwendigen Ressourcen bleiben erhalten. Bereits ausgegebene Arrayreferenzen lassen sich durch .NET nicht zurückrufen; ihr Inhalt wird gelöscht.

An einigen verwalteten Native-Einstiegspunkten fehlten ausdrückliche Nullprüfungen vor Längenprüfung oder Übergabe. Diese Eingänge weisen fehlende Arrays jetzt vor dem nativen Aufruf ab. Die zweite Master-KDF-Runde verlangt ihren vollständigen 128-Byte-Vorgänger; die erste Runde behält ihren zulässigen optionalen leeren Zusatzinput.

Der gemeinsame interne Übergabevertrag prüft Breite und drei ausdrücklich benannte Fehlerbilder: ausschließlich `00`, ausschließlich `01` und ausschließlich `FF`. Die Prüfung läuft über den vollständigen Puffer. Bei einer fehlgeschlagenen Übergabe wird der betroffene Puffer gelöscht und kein Ergebnis ausgegeben. Sie umfasst die Master-KDF, Rollen-/Stufenableitung und Besitzerübergabe sowie die Kopien und Verbraucher der Cipher-, MAC- und Recovery-Pfade. Eine fehlerhafte AEAD-Nonce-Allokation räumt auch den bereits angelegten Schlüssel auf.

Diese Prüfung betrifft abgeleitetes Anwendungsschlüsselmaterial. Die Cipher-Primitiven dürfen weiterhin legitime konstante Testschlüssel verwenden; hierfür bestehen unabhängige Positivprüfungen. Nonces, Zähler, Tweaks und Nutzdaten erhalten kein pauschales Konstantenverbot. Eine Hexeingabe mit vielen Nullen ist kein Nullpointer. Die Wächter erkennen die genannten Sentinelwerte und fehlende/beschädigte Breiten, keine beliebige Speicherbeschädigung, und stellen keinen Entropiebeweis dar.

## Tatsächlich ausgeführte gezielte Prüfungen

Das [öffentliche Belegpaket](evidence/v13-build21-kdf-handoff-20261012/README.md) bindet die einzelnen Läufe an Produkt-/Testassembly, native Bibliotheken und die beobachteten Exitcodes.

| Prüfung | Ergebnis und Umfang |
|---|---|
| KDF-/Rollen-/Besitzer-Fehlermatrix | PASS: zwölf Suites, 626 benannte Grenzen, vier Fehler je Grenze, insgesamt 2.504 Fälle |
| Cipher-Verbraucher | PASS: 336 injizierte Fehler, kein fertiggestelltes Ergebnis |
| MAC-Verbraucher | PASS: 80 Fehler, seriell und mit zwei tatsächlich zugelassenen Workern |
| Recovery-Ableitung und tatsächliche Zertifizierungs-MACs | PASS: 24 Fehler an sechs Grenzen |
| Caller-Output-Cleanup | PASS: 48 zusätzliche Fälle |
| Nativer Nullpointer-/Breitenvertrag | PASS: je 161 Fälle auf ARM64 und x86_64 unter Rosetta |
| Besitzer-Lebenszyklus | Alter Fehler reproduziert; neuer Getter verweigert den Zugriff, echter Cleanup kann wiederholt werden und bleibt idempotent |
| Neue gezielte Gruppen | 17 PASS, darunter vier Prüfungen des isolierten GUI-Audit-Modus |

Die KDF-Fehlermatrix nutzt intern begrenzte 8-MiB-Testparameter, um jeden Fehler gezielt auszulösen. Produktive KDF-Kosten, Formatparameter und bestehende Referenzwerte werden nicht reduziert. Die reguläre vollständige Testsuite des neuen Release-Builds ist ein eigener Nachweis. Die Native-Prüfung verwendet echte Nullpointer, ohne ungültige Nichtnulladressen oder absichtlichen Use-after-free. Die neun ausgelieferten Bibliotheken sind separat an die Produktdateien gebunden; die zehnte SHA3-Referenzbibliothek dient ausschließlich dem Test und wird nicht ausgeliefert.

Die [fehlgeschlagene zweite Managed-Kampagne](evidence/v13-build21-kdf-handoff-staging-failure-20261012/README.md) bleibt erhalten: Ein erneuter Testbuild hatte die signierten Testkopien durch unsignierte Native-Kopien ersetzt, und die Integritätsprüfung verweigerte diese korrekt. Nach erneutem Staging der unveränderten signierten Dateien besteht die dritte Kampagne. Der erste gestagte Intel-ABI-Lauf bleibt ebenfalls FAIL, weil die zusätzliche, nicht ausgelieferte SHA3-Testreferenz nur ARM64 enthielt. Der korrigierte Lauf verwendet für diese Testreferenz ausdrücklich ihren x86_64-Build; die neun Produktbibliotheken bleiben bytegleich.

## Veröffentlichung und offene Gesamtfreigabe

Der [erste vollständige signierte Build-21-Durchgang](evidence/v13-build21-complete-suite-failure-20261012/README.md) besteht 317 von 319 Gruppen und endet mit Exit 1. Seine zwei Fehler sind die veraltete Before-Unlock-Fixture und die `.csproj`-Archivverpackung. Die Korrektur erhält den geschlossenen Getter und die strenge Projektprüfung; die öffentliche Probe bleibt bytegleich reproduzierbar. Die Unlock-Fehler-Fixtures verwenden beim Cleanup-Retry wieder den echten macOS-Systemaufruf und versuchen alle Bereinigungen auch nach einem Cleanup-Fehler. Beide [gezielten Korrekturprüfungen](evidence/v13-build21-fixture-corrections-20261012/README.md) bestehen danach mit dem regulären sicheren Testrunner und Exit 0. Dieser fehlgeschlagene erste vollständige Durchgang wird nicht nachträglich freigegeben. Der neue dritte vollständige Builder besteht danach separat mit 319 PASS, 0 FAIL und 0 BLOCKED; der zwischenzeitliche zweite Builder scheitert vor der Suite an NU1301/DNS. Die [Originale und der neue Abschluss](evidence/v13-build21-published-20261012/README.md) bleiben getrennt gebunden.

Build 21 ist separat als [v5.0.3-rc.build21](https://github.com/michael-feinermann/keep-vault/releases/tag/v5.0.3-rc.build21) veröffentlicht, kompiliert aus `8c68571695ae9072555ffb462b3c0b9c500811ea`. Der [Abschlussbericht](PRERELEASE_BUILD21_REPORT.md) belegt auch die frischen Prüfungen beider öffentlich heruntergeladenen Kits, die finale native ABI-Prüfung und den tatsächlichen installierten Vertrag. `--prerelease` verlangt Developer ID, Notarisierung sowie die regulären Native-, Kryptografie-, Sicherheits- und Funktionsprüfungen. Es ist mit `--release` unvereinbar und ersetzt den offiziellen Ausgabeordner nicht. Der komplette normative `--release`-Block mit seinen 49 Phasen, der historischen Baseline und den Leistungsgrenzen bleibt unverändert.

Noch offen sind insbesondere die final gebundenen Langläufe, wiederholte vergleichbare Geschwindigkeitsmessungen am Netzteil, verbleibende reale GUI-Abnahmen und die anschließende Gesamtfreigabe. Historische Build-20- oder Entwicklungsbelege werden nicht in aktuelle Build-21-Belege umbenannt. Windows und reale Mehr-TiB-Läufe bleiben außerhalb dieses macOS-Durchgangs.
