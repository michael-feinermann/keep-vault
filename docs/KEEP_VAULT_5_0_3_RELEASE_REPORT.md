# Keep Vault 5.0.3: Release und Installation

Status am 29.09.2026: Der Kandidat aus `253b5fa` wurde bei Apple akzeptiert, gestapelt und regulär als 5.0.3/Build 14 installiert. Seine vollständige Testsuite fand zwei Fehler. Er ist deshalb nicht freigegeben oder veröffentlicht; nach den Korrekturen ist ein neuer vollständiger Kandidatenlauf erforderlich.

Ziel: Produkt 5.0.3, Build 14, ausschließlich Containerformat 13. Ausgangsinstallation: `/Applications/Keep Vault.app`, Produkt 5.0.2, Build 13. Die historische Veröffentlichung `v5.0.2` bleibt unverändert.

Der Benutzer hat diesen Durchgang ausdrücklich auf macOS und reale Testgrößen bis 256 MiB je Lauf beschränkt. Der zusätzlich ausdrücklich beauftragte Paranoia-Strukturtest verwendet als einzige Ausnahme einen 256-MiB-Baum plus eine weitere 256-MiB-Datei. Windows ist auf ausdrücklichen Benutzerwunsch kein Gate dieses macOS-Durchgangs; seine Binärdateien werden nicht als geprüft angeboten. Das ist keine Behauptung von Mehr-TB-Testnachweisen.

Neue externe Releaseidentität erzeugt und als öffentliche Pins eingebunden. Private Dateien ausschließlich im VeraCrypt-geschützten APFS-Schlüsselspeicher. Prüfstatus für Signatur, Notarisierung, Stapling, Paketinventar, Downloadabgleich und lokale GUI wird mit tatsächlichen Belegen ergänzt.

Vor einem Installationsabschluss muss ausdrücklich auf die Inkompatibilität hingewiesen werden: 5.0.3 öffnet keine vorhandenen v12-Archive. Benutzerarchive, KPAR2-Dateien, Schlüsselblätter und alte private Schlüssel bleiben erhalten.

Kein Tag `v5.0.3`, keine fertigen Assets, keine Installationsbehauptung ohne entsprechenden Nachweis. Commit und Push eines geprüften Arbeitsstands sind von Release und Installation getrennt.

## Erster universeller Releasebuild, 28.09.2026

Quellcommit `a2ab34d0706b220664bdc36085b3eafa403655c3` wurde auf dem dedizierten Arbeitsbranch gepusht und remote bestätigt. Native-Neubau beider Architekturen blieb bytegleich zum versionierten Bestand; AOT-App und Hybrid-/Apple-Signierung liefen. Der Build stoppte anschließend im bisherigen Scanner-Skript bei `lipo <file> -verify_arch arm64 x86_64`: Xcode 27 meldet dabei mehr als eine Eingabedatei. Beide getrennten Architekturprüfungen derselben universellen Datei bestehen. Das Skript prüft nun jede verlangte Architektur einzeln. Dieser Versuch installierte und veröffentlichte nichts; er ist kein bestandener Paketlauf. Rohlog: `work/v13-evidence/rev9-release-a2ab34d.log`, Reproduktion: `rev9-lipo-architecture-regression.log`.

## Zweiter Build und Fortsetzung am 29.09.2026

Der zweite Versuch basiert auf `837e36cf1da2c6940c616348edaed4b03ff05bec`. Der Scanner wurde als 5.0.3/Build 14 signiert, von Apple akzeptiert (Submission `19fe07bb-e9a9-425c-95ca-3ef84f1dbd81`), gestapelt und verifiziert. Seine 127 Swift-Checks und alle 19 Python-Prüfungen der Installer-Paketgrenze bestanden. Der universelle Release-Verifier und die Installer-Helfer wurden gebaut und signiert. Anschließend stoppte derselbe inkompatible Mehrfach-Architekturaufruf in `Build-InstallerKit-macOS.zsh`. Auch dieser prüft jetzt jede geforderte Architektur getrennt. Die lokale Regression akzeptiert beide vorhandenen Slices und verwirft einen tatsächlich fehlenden Slice. Alle aktiven Shell-/zsh-Aufrufe wurden daraufhin abgeglichen. Rohlog: `work/v13-evidence/rev9-release-837e36c.log`.

Am 29.09. war der externe Schlüsselspeicher erneut nicht verbunden: weder `/Volumes/NO NAME` noch `/Volumes/Keep Vault Keys 5.0.3 Secure` waren vorhanden; auch die Liste externer Datenträger zeigte kein entsprechendes Gerät. Ohne diesen Speicher wird kein Ersatzschlüssel erzeugt und keine schwächere Signierung verwendet. Ein korrigierter vollständiger Releasebuild, Gesamtpaket-Notarisierung, installierter v13-Anker, finale Tests, reale GUI und Veröffentlichung sind weiterhin offen. Die tatsächlich installierte Hauptapp bleibt 5.0.2/Build 13. Die zusätzlichen unabhängig ausführbaren Tests vom 29.09. sind im Testbericht dokumentiert.


## Vorbereiteter Kandidat am 29.09.2026

Quellcommit `253b5fa33f0d93cf87525b6e70ad9d4a9af8c3f8` ist auf dem Arbeitsbranch gepusht. Der dedizierte Releaseworktree bleibt auf diesem Commit. Die sechs generierten Native-Ausgaben für `libkalyna_v13.dylib` und `zpaq` entsprechen dem frischen nativen Neubau; der gesamte vor dem Lauf erfasste Dateibestand blieb während des abschließenden Builds bytegleich. Nativequellen und Compiler stammen aus dem dokumentierten Build, nicht aus einer fremden Ersatzdatei.

Hauptapp, QR-Scanner und Installer wurden als universeller Paketsatz 5.0.3/Build 14 erstellt. Apple-Signaturprüfung aller Architekturen, vollständige RSA-PSS-/ML-DSA-Signaturen einschließlich aller Hashmanifeste, kompilierten Pins und der frisch entpackte Installationsbestand bestanden die Vorbereitung. Das bestätigt keine Apple-Notarisierung des Gesamtpakets. Der Builder endete absichtlich mit Exit 2 am vorhandenen manuellen Wartepunkt ohne Bestätigung, nachdem er Kandidat und drei Xcode-Archive dauerhaft gesichert und deren Kopien abgeglichen hatte.

Das vorbereitete ZIP hat 43.912.282 Byte und SHA-256 `635b29b19a04b3cc83964c6b2de76288afd24abbde674edebe1ab65d64031812`. Die geprüfte Übergabekopie liegt unter `/Users/michael/Downloads/Keep Vault 5.0.3 - macOS Vorbereitung 2026-09-29/Vorbereiteter Kandidat`. Alle 355 Inventareinträge einschließlich Verzeichnisstruktur, Symlinkzielen und Dateihashes stimmen mit dem erhaltenen Original überein. Dieser Hash bezeichnet das Paket vor Stapling, keinen späteren Downloadrelease.

Die Apple-Signieridentität verbleibt wie angeordnet im Apple-Schlüsselbund. Alle privaten RSA-/ML-DSA-/Wrapping-Dateien bleiben im vorhandenen VeraCrypt-geschützten APFS-Speicher; keine neuen Ersatzschlüssel wurden erzeugt. Das APFS-Image ist mit Eigentümerverwaltung eingebunden. Das Profil `Keep Vault v13` war bei der Wiederaufnahme nicht verfügbar. Der Benutzer übernimmt dessen spätere manuelle Bereitstellung beziehungsweise Freigabe.

Der separate Starthelfer `Finish-KeepVault-5.0.3.command` startet anschließend den vollständigen bestehenden Build mit frischer Signierung, Notarisierung und den regulären Installations-/Testgates erneut. Er ist ausdrücklich kein Resume der erhaltenen App-Bytes. Der bestehende Builder besitzt keinen dauerhaften Post-Notarisierungs-Resume-Einstieg; ein erneuter regulärer Build ist deshalb der unveränderte automatisierte Abschlussweg. Die erhaltenen Xcode-Archive sind keine Erlaubnis, Originale durch neu signierte Xcode-Exporte zu ersetzen.

Noch abhängig von diesem Apple-Schritt: gültige Tickets und Stapling aller drei Apps, endgültige Inventare/ZIP-Signaturen, regulärer rootgeschützter v13-ZPAQ-Anker, alle ZPAQ-Archiv- und Struktur-/Reparatur-End-to-End-Gates einschließlich des 512-MiB-Paranoiatests, finale installierte GUI-Abnahme und eine anschließend gesondert geprüfte Veröffentlichung. Die bestehende Installation 5.0.2/Build 13 blieb erhalten.

## Notarisierter, installierter Prüfkandidat vom 29.09.2026

Nach Rückkehr des Benutzers war das Schlüsselbundprofil `Keep Vault v13` lesbar. Der vollständige Build aus `253b5fa33f0d93cf87525b6e70ad9d4a9af8c3f8` lief mit frischer Signierung und dem regulären Installer. Apple akzeptierte den Scanner unter `81901858-3721-4bea-99cf-4f6c2fa0abc7` und das Gesamtpaket unter `44c1f5f8-9c99-4dbf-82af-00500efab3c0`. Stapling, Signaturen, Hybridprüfungen und Gatekeeper bestanden. Der Benutzer autorisierte die Installation lokal. Installierte Hauptapp und Scanner meldeten 5.0.3/Build 14, und der rootgeschützte ZPAQ-Anker stimmt mit den Testdateien dieses Builds überein. Die frühere Aussage zur unveränderten 5.0.2-Installation gilt nur für die vorherige Vorbereitungsphase.

Im anschließenden vollständigen Testlauf scheiterten zunächst zwei Gruppen: `gui.resource-policy` setzte nur das Gesamtdatenlimit und erwartete fälschlich zugleich dasselbe inzwischen unabhängige Einzeldateilimit. Die Testeingabe wird ergänzt, alle Assertions bleiben erhalten. `zpaq.full-matrix` wies ein tatsächlich manipuliertes unverschlüsseltes Archiv zwar vor der Extraktion zurück, meldete im neuen macOS-Adapter aber eine `CryptographicException` mit Passworttext anstelle der bisherigen `InvalidDataException` zur doppelten Manifestprüfung. Der Plain-ZPAQ-Adapter erhält wieder seinen passenden Fehlervertrag; zusätzliche Negativfälle prüfen beide getrennten Hashfehler und ausbleibende Ausgabe. Ein erneuter Build und Gesamtlauf ist deshalb erforderlich.

Rohlog dieses nicht freigegebenen Kandidaten: `work/v13-evidence/finish-5.0.3.2uXZiX4E/build.log`. Der bestandene echte Kamera-/Zwischenablagetest mit einem öffentlichen Testblatt ist separat in `work/v13-evidence/real-camera-253b5fa-20260929/result.json` dokumentiert. Diese Teilnachweise ersetzen keine vollständige Freigabe.

Der ursprüngliche vollständige Lauf endete mit 225 bestandenen und zwei fehlgeschlagenen Gruppen aus insgesamt 227 (Exit 1, 1.157,5 Sekunden). Der ausdrücklich beauftragte 512-MiB-Paranoia-Test bestand in 733,442 Sekunden, einschließlich Beschädigung, KPAR2-Reparatur und vollständigem Struktur-/Hashvergleich. Die Originalresultate sind unverändert unter `work/v13-evidence/final-run-253b5fa-20260929/phase-1/` erhalten.

Nach den Korrekturen wurde ein isolierter verwalteter Release-Testharness mit SDK 10.0.400 gebaut. Alle 68 Native-/Sidecar-/Oracle-Dateien stimmen bytegenau mit der gesicherten finalen Teststage des installierten Kandidaten überein. Alle sieben gezielten Gruppen bestanden: `trust.native-tools`, `io.plain-manifest-rejection`, `io.verified-original`, `io.verified-input-state`, `gui.resource-policy`, `zpaq.full-matrix` und `infra.runner-invariants`. Die ZPAQ-Matrix erreichte jetzt auch ihre nachgelagerten Traversal-, Leerordner-, Staging-, Ressourcen- und Fehlformatfälle. Dies ist der Korrekturstand im verwalteten Testharness, noch kein neuer signierter AOT-Kandidat. Belege: `work/v13-postfix-check-rgngbcfz/evidence/`.
