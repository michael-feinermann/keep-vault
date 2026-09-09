# Keep Vault macOS Release

[Deutsch](README.md) · [English](README.en.md) · [Dokumentationsverzeichnis](../../docs/README.md)

Diese Infrastruktur erzeugt kein unsicheres Ersatz-Release. Ein Build wird nur
veroeffentlicht, wenn alle folgenden Vertrauenskettenglieder vorhanden und
erfolgreich geprueft sind:

1. NativeAOT-Core und alle nativen Werkzeuge sind Universal-Mach-O oder, bei
   einem ausdruecklichen lokalen Build, arm64-Mach-O.
2. Jedes Mach-O ist mit Hardened Runtime und einer Apple-Identitaet des fest
   eingebundenen Teams `2T6K9PGS55` signiert.
3. Die Mach-O-Komponenten werden aus dem Bundle vollstaendig ermittelt und
   besitzen SHA3-512- und Skein-1024-Manifeste. Artefakt und beide Manifeste
   werden jeweils mit RSA-PSS/SHA-512 und ML-DSA-87 signiert.
4. Der kleine Swift-Launcher enthaelt den exakten SHA-256-Pin des hybriden
   RSA-Zertifikats und den ML-DSA-87-Public-Key. Er prueft vor dem ersten
   `exec` die vollstaendige Apple-Bundle-Signatur, den signierten Core-Identifier,
   die SHA-512-Artefaktbindung und beide hybriden Signaturen des Cores.
5. Ein separat Apple-signierter Supervisor wird suspendiert gestartet und vom
   Launcher gegen Team, Identifier und seinen buildgenau eingebetteten CDHash
   geprueft. Der Launcher ersetzt danach seine eigene PID mit
   `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED` durch den Core. Der
   Supervisor prueft den tatsaechlich gemappten Prozess mit Security.framework
   gegen den zuvor eingebetteten Core-CDHash und setzt ihn nur bei exakter
   Uebereinstimmung fort. Ein Pfadtausch zwischen Pruefung und Start kann damit
   keinen ungeprueften Core zur Ausfuehrung bringen.
6. Erst danach wird das gesamte `.app`-Bundle von innen nach aussen versiegelt.
   Das Distributions-ZIP erhaelt zusaetzlich eigene hybride Signaturen.

Damit entsteht kein Selbstreferenz-Zyklus: Der eigentliche Core ist hybrid
signiert. Sein Apple-CDHash wird in den Supervisor eingebettet, dessen Apple-
CDHash wiederum in den Launcher eingebettet wird. Launcher und Supervisor sind
Bestandteil der aeusseren Apple-Signatur.

## Entitlements

Core und Launcher verwenden keine App Sandbox und deklarieren keine
Entitlements. Beide laufen mit Hardened Runtime und aktiver Library Validation.
Dateiauswahl und Druck erfolgen über die regulären macOS-Dialoge. Die leeren
Entitlement-Dateien für Core, Launcher und native Helfer sind im Quellstand
festgelegt. Der separate QR-Scanner besitzt seine eigene Kamera-Sandbox.

Es gibt keine Netzwerk-, Kamera-, Mikrofon-, USB-, Bluetooth-, Apple-Events-,
Debug-, JIT-, Unsigned-Memory- oder Library-Validation-Ausnahme. ZPAQ und das
Argon2-Kommandozeilenwerkzeug erhalten keine zusaetzlichen Sandbox- oder
Inherit-Entitlements. Fuer ZPAQ gelten ausserdem die restriktiven,
operationsspezifischen Seatbelt-Profile und der root-eigene v12-Ausfuehrungsanker.

## Private Release-Schluessel

Private Schluessel duerfen nicht im Repository liegen. Der Build erwartet:

- standardmaessig
  `~/Library/Application Support/Keep Vault/ReleaseKeys/hybrid-rsa4096.pfx`
  als externes RSA-4096-Code-Signing-PFX mit SHA-512-
  Zertifikatssignatur, Digital-Signature-Key-Usage und Code-Signing-EKU,
- standardmaessig
  `~/Library/Application Support/Keep Vault/ReleaseKeys/mldsa87-private.key.v12.enc`
  als rollenspezifischen v12-Umschlag des ML-DSA-87-Private-Keys,
- standardmaessig
  `~/Library/Application Support/Keep Vault/ReleaseKeys/hybrid-rsa4096.pfx.password.v12.enc`
  als davon unabhaengigen v12-Umschlag des PFX-Passworts,
- den zugehoerigen Public Key unter
  `KeepVaultMac/Packaging/Keys/mldsa87-public.key`.

Die Variablen `KEEPVAULT_HYBRID_PFX`,
`KEEPVAULT_MLDSA_PRIVATE_KEY_ENCRYPTED`,
`KEEPVAULT_PFX_PASSWORD_ENCRYPTED` und `KEEPVAULT_MLDSA_PUBLIC_KEY` koennen
diese Pfade fuer eine kontrollierte Releaseumgebung ersetzen. Das PFX und die
beiden voneinander getrennten v12-Umschlaege muessen dem aktuellen Benutzer
gehoeren, duerfen weder Symlinks noch im Repository sein und muessen in einem
privaten Verzeichnis ohne Gruppen- oder Fremdzugriff liegen. Die beiden
Wrapping-Keys bleiben in getrennten, promptpflichtigen Keychain-Eintraegen.
`tools/Protect-HybridKeys-macOS.sh --verify-only` prueft diese Trennung, ohne
Schluessel oder Passwoerter auszulesen.

Alternativ koennen beide Wrapping Keys explizit auf einem geschuetzten lokalen
Datentraeger liegen. Dafuer muessen `KEEPVAULT_MLDSA_WRAPPING_KEY_FILE` und
`KEEPVAULT_PFX_WRAPPING_KEY_FILE` gemeinsam gesetzt werden. Beide Dateien
enthalten je einen kanonischen Base64-Wert fuer 32 Bytes, sind rollensepariert,
single-link und Modus 0600. Ihre Elternverzeichnisse sind privat (0700).
Symlinks, gleiche Schluesselwerte, nicht lokale Volumes und deaktivierte
Eigentuemerpruefung werden abgewiesen. Es gibt keinen stillen Wechsel zwischen
Datei- und Keychain-Zugriff. Die v12-Umschlaege muessen genau zu den gewaehlten
Wrapping Keys passen; vorhandene andere Umschlaege werden nicht ueberschrieben.

`KEEPVAULT_APPLE_KEYCHAIN` waehlt zusaetzlich einen privaten Apple-Schluesselbund
aus, etwa auf demselben verschluesselten USB-Datentraeger. Identitaetssuche und
`codesign --keychain` verwenden dann ausschliesslich diesen Schluesselbund fuer
die private Signierungsidentitaet. Zertifikate fuer die oeffentliche
Vertrauenskette kann macOS weiterhin aus seinen normalen Zertifikatsspeichern
beziehen. Betriebssystemfreigaben und Entsperren erfolgen lokal; Kennwoerter
werden nicht als Kommandozeilenargumente oder Umgebungswerte uebergeben.

Wenn der installierte root-eigene ZPAQ-Anker nicht dem neuen signierten Build
entspricht, kann `--install-for-tests` ausdruecklich die Installation genau
dieses Kandidaten vor den Tests anfordern. Der regulaere Installer verlangt
die lokale macOS-Administratorfreigabe. Danach laeuft derselbe Build weiter und
prueft die Bytegleichheit erneut. Ein neuer Build nach separater Installation
waere kein Ersatz: bereits der CMS-Signierzeitpunkt aendert die signierten Bytes.
Die Option ueberspringt keinen Test und ist keine oeffentliche Releasefreigabe.

Da macOS private PFX-Schluessel nicht rein ephemer in `X509Certificate2`
laden kann, verwendet der Signierer den von .NET vorgesehenen temporaeren
Keychain-Pfad. Das Buildskript begrenzt ihn auf einen eigenen `0700`-TMPDIR,
startet den bereits gebauten Signierer ohne MSBuild im selben Prozesspfad und
vergleicht vor und nach jedem Signiervorgang sowohl diesen TMPDIR als auch den
Benutzer-Keychain-Bestand. Ein Restartefakt bricht das Release fehlersicher ab.
Der Signierer gibt alle Zertifikats- und RSA-Handles vor dieser Kontrolle
deterministisch frei.

Danach kann der lokale arm64-Release-Build ohne weitere
Schluesselpfadvariablen gestartet werden:

```sh
tools/Build-KeepVault-macOS.sh --architecture arm64
```

Fuer ein Distributionsartefakt mit beiden Architekturen wird stattdessen
`--architecture universal` verwendet. Dabei muessen beide NativeAOT-Publishes
und alle nativen Komponenten als `arm64` und `x86_64` erfolgreich entstehen.

Der Releasepfad fuehrt kein ambient installiertes .NET SDK aus. Er laedt bei
Bedarf Microsofts offizielles macOS-arm64-Archiv fuer SDK 10.0.400, prueft es
vor und nach dem Entpacken gegen den fest gepinnten SHA-512-Wert und verwendet
fuer jeden Einstiegspunkt einen frischen privaten SDK-Baum. Der Host muss
zusaetzlich Microsofts Developer-ID-Signatur tragen.

Vor jedem Release werden Hauptprojekt, HybridSigner, Tests und Release-Verifier
mit `--locked-mode`, `--force`, `-p:RestoreForceEvaluate=false` und deaktiviertem
HTTP-Cache in einen neuen privaten NuGet-Cache restauriert. `--force` erzwingt
die erneute Restore-Prüfung; `--force-evaluate` wird nicht verwendet, weil es
den gesperrten Abhängigkeitsmodus aufheben würde. Alle .NET-Aufrufe erhalten per `env -i` nur eine feste
Allowlist; Publish und Signer-Build laufen danach mit `--no-restore` und ohne
persistente Buildserver. `obj`, `bin` und Publish-Ausgaben aller Projekte und
ProjectReferences liegen dabei ausschließlich in projektgetrennten Unterbaeumen
des frischen privaten Artefaktpfads; Repository-Zwischenergebnisse werden weder
gelesen noch ausgefuehrt. Das Release- und Verifikationsskript pinnt zusaetzlich
die SHA-256-Werte der auditierten Lockfiles und bricht bei jeder Abweichung vor
dem Zugriff auf private Signierschluessel ab.

Der Signierer lehnt Schluessel ab, die nicht zu den kompilierten dreifachen
RSA- und ML-DSA-Pins passen. Ein neuer macOS-Schluesselsatz erfordert deshalb
eine ausdrueckliche, gemeinsam auditierte Aktualisierung der Public Keys und
Build-Pins. Das Buildskript aendert solche Vertrauensanker nie automatisch.

## Lokale Apple-Signatur und Veroeffentlichung

Eine Apple-Development-Identitaet reicht fuer einen lokal geprueften Build,
aber nicht fuer eine oeffentliche Gatekeeper-Distribution. Bei solchen Builds
meldet die Verifikation die erwartete Gatekeeper-Ablehnung ausdruecklich und
behauptet keine Notarisierung.

Der von Apple dokumentierte Weg fuer das bereits signierte, unveraenderte ZIP
ist die direkte Einreichung mit `notarytool` aus Xcode. Der Buildpfad verwendet
dafuer `--notary-profile NAME`; nur dieser Profilpfad setzt ein gegen Apples
Dienst validiertes und erfolgreich gespeichertes Keychain-Profil voraus.
Alternativ unterstuetzen `notarytool submit` und `notarytool log` einen
geschuetzten Terminalprompt ohne Profilspeicherung: `--apple-id` und
`--team-id` angeben, `--password`, `--keychain-profile` und `--keychain`
weglassen. Dies ist in beiden lokalen Unterbefehls-Hilfen und
`man notarytool` dokumentiert; Apple verweist in
[TN3147](https://developer.apple.com/documentation/technotes/tn3147-migrating-to-the-latest-notarization-tool)
auf diese Hilfen. Eine erneute Signierung der Apps vor der Einreichung ist
nicht erforderlich.
[Apple: Notarisierung bestehender Software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)

Am 06.09.2026 bestaetigte der geschuetzte Benutzerprompt die Zugangsdaten
erfolgreich. Erst die anschliessende Speicherung im explizit gewaehlten
USB-Schluesselbund scheiterte mit `UNIX[Invalid argument]`. Das ist kein
Nachweis einer erneuten 401-Ablehnung. Die Ursache des Speicherfehlers bleibt
offen; ein Zusammenhang mit Unicode im Pfad ist nicht belegt.

Der Organizer-Preflight vom 06.09.2026 zeigte dagegen, dass das hier verwendete
Xcode seine Exportkopie auch mit dem passenden Developer-ID-Zertifikat erneut
signiert: Es erweitert die Designated Requirement um die App-Store-Klausel
mit OID `1.2.840.113635.100.6.1.9`; alle 30 geprueften Mach-O-CDHashes der
Haupt-App weichen danach vom Original ab. Apple beschreibt diese gemeinsame
Codeidentitaet fuer App-Store- und Developer-ID-Ausgaben in
[TN3127](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements).
Eine Notarisierung dieser Exportkopie begruendet keine Freigabe der
unveraenderten Originale. Deren strengere Signaturanforderung bleibt erhalten.

Die vorhandene Option `--notarize-in-xcode` erstellt getrennte Standardarchive
fuer Keep Vault, QR-Scanner und Keep Vault Installer und bewahrt den signierten Kandidaten in einem privaten
Verzeichnis. Sie schliesst `--notary-profile` aus und wartet am Terminal auf
`NOTARIZED`. Diese Eingabe und eine Organizer-Erfolgsmeldung sind keine
Freigabe: Das Skript verlangt unveraenderte Originaldateien sowie eigenstaendig
gueltige Tickets auf allen drei Original-Apps und bricht andernfalls ab. Der
Organizer-Weg ist auf diesem Xcode deshalb kein nachgewiesener erfolgreicher
Notarisierungspfad fuer den unveraenderten Kandidaten.

Nach erfolgreicher Einreichung sind Keep Vault, QR-Scanner und Keep Vault Installer
jeweils separat
am Original mit `stapler staple` und `stapler validate` zu behandeln. Alle drei
Original-Apps muessen anschliessend die Apple- und Hybrid-Signaturpruefungen,
die erforderlichen CDHash-Abgleiche und die finale Verifikation mit
`--require-notarization` und Gatekeeper bestehen. Ein Xcode-Export ersetzt
keines der drei Originale. Danach wird das ZIP mit Tickets neu erstellt und
signiert; `--install-for-tests` installiert exakt diesen Kandidaten vor den
Tests mit dem root-eigenen ZPAQ-Anker.

Eine oeffentliche Veroeffentlichung benoetigt zusaetzlich:

- ein gueltiges `Developer ID Application`-Zertifikat desselben Teams,
- erfolgreiche Notarisierung ueber das gewaehlte Verfahren,
- gueltige angeheftete Tickets fuer alle drei Apps,
- die abschliessenden Pruefungen mit `--require-notarization` und `spctl`,
- alle vorgeschriebenen funktionalen, GUI- und Performancegates sowie die
  genaue Zuordnung von Commit, Tag und Distributionsartefakten.

Ein GitHub-Entwurf ist keine oeffentliche Freigabe.

## Installation und Finder-Verknuepfung

Nach erfolgreichem Release-Build installiert der folgende Befehl das bereits
verifizierte Bundle nach `/Applications` und erstellt einen echten Finder-Alias
`Keep Vault` auf dem Schreibtisch:

```sh
tools/Install-KeepVault-macOS.sh
```

Ein vorhandenes Keep-Vault-Bundle wird nur bei passender Bundle-ID atomar mit
`NSFileManager.replaceItemAtURL` ausgetauscht. Nach erfolgreicher erneuter
Pruefung wird die vorherige Version wiederherstellbar in den Papierkorb
verschoben. Ein bereits vorhandenes Schreibtischobjekt wird nur ersetzt, wenn
es wirklich ein Finder-Alias ist.
