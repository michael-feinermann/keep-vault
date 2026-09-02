# Keep Vault macOS Release

Diese Infrastruktur erzeugt kein unsicheres Ersatz-Release. Ein Build wird nur
veroeffentlicht, wenn alle folgenden Vertrauenskettenglieder vorhanden und
erfolgreich geprueft sind:

1. NativeAOT-Core und alle nativen Werkzeuge sind Universal-Mach-O oder, bei
   einem ausdruecklichen lokalen Build, arm64-Mach-O.
2. Jedes Mach-O ist mit Hardened Runtime und einer Apple-Identitaet des fest
   eingebundenen Teams `2T6K9PGS55` signiert.
3. Der NativeAOT-Core und die fuenf zur Laufzeit benoetigten nativen Artefakte
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

Core und Launcher laufen in der App Sandbox. Erlaubt sind nur:

- durch den Benutzer ausgewaehlte Dateien mit Lese- und Schreibzugriff,
- Drucken fuer die Schluesselblaetter.

Es gibt keine Netzwerk-, Kamera-, Mikrofon-, USB-, Bluetooth-, Apple-Events-,
Debug-, JIT-, Unsigned-Memory- oder Library-Validation-Ausnahme. ZPAQ und das
Argon2-Kommandozeilenwerkzeug und Supervisor erben nur die Sandbox des
Hauptprozesses.

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

Vor jedem Release werden Hauptprojekt und HybridSigner mit `--locked-mode`,
`--force-evaluate` und deaktiviertem HTTP-Cache in einen neuen privaten
NuGet-Cache restauriert. Alle .NET-Aufrufe erhalten per `env -i` nur eine feste
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

Auf dem aktuellen Entwicklungsrechner ist eine Apple-Development-Identitaet
vorhanden. Sie reicht fuer einen lokal geprueften Build, aber nicht fuer eine
oeffentliche Gatekeeper-Distribution. Das Skript setzt deshalb bei diesem
lokalen Build keinen Notarisierungsstatus und meldet die erwartete
Gatekeeper-Ablehnung ausdruecklich.

Das lokale Buildskript lehnt eine `Developer ID Application`-Identitaet
absichtlich als Release-Gate ab, solange kein eigener notarisierender
Distributionsablauf mit Apple Secure Timestamp, `notarytool`, Stapling und
abschliessender `--require-notarization`-Pruefung konfiguriert ist. Es erzeugt
also nie still ein unnotarisiertes Developer-ID-Artefakt.

Eine oeffentliche Veroeffentlichung benoetigt zusaetzlich:

- ein gueltiges `Developer ID Application`-Zertifikat desselben Teams,
- Apple-Notarisierungsdaten fuer `notarytool`,
- ein erfolgreich angeheftetes Notarisierungsticket,
- eine abschliessende Pruefung mit
  `Verify-KeepVault-macOS.sh --require-notarization`.

Ohne diese Daten wird keine Notarisierung behauptet.

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
