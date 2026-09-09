# Historische v11-Prüfnotizen

Deutsch | [English](v11-open-questions.md)

Status: historisch und nicht normativ. Diese Datei hält den Stand des
abgelösten v11-Entwicklungszweigs fest. Keep Vault v12 implementiert und liest
v11 nicht. Keine Releaseentscheidung darf auf diesem Dokument beruhen. Die aktuellen
macOS-v12-Anforderungen stehen in `KEEP_VAULT_V12_MACOS_RELEASE.md`.

Alles hier wurde während der Entwicklung von v11 gefunden oder angesprochen und
bewusst nicht behoben. Jeder Eintrag beschreibt den Fehler, den Grund für die
ausstehende Behebung und die Voraussetzungen für seinen Abschluss.

## 1. Die beiden Signierschlüssel verwendeten einen gemeinsamen Wrapping-Key

RSA-PSS/SHA-512 und ML-DSA-87 sind algorithmisch unabhängig. Ein Release wird
nur als vertrauenswürdig akzeptiert, wenn beide Prüfungen bestehen. Betrieblich
sind sie nicht unabhängig: Beide privaten Schlüsselhälften werden durch denselben
32-Byte-AES-Schlüssel in einem einzigen Keychain-Eintrag geschützt. Wer diesen
Schlüssel erhält, erhält beide Hälften. Die Hybridsignatur verliert ihre hybride
Eigenschaft genau in dem Moment, in dem diese entscheidend wäre.

Dies wurde in v11 nicht behoben, weil das erneute Verpacken den ML-DSA-Schlüssel
im Klartext benötigt. Dieser befindet sich ausschließlich auf dem Offline-
Sicherungsmedium. Die Migration kann nicht auf einem Buildrechner erfolgen,
der nur die Envelopes besitzt.

Der v12-Releasegate verlangt zwei Keychain-Einträge mit unabhängigen zufälligen
Schlüsseln, einen pro Algorithmus. `Protect-HybridKeys-macOS.sh` erzeugt beide;
der Signer liest jede Hälfte über ihren eigenen Eintrag. Zwei Rückfragen pro
Release entsprechen bereits dem akzeptierten Verhalten. Noch besser wären
zwei unterschiedliche Schlüsselträger, mindestens für die RSA-Hälfte eine
Smartcard oder ein HSM, sodass kein einzelner Rechner jemals beide besitzt.

## 2. Der v11-ZPAQ-Kindprozess hatte keine eigene Sandbox

ZPAQ läuft bereits als externer Prozess und nicht innerhalb des App-Prozesses:
`ZpaqService` startet eine auf Vertrauenswürdigkeit geprüfte Programmdatei und
kommuniziert mit ihr über Pipes. Ein eigenes Sandboxprofil fehlt jedoch. Der
Parser besteht aus umfangreichem nativem C++-Code und ist die größte verbleibende
Angriffsfläche des Programms. Er ist eingegrenzt durch Pfadvalidierung, das
Verbot von Symlinks, private Eingabesnapshots, Größenlimits, einen Korpus
fehlerhafter Eingaben, begrenzte Ausgabe und einen Abbruch, der den gesamten
Prozessbaum beendet. Ein Speichersicherheitsfehler darin würde dennoch mit
denselben Rechten wie die aufrufende App ausgeführt, einschließlich des Zugriffs
auf Benutzerdateien und die oben genannten Keychain-Einträge.

Als Abhilfe wurde festgehalten, den Kindprozess unter einem restriktiven
Sandboxprofil zu starten, mit Dateizugriff ausschließlich auf den privaten
Snapshot und ein Ausgabeverzeichnis sowie ohne Netzwerkzugriff.
Die Schnittstelle ist bereits eine Pipe. Dafür muss daher der Start geändert
und nicht die Anwendung neu geschrieben werden.

## 3. v11 war nicht notarisiert und verwendete eine Apple-Development-Identität

Gatekeeper lehnt die App auf jedem anderen Mac als dem Buildrechner ab. Dies
ist ein Distributionsproblem und kein kryptografisches Problem. Die Hybridsignatur
und die beiden Manifeste sind die eigentlichen Nachweise für die Identität des
Pakets. Dennoch erschwert dies die Installation des veröffentlichten Builds.

Als Abhilfe wurden ein Developer-ID-Application-Zertifikat und eine Einreichung
zur Notarisierung im Releasebuild festgehalten. Dafür ist ein kostenpflichtiges
Apple-Developer-Konto erforderlich. Am Code muss nichts geändert werden.

## 4. Der PMI ist lokal beobachtbar, obwohl er nicht gespeichert wird

Die Argon2id-Speicherkosten werden aus den Credentials abgeleitet und weder in
den Header noch in KPAR2 geschrieben. Dadurch bleiben sie vom Datenträger fern.
Vor einem beobachtenden Prozess werden sie damit nicht verborgen: Sowohl die
Resident-Set-Größe als auch die verstrichene Zeit hängen davon ab. Ein lokaler
Beobachter kann daher den PMI einer beobachteten Ableitung abschätzen, und
16 Bits für das Speicherprofil bilden einen kleinen Suchraum.

Dies wird dokumentiert statt behoben, weil die Alternative konstanter
Speicherkosten dieselbe Information bedingungslos an alle preisgibt. Ob der
Nutzen der variablen Kosten ihre Komplexität rechtfertigt, bleibt offen.

## 5. Der XOR-Kombinator im Rollenschlüsselplan

Jeder Rollenschlüssel ist das XOR einer HKDF-HMAC-SHA3-512-Ausgabe und einer
geschlüsselten Skein-MAC-1024-1024-Ausgabe. Damit werden zwei 1024-Bit-PRF-
Ausgaben zu einer kombiniert, unter der Voraussetzung, dass beide Familien
die angenommenen Eigenschaften besitzen und die Kontexte eindeutig sind.
Dies ist kein robuster Kombinator: Zwei Primitive, die auf korrelierte Weise
versagen, oder ein böswillig gewähltes Paar sind nicht abgedeckt. Die Aussage
im Code und in der Dokumentation ist bewusst eng gefasst und sollte es bleiben.

## 6. Beide Argon2id-Zweige verwenden BLAKE2b

Der SHA3-Zweig und der Skein-Zweig unterscheiden sich in ihren Eingaben und
Domains, nicht in ihrem Kern. Argon2id ist auf beiden Seiten Argon2id. Ein
struktureller Bruch der Kompressionsfunktion von Argon2 betrifft daher beide.
Die Bezeichnung der beiden Zweige als „unabhängig“ trifft nur auf ihre
Eingaben zu.

## 7. Windows

`KalynaArchiver` wurde als Quellcode bis v11 mitgeführt. Das Projekt lässt sich
auf macOS mit `-p:EnableWindowsTargeting=true` kompilieren. Auf diese Weise
wurden die v11-Änderungen an ausschließlich unter Windows verwendeten
Codepfaden geprüft. Es wurde jedoch nie unter Windows ausgeführt oder getestet.
Insbesondere wurden der Windows-ZPAQ-Eingabesnapshot (`WindowsInputSnapshot`
in `ZpaqService.cs`) und seine adversariale Regressionsmatrix nur kompiliert,
nie ausgeführt. Entweder muss die Windows-Testsuite unter Windows laufen,
oder es muss klar benannt werden, dass der Windows-Quellbaum nicht unterstützt wird.
