# Keep Vault v12: Recheck mit GPT-5.6-sol

Stand: 2026-09-02. Dieser Prüfauftrag ist absichtlich kein
Veröffentlichungsauftrag. Der aktuelle Durchlauf darf bauen, testen, committen
und pushen, aber weder ein GitHub-Release noch eine öffentliche ZIP oder eine
Notarisierungsveröffentlichung erzeugen.

## Zweck

GPT-5.6-sol soll den vollständigen v12-Quellbaum unabhängig erneut lesen und
die nachstehenden Punkte mit reproduzierbaren Ergebnissen bestätigen. Ein
Roundtrip allein gilt bei kryptografischen Änderungen nicht als unabhängiger
Nachweis. Für jede primitive Änderung ist ein Known-Answer-Test gegen eine
zweite Implementierung erforderlich.

## Verbindliche Nachprüfungen

| Bereich | Nachweis, der erneut erbracht werden muss | Status dieses Laufs |
| --- | --- | --- |
| v12-Grenze | Kein v11-Reader, keine Migration, keine alten Magic-/KDF-/KPAR2-Pfade; alle Parser lehnen ältere Versionen ab | bestätigt durch `spec.no-legacy-source` und `spec.normative-v12-docs` |
| Kalyna | Lizenzierte Quelle, v12-Exportliste, skalare und parallele KATs, In-place-/Null-Längen-/Counter-Grenzen, Create- und Join-Fehler-KAT | Native Slice-KATs für arm64 und x86_64 bestanden; deterministischer Create-Failure-KAT bleibt offen |
| Threefish | Referenzvektoren, paralleler CTR gegen skalare Gegenprobe, Completion-Lebensdauer bei Create-/Join-Fehler, Windows-Pfad | Native Slice-KATs sowie Create-/Join-Abdeckung vorhanden; ASan/TSan-Lauf bleibt offen |
| Argon2id | PHC- und unabhängiger Bouncy-Castle-Vergleich; unveränderlich `t=4`, `p=4`; alle Worker bei Create-/Join-Fehler sicher abgeschlossen | Lifecycle-Fix kompiliert und Low-Memory-KAT bestanden; deterministischer Fault-Injection-KAT bleibt offen |
| Poly1305 | RFC-8439-KAT, paralleler und serieller Bytevergleich inklusive Tail, Overflow- und Fehlerpfade, kein Puffer-Reuse vor Worker-Ende | Native parallele KATs einschließlich 256-MiB-Lauf bestanden; frischer vertrauenswürdiger Release-Sidecar-Lauf bleibt offen |
| Containerpipeline | Archivieren, Kompression, Verschlüsseln, Entschlüsseln und Entpacken bounded und parallel; Authentifizierung vor Klartextausgabe | Implementierung und Worker-Gleichheit vorhanden; vollständige Release-Suite durch fehlenden Root-Anker bzw. vertrauenswürdige Testartefakte blockiert |
| Integrität/KPAR2 | SHA3-/Skein-Blätter, KPAR2-v4 RS(20,3), duale Authentifizierung und deterministische Fehleraggregation parallel geprüft | KPAR2-v4-KATs bestanden; vollständige Container-/Recovery-Suite wegen derselben Artefakt- und Root-Anker-Gates offen |
| ZPAQ | v12-Streaming, `--`-Argumentgrenze, FD-/Umgebungsvererbung, Seatbelt/Containment, kill/join und 6-GiB-Normrahmen | Prozess-Ressourcen-, CPU- und Stall-Gate bestanden; Root-Anker und vollständige Matrix bleiben offen |
| Source-TOCTOU | Build/Packaging aus einem privilegiert verankerten, unveränderlichen Commit-/Tree-Snapshot; kein Live-Repo-Fallback; ABA-, Detach- und Mount-Swap-Negativtests | release-blockierend, noch offen |
| Secrets | Keine privaten Schlüssel, Passwörter oder Keychain-Ausgaben in argv, Logs, temporären Artefakten oder Git; nur Keychain-Prompts mit „Erlauben“ | USB-Public-Key-Abgleich und PFX-Dateiprüfung bestanden; Schutz-ACLs verifiziert; keine Geheimnisse protokolliert |
| Toolchain | Gepinnter .NET-10-SDK, Locked Restore, native Compiler-/Linkerflags, Lizenz- und Provenienzmanifest unverändert zum geprüften Commit | Native arm64/x86_64/Universal-Builds, Locked-Restore-Gate und Toolpfad-Selbsttests bestanden |
| Release-Verifier | Jede EXE, DLL, jedes Manifest, ZIP und Companion-Artefakt in einem frischen Zielverzeichnis verifiziert; absichtliche Mutation wird blockiert | Nichtöffentlich vorbereitet; vollständiger vertrauenswürdiger App-/Sidecar-Lauf bleibt wegen fehlendem Root-Anker offen |

## Ausführungsprotokoll 2026-09-02

Der Lauf fand auf echter Apple-Hardware statt. Hostdaten: Apple-Silicon
`arm64`, macOS `26.6.2` (Build `25G83`), Xcode `26.6` (Build `17F113`),
Clang `21.0.0`, zehn logische Prozessoren. Der geprüfte Ausgangsstand war
`master` bei Commit `26cd3fba4bcb0b233d65009377a9e350c50663f6`; die Änderungen
dieses Laufs waren zu diesem Zeitpunkt noch nicht committed.

Nach Abschluss der Prüfungen wurde der geprüfte v12-Stand als Commit
`0dd3acc0e8e4254d345bfd9d9a6b487f8a0dbc19` mit Tree-Hash
`404c2fa03983db73b69ccecc8bf534befa84ee6d` auf `origin/master` gepusht.

Ausgeführte Gates und Ergebnisse:

| Kommando bzw. Test-ID | Ergebnis | Artefakt oder Hinweis |
| --- | --- | --- |
| `./tools/Build-Native-macOS.sh` | PASS | arm64, x86_64 und Universal; native Mach-O-Ausgaben erzeugt |
| `NativeKats.c` je Slice | PASS | `Native per-slice cryptographic KATs passed` für arm64 und x86_64 |
| `./tools/Build-Native-macOS.sh --verify-sources` | PASS | Manifest mit 431 Quellen |
| `./tools/Build-Native-macOS.sh --self-test-atomic-publish` | PASS | Vorab-Fehler, Hard-Link-Schutz und atomarer Austausch bestanden |
| `./tools/Build-KeepVault-macOS.sh --tool-path-self-test` | PASS | Release-Toolpfade verifiziert |
| `./tools/Provision-VerifiedDotnet-macOS.sh --tool-path-self-test` | PASS | Gepinnter .NET-10-Pfad verifiziert (`10.0.400` im Provisioner) |
| `./tools/Stage-TestNatives-macOS.sh --tool-path-self-test` | PASS | Test-Native-Stagingpfade verifiziert |
| `./tools/Protect-HybridKeys-macOS.sh --verify-only` | PASS | beide Keychain-ACLs und getrennte Wrapping-Rollen verifiziert |
| `spec.no-legacy-source` | PASS | `/private/tmp/keep-vault-test-runner.S8hQD8lG/artifacts/bin/KeepVaultMac.Tests/release_osx-arm64/.test-results.json` |
| `spec.normative-v12-docs` | PASS | `/private/tmp/keep-vault-test-runner.aaYaKEDN/artifacts/bin/KeepVaultMac.Tests/release_osx-arm64/.test-results.json` |
| `packaging.keychain-secret-not-in-argv` | PASS | `/private/tmp/keep-vault-test-runner.B08SE34D/artifacts/bin/KeepVaultMac.Tests/release_osx-arm64/.test-results.json` |
| `zpaq.process-resource-limits` | PASS | CPU-, RSS-, Wall-Time-, Prozesszahl- und Stall-Gates bestanden |
| `./tools/Test-KeepVault.sh --full --no-smoke --parallel 2` | 51 PASS, 50 FAIL | Ergebnisbaum `/private/tmp/keep-vault-test-runner.Etk0mTNo/artifacts/bin/KeepVaultMac.Tests/release_osx-arm64/.test-results.json`; die 50 Fehler sind fehlende signierte Sidecars, fehlender finaler `dist`-Stand oder der absichtlich erforderliche root-eigene ZPAQ-v12-Anker, nicht stillschweigend übersprungene Tests |

Der USB-Stick wurde ausschließlich für die direkte, speicherinterne
Authentifizierung verwendet. Der ML-DSA-Public-Key-Abgleich war erfolgreich
(`usb_mldsa_public_match=true`), die PFX-Datei war eine reguläre geschützte
Datei. Private Schlüssel, Passwörter und Keychain-Inhalte wurden weder
ausgegeben noch in das Repository übernommen. Die absichtlich prompt-only
gesetzten Keychain-ACLs wurden nicht abgeschwächt.

Die Performance- und End-to-End-Gates `performance.cipher-suites`,
`performance.paranoia-256mib-e2e` und `performance.paranoia-complex-tree-e2e`
konnten in diesem nichtöffentlichen Lauf nicht als Release-Nachweis ausgeführt
werden: Vor ihrem Start verweigert die Testumgebung die untrusted oder nicht
sidecar-signierten nativen Bibliotheken und den fehlenden root-eigenen ZPAQ-
Anker. Es werden deshalb keine Geschwindigkeitswerte als gemessen ausgegeben.

## Pflichtläufe auf echter Apple-Hardware

Die Ergebnisse sind mit Host, macOS-Version, Architektur, Commit-/Tree-Hash,
Toolchain, Workerlimit, Dauer und Exit-Code zu protokollieren:

1. Alle Smoke- und Comprehensive-Gruppen.
2. Alle zehn Cipher-/Kaskaden-Messungen mit denselben Eingabedaten und
   reproduzierbaren Warm-up-/Medianregeln.
3. Der exakte 256-MiB-Lauf mit Kompressionsstufe 5, Paranoia und vollständigem
   Argon2id.
4. Als letzter funktionaler Lauf ein komplizierter Ordnerbaum mit leeren,
   sehr kleinen, großen, zufälligen und stark komprimierbaren Dateien,
   Unicode-Namen und tiefen Verzeichnissen. Danach keine weitere funktionale
   Mutation des geprüften Quellstands vor dem Commit.

## Sicherheitsentscheidung

Solange der Build nicht aus einem unveränderlichen, gegen denselben Benutzer
verankerten Source-Snapshot erfolgt, darf GPT-5.6-sol keinen öffentlichen
Release als reproduzierbar oder sicher ausgeben. Gleiches gilt für einen
offenen Argon2-Worker-Lifecycle-Fehler oder fehlende Poly1305-KATs. Die
Entscheidung muss als „Release blockiert“ mit Fundstelle und Testkommando
notiert werden, nicht durch eine abgeschwächte Testauswahl umgangen werden.

## Abschlussformat

Das Recheck-Ergebnis enthält:

* geprüften Commit und Tree-Hash,
* jede ausgeführte Test-ID mit Ergebnis und Artefaktpfad,
* alle offenen Befunde mit Priorität, Datei/Zeile und reproduzierbarem
  Kommando,
* eine klare Entscheidung `bereit für separates Release-Gate` oder
  `Release blockiert`.

Private Schlüssel und App-spezifische Passwörter gehören nicht in dieses
Protokoll.
