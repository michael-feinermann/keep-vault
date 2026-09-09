# Updating Keep Vault v12 on Windows

[Deutsch](KEEP_VAULT_V12_WINDOWS_UPDATE.md) | English

This document is the work guide for the later Windows port. The macOS 5.0.2
implementation is the normative v12 target reference. The
[password/PIN contract](KEEP_VAULT_V12_CREDENTIAL_POLICY.en.md) is included in
full. The [macOS audit report for 5.0.2](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md)
documents technical macOS acceptance completed on 8 September 2026. Before
porting, the published tag and specific commit assignment must also be checked.
The Windows version is built and tested separately; a successful macOS run is
not Windows evidence.

## Direct assignment for Codex on Windows

The following assignment can be passed unchanged to Codex on the Windows
computer. The original German block is preserved verbatim; its complete English
translation follows below.

```text
Arbeite im Repository keep-vault an der Windows-Version von Keep Vault v12.
Starte vom vollständig geprüften und gepushten macOS-5.0.2-Stand, der durch
Tag und Prüfbericht bestätigt ist. Prüfe Commit- und Tree-Hash sowie die
Zuordnung zu origin/master und arbeite auf einem neuen Branch codex/windows-v12.
Der technisch abgeschlossene, weiterhin nur als GitHub-Entwurf vorliegende
Vorgänger v5.0.1 liegt auf
e52159e7a569a8b77fe7732006388c4401c4009f und ist nicht die vollständige
5.0.2-Zielreferenz. Keinen beliebigen neueren Commit ungeprüft als Basis nehmen.

Lies zuerst den vollständigen aktiven Quellbaum einschließlich
KalynaArchiver, KeepVaultMac als normative Referenz, nativer Quellen,
Packaging, QR-Scanner, Tests, Build-Skripten und Dokumentation. Suche danach
gezielt nach v11, V11, alten Magic-Werten, alten KDF-/KPAR2-Pfaden und
Fallbacks. Abwärtskompatibilität ist ausdrücklich verboten. Entferne jeden
Legacy-Produktionspfad, statt ihn zu überbrücken.

Portiere die Windows-App ausschließlich auf das v12-Protokoll. Implementiere
und prüfe die nativen Windows-x64-DLLs, insbesondere kalyna_v12.dll,
threefish_ref.dll, aes_ref.dll, mars_ref.dll, shacal2_ref.dll,
chachapoly_ref.dll, argon2_ref.dll und zpaq.exe. Der bisherige Hinweis
„Windows Kalyna port is intentionally deferred“ ist ein Blocker und darf
nicht als erfolgreicher Build gelten. Verwende nur nachweislich kompatible,
lizenzierte Quellen und aktualisiere das Provenienz- und Hash-Manifest.

Übernehme zuerst KEEP_VAULT_V12_CREDENTIAL_POLICY.md einschließlich sämtlicher
alten Regeln und der neuen Offline-Modelldaten, ihrer Hashes und Vektoren.
PIN6–16 und Passwort24–256 sowie alle Auswahl-, Stärke-, Paar- und Datumsregeln
gelten ausschließlich beim Erstellen. Die Windows-GUI darf beim Entpacken keine
alten Längen-/Syntax-Qualitätsgates weiterverwenden. Der gemeinsame KDF-Pfad
verwendet ausschließlich technische Kodierungs-/Ressourcengrenzen.

Übernehme den Parallelisierungsvertrag des macOS-v12-Standes:

* Archivieren, Kompression, Verschlüsselung, Entschlüsselung, Entpacken,
  Integritätsblätter und KPAR2-Recovery arbeiten mit begrenzten Worker-Pools.
* Poly1305 muss ab der festgelegten Mindestgröße parallel laufen und durch
  RFC-8439-KATs, Parallel-vs.-Skalar-Vergleich, Tail-, Overflow- und
  Join-Fehler-Tests abgesichert sein.
* CTR-Counterbereiche müssen disjunkt sein. Counter-Überlauf wird vor jeder
  Ausgabemutation abgewiesen.
* Nach Create-, Cancel-, Wait- oder Join-Fehlern werden alle Worker sicher
  beendet, bevor Schlüssel, Jobtabellen oder Caller-Puffer freigegeben werden.
* Argon2id bleibt die einzige absichtliche Ausnahme: t=4 und p=4 sind fest,
  die Branches und Paranoia-Runde bleiben sequentiell. Diese Werte dürfen
  nicht aus untrusted Headerdaten kommen.

Führe Locked Restore und Release-Build mit dem im Repository gepinnten
.NET-10-SDK sowie Visual Studio 2022, MSVC, Windows SDK, MASM und PowerShell 7
aus. Protokolliere Host, SDK, Compiler, Commit, Tree-Hash, Worker-Limits,
Dauer und Exit-Code. Verwende für Build und Packaging einen unveränderlichen
Snapshot desselben Commits. Nie aus einem nachträglich veränderten Live-
Arbeitsbaum signieren.

Führe in dieser Reihenfolge aus und stoppe bei einem Fehler mit einem
reproduzierbaren Befund:

1. Locked Restore, native Build- und PE-/Exportprüfung.
2. Unabhängige KATs für Kalyna, Threefish, AES, MARS, SHACAL-2,
   ChaCha20-Poly1305, SHA3, Skein und Argon2id.
3. Smoke-Suite, danach die vollständige Windows-Suite.
4. Alle Cipher- und Kaskaden-Benchmarks mit Warm-up und Medianregeln.
5. Exakter 256-MiB-Durchlauf mit Kompressionsstufe 5, Paranoia und komplettem
   Argon2id.
6. Release-Verifier, Authenticode-/Manifestprüfung, Mutationstests,
   ZIP-Inhaltsprüfung, Installation und reale DE/EN-GUI einschließlich
   Offline-Erststart und unveränderter Geheimnisbytes.
7. Als letzten funktionalen Lauf ein komplexer Ordnerbaum mit leeren,
   kleinen, großen, zufälligen, stark komprimierbaren Dateien, Unicode-Namen,
   tiefen Verzeichnissen und ähnlichen Dateinamen. Archivieren, verschlüsseln,
   entschlüsseln, entpacken und alle Daten, Hashes und Metadaten vergleichen.
8. Danach nur unverändernde Paket-, Git- und Veröffentlichungsprüfungen.
   Jede Produkt- oder Artefaktänderung macht den letzten Gate ungültig.

USB- oder Hardware-Schlüssel dürfen nur direkt und speicherintern verwendet
werden. Private Schlüssel, PFX-Passwörter und geheime Schlüsselcontainer dürfen nie
in Argumenten, Umgebungsvariablen, Logs, temporären Dateien, Artefakten oder
Git erscheinen. Fehlt eine sichere Signaturquelle, signiere nicht ersatzweise
mit einem Testschlüssel und dokumentiere den Blocker. Öffentliche Zertifikate
und Zertifikatsketten dürfen Bestandteil der überprüfbaren Signaturartefakte sein.

Führe einen vollständigen Code- und Sicherheitsreview durch. Melde offene
TOCTOU-, Reparse-Point-, Hardlink-, ADS-, Pfad-, Ressourcen-, Thread-Lifecycle-
und Geheimnisbefunde mit Datei, Zeile und Kommando. Behaupte niemals
„ohne Sicherheitslücken“, solange ein Gate offen ist. Erzeuge kein öffentliches
Release, keinen Store-Upload und keine Veröffentlichung, bevor alle Windows-
Gates separat bestätigt und ausdrücklich freigegeben wurden.

Wenn alle nichtöffentlichen Gates bestanden sind, prüfe git diff --check,
stage nur geprüfte v12-Dateien, committe mit
„Implement Keep Vault v12 Windows parallel pipeline“ und pushe den Branch
codex/windows-v12. Führe danach einen Remote-Hash-Abgleich durch und schreibe
das vollständige Protokoll in die Windows-Dokumentation.
```

English translation of the assignment:

> Work in the keep-vault repository on the Windows version of Keep Vault v12.
> Start from the fully checked and pushed macOS 5.0.2 state confirmed by its
> tag and audit report. Check the commit and tree hashes and their assignment
> to origin/master, and work on a new branch codex/windows-v12. The technically
> complete predecessor v5.0.1, which is still only a GitHub draft, is at
> e52159e7a569a8b77fe7732006388c4401c4009f and is not the complete 5.0.2 target
> reference. Do not use an arbitrary newer commit as the base without checking.
>
> First read the complete active source tree, including KalynaArchiver,
> KeepVaultMac as the normative reference, native sources, packaging, QR Scanner,
> tests, build scripts and documentation. Then search specifically for v11, V11,
> old magic values, old KDF/KPAR2 paths and fallbacks. Backward compatibility is
> explicitly prohibited. Remove every legacy production path instead of bridging
> it.
>
> Port the Windows app exclusively to the v12 protocol. Implement and check the
> native Windows x64 DLLs, especially kalyna_v12.dll, threefish_ref.dll,
> aes_ref.dll, mars_ref.dll, shacal2_ref.dll, chachapoly_ref.dll, argon2_ref.dll
> and zpaq.exe. The existing notice “Windows Kalyna port is intentionally
> deferred” is a blocker and must not count as a successful build. Use only
> demonstrably compatible, licensed sources and update the provenance and hash
> manifest.
>
> First adopt KEEP_VAULT_V12_CREDENTIAL_POLICY.md, including all old rules and
> the new offline model data, their hashes and vectors. PIN6–16 and
> password24–256, and all selection, strength, pair and date rules apply
> exclusively at creation. The Windows GUI must not reuse old length/syntax
> quality gates during extraction. The shared KDF path uses only technical
> encoding/resource limits.
>
> Adopt the parallelization contract of the macOS v12 state:
>
> * Archiving, compression, encryption, decryption, extraction, integrity leaves
>   and KPAR2 recovery operate with bounded worker pools.
> * Poly1305 must run in parallel from the specified minimum size and be covered
>   by RFC-8439 KATs, parallel-versus-scalar comparison, tail, overflow and
>   join-failure tests.
> * CTR counter ranges must be disjoint. Counter overflow is rejected before
>   any output mutation.
> * After create, cancel, wait or join failures, all workers are safely completed
>   before keys, job tables or caller buffers are released.
> * Argon2id remains the only intentional exception: t=4 and p=4 are fixed;
>   the branches and Paranoia round remain sequential. These values must not
>   come from untrusted header data.
>
> Perform locked restore and release build with the .NET-10 SDK pinned in the
> repository and Visual Studio 2022, MSVC, Windows SDK, MASM and PowerShell 7.
> Record host, SDK, compiler, commit, tree hash, worker limits, duration and
> exit code. Use an immutable snapshot of the same commit for build and
> packaging. Never sign from a live working tree changed afterwards.
>
> Execute in this order and stop on an error with a reproducible finding:
>
> 1. Locked restore, native build and PE/export verification.
> 2. Independent KATs for Kalyna, Threefish, AES, MARS, SHACAL-2,
>    ChaCha20-Poly1305, SHA3, Skein and Argon2id.
> 3. Smoke suite, then the complete Windows suite.
> 4. All cipher and cascade benchmarks with warm-up and median rules.
> 5. Exact 256-MiB run with compression level 5, Paranoia and complete Argon2id.
> 6. Release verifier, Authenticode/manifest verification, mutation tests,
>    ZIP content verification, installation and real DE/EN GUI, including
>    offline first launch and unchanged secret bytes.
> 7. As the last functional run, a complex folder tree with empty, small, large,
>    random and highly compressible files, Unicode names, deep directories and
>    similar filenames. Archive, encrypt, decrypt, extract and compare all data,
>    hashes and metadata.
> 8. Afterwards, only non-mutating package, Git and publication checks.
>    Any product or artifact change invalidates the last gate.
>
> USB or hardware keys may be used only directly and in memory. Private keys,
> PFX passwords and secret key containers must never appear in arguments,
> environment variables, logs, temporary files, artifacts or Git. If a secure
> signing source is missing, do not sign with a test key as a substitute and
> document the blocker. Public certificates and certificate chains may be part
> of verifiable signature artifacts.
>
> Perform a complete code and security review. Report open TOCTOU,
> reparse-point, hardlink, ADS, path, resource, thread-lifecycle and secret
> findings with file, line and command. Never claim “without security
> vulnerabilities” while a gate is open. Create no public release, store upload
> or publication before all Windows gates have been separately confirmed and
> explicitly approved.
>
> When all nonpublic gates have passed, check git diff --check, stage only
> checked v12 files, commit with “Implement Keep Vault v12 Windows parallel
> pipeline” and push branch codex/windows-v12. Then perform a remote hash
> comparison and write the complete record in the Windows documentation.

## Goal and hard boundaries

* The goal is a new Windows v12 state with `ContainerVersion = 12` and
  `KPAR2 = 4`.
* The Windows app accepts only v12. There is no v11 reader, v11 migration or
  compatibility fallback.
* The old unlicensed Kalyna reference code must not be adopted. The native v12
  Kalyna implementation must come from a demonstrably compatible, licensed
  source and be recorded in the provenance log.
* The Windows version may be called a release only when all Windows gates,
  signature verification and a real Windows end-to-end run have passed.

## 1. Prepare the working tree and toolchain

1. Create a separate Windows branch from the pushed v12 commit. Check
   `git status --short` before starting and do not include macOS artifacts in
   the Windows build.
2. Install Visual Studio 2022 with C/C++, Windows 10/11 SDK, MASM and PowerShell 7.
   Record the SDK version and MSVC version used in the build log.
3. Restore the repository through `global.json` in locked mode.
   `packages.lock.json` may be changed only by a deliberately documented
   dependency update. `--force-evaluate` must not be combined with
   `--locked-mode`: it overrides locked mode. Normal builds set
   `RestoreForceEvaluate=false` and compare the checked lockfile hashes before
   and after restore/build.
4. For reproducible builds, use a case-sensitive, immutable source snapshot of
   the checked commit. The build script must not read from the live working tree
   between review, compilation and packaging.
5. Check `external/VENDOR-PROVENANCE.md` and the associated SHA-256 manifests
   again on the Windows computer against the sources actually compiled.

## 2. Switch projects to v12

* `KalynaArchiver`, `KalynaArchiver.Tests` and the release verifier target the
  same approved Windows TFM, currently `net10.0-windows` with the .NET-10 SDK
  pinned in the repository. There is no parallel v11 TFM.
* All project files, resources, error messages and README texts must use `v12`.
  Occurrences of `v11`, `V11`, old magic values or old KDF/KPAR2 fields must be
  searched for and removed before committing.
* Windows interop must load only the v12 names, especially `kalyna_v12.dll`.
  A missing or untrusted native module is a hard error, not a fallback to
  another DLL.

## 3. Native Windows libraries

`tools/Build-Native.cmd` is only the skeleton. It must produce the complete
v12 set for x64:

* `kalyna_v12.dll` from the licensed v12 Kalyna source with the two exports for
  the parallel and scalar CTR paths. Record export names, calling convention,
  endianness and cross-checking against an independent implementation.
* `threefish_ref.dll`, `aes_ref.dll`, `mars_ref.dll`, `shacal2_ref.dll` and
  `chachapoly_ref.dll` from their respective documented sources.
* `argon2_ref.dll` and `argon2.exe` from the checked PHC reference source.
* `zpaq.exe` with the v12 streaming format `KVP12ZP1` and the hardened
  argument/file-list path.
* Enable `/O2 /MT /GS /sdl /guard:cf` for all native targets and
  `/guard:cf /CETCOMPAT`, ASLR and NX when linking. The Crypto++ library and
  its adapters must be built with the same ABI-relevant SIMD options;
  `CRYPTOPP_DISABLE_ASM` must not be set on only one side.

Before inclusion in the app:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File tools\Verify-MldsaReference.ps1
cmd /c tools\Build-Native.cmd
```

The existing exit code “Windows Kalyna port is intentionally deferred” is
not a passed build but a deliberate porting blocker that must be removed.

## 4. Parallelization contract

Parallelization is data-independent and remains memory-bounded:

* Archives, compression, decryption and extraction operate in bounded
  chunks/worker pools. Worker count and chunk size are capped and never taken
  from untrusted header data.
* Each native worker must be tracked through `CreateThread`, cancel and wait
  failures until safe completion. Only then may job tables, key copies and
  caller buffers be released.
* CTR keystreams receive disjoint counter ranges. Overflow is rejected before
  the first output mutation.
* From the specified minimum size, Poly1305 is calculated in parallel over
  independent blocks. The last partial message, block order, length and nonce
  must be covered in an independent RFC-8439 KAT and a parallel-versus-serial
  test.
* Leaf hashes/MACs and KPAR2 data/parity blocks may run in parallel provided
  no buffer is reused before all dependent workers have completed. Errors are
  aggregated deterministically.
* Argon2id is the only intentional exception: `t = 4`, `p = 4`, the two branches
  and the Paranoia round remain sequential. As on macOS, memory size is derived
  from PMI16 and not stored in the container.

## 5. Container and KDF contract

The Windows port must satisfy the same v12 invariants as macOS:

* Magic/container version v12, `KPAR2-v4`, no v11 read or migration paths.
* Four mandatory factors: password, PIN and two separate generated 1024-bit
  hex factors.
* Separate SHA3-512 and Skein-1024 branches, length-prefixed and
  domain-separated. Paranoia executes the complete second Argon2id round.
* Authentication occurs before plaintext output. An encrypted container
  receives dually authenticated KPAR2 metadata; a tampered or unauthenticated
  sidecar is not treated as trusted.
* Paths, reparse points, hardlinks, ADS, leading hyphens and mutating
  input/output are checked before and during the operation.

## 6. Windows build and test sequence

The gates are recorded in this order. Each run receives commit, tree hash,
toolchain, host, runtime, test ID, duration and exit code.

The preserved command comments specify, in order: inexpensive KATs and
infrastructure first; the complete Windows suite without early termination;
primitive and container measurements only on an undisturbed computer.

```powershell
dotnet restore --locked-mode
dotnet build KalynaArchiver\KalynaArchiver.csproj -c Release --no-restore
dotnet build KalynaArchiver.Tests\KalynaArchiver.Tests.csproj -c Release --no-restore

# zuerst günstige KATs und Infrastruktur
dotnet run --project KalynaArchiver.Tests -c Release --no-build -- --smoke

# vollständige Windows-Suite ohne vorzeitigen Abbruch
dotnet run --project KalynaArchiver.Tests -c Release --no-build -- --full

# primitive und Container-Messungen, nur auf einem ungestörten Rechner
dotnet run --project KalynaArchiver.Tests -c Release --no-build -- --performance
```

Additionally mandatory:

1. Independent Kalyna, Threefish, AES, MARS, SHACAL-2, ChaCha20-Poly1305, SHA3,
   Skein and Argon2 KATs.
2. Parallel versus scalar for every cipher and cascade, including Poly1305
   and KPAR2.
3. Error paths for thread creation, join/wait, cancellation, counter overflow,
   damaged chunks and damaged parity blocks.
4. A complete run with 256 MiB, compression level 5, Paranoia and real Argon2id.
   Measured time and effective worker count must not come only from an estimate.
5. Release verifier, Authenticode/manifest verification and tamper tests for
   every EXE, DLL, manifest and the ZIP file; installation and actual GUI,
   including complete offline operation.
6. As the last functional test, a complex folder tree with empty files, very
   small and large files, random and highly compressible data, unusual Unicode
   names, nested directories and deliberately similar filenames. Archive,
   encrypt, decrypt, extract, compare hashes and metadata.
7. Afterwards, only non-mutating package/Git checks; no further mutations or
   functional tests without repeating the last gate.

The performance baseline must be identified per machine. A speedup must not
be obtained by removing authentication, KDF rounds, error correction or
security checks.

## 7. Signing and packaging

* For development builds, use only an explicitly marked test certificate;
  it must not be installed as a globally trusted root CA.
* For later Windows publication, separately verify a protected Authenticode
  certificate, the three RSA-SPKI pins and the three ML-DSA-87 pins. Private
  keys and PFX passwords belong neither in arguments, logs, Git nor in the
  ZIP file.
* `tools\Build-Portable.ps1` must build the main app, separate QR Scanner and
  release verifier from the same snapshot. Only then are SHA3/Skein manifests
  and hybrid signatures created.
* Before committing, extract the ZIP file into a new directory and check it
  with the standalone verifier. The result must contain no symlinks, debug
  symbols or unintended additional files.

## 8. Completion and release decision

Only when all gates are green. The preserved `git add` placeholder denotes
checked v12 files:

```powershell
git diff --check
git status --short
git add <geprüfte-v12-Dateien>
git commit -m "Implement Keep Vault v12 Windows parallel pipeline"
git push origin <windows-v12-branch>
```

A push is not yet publication. A tag, public ZIP, store upload or other
distribution requires separate approval after the Windows security review.
Open issues are recorded in `docs/KEEP_VAULT_V12_MACOS_RELEASE.md` or in the
recheck record with a specific test name and reproducible command.

## 9. Mandatory additions from macOS 5.0.2

- Marketing version and build number are independent of container v12. The
  real version from the build metadata must appear below the DE/EN subtitle.
  Main app and QR Scanner must carry the same release version/build number.
- Key sheets must contain the actual app version in the visible title and PDF
  document title: `Keep Vault [Version] Schlüsselzettel A` or B; in English,
  `Keep Vault [Version] Key Sheet A/B`. The version information changes neither
  the v12 container nor the binding of key sheets to archive path, algorithm
  and factors.
- Below the storage notice, the four metadata labels, including colons, are
  bold, while their values use regular type. This applies to encryption suite,
  archive file, creation device and storage location, and their English
  equivalents. Line wrapping accounts for the actual widths of both font
  styles.
- Provide at least three full writing lines with comfortably usable spacing
  for the handwritten user password. Immediately beside them, place
  `PIN nicht eintragen` or `Do not write down the PIN`. Password and PIN are
  never included as digital content in the sheet, QR code or PDF. Long metadata
  must neither displace writing lines nor obscure or clip factor characters,
  notices or QR codes. Unresolvable overflow must be reported understandably
  before a print job.
- DE/EN PDFs and actual paper printing must use the same checked design.
  Each separate print job contains only one complete factor with two identical
  QR codes and a public installation page without secret values. Render all
  pages and inspect them visually; additionally recognize printed QR codes
  with the separate scanner and verify exact agreement through actual copying
  and pasting. macOS CUPS evidence does not replace a Windows print test.
  The final macOS preview with bold field labels was explicitly approved on
  7 September 2026 with “Sieht gut aus. Setzt das um” (looks good, implement it)
  and is the design reference.
- Adopt all embedded password model data unchanged, including original indices,
  hashes, counts, licenses and fixed model parameters. Missing data blocks only
  a positive archiving check. No network fallback and no download at first
  launch.
- Exact pair check against the raw password and four forms of today's date
  from the local Windows time zone before the final archive start. Adopt tests
  for midnight changes, leading zeros and leap years.
- Existing 128-bit threshold unchanged; `Hneu <= Halt` for every test case.
  Do not present uncalibrated models as empirical entropy or attack costs.
  Execute all language, BIP39 and Unicode reference vectors independently on
  Windows, including static v12 archives that violate selection rules but are
  cryptographically correct, and KPAR2 restoration without model calls. No new
  normalization of KDF inputs.
- The macOS 5.0.1 corrections remain prerequisites: streaming empty directories,
  native read errors, ordered memory admission, complete volatile erasure of
  Skein working arrays and verified read-only archive staging data. Platform
  mechanisms for immutable private staging must be independently implemented
  on Windows and checked with negative counterchecks. Do not adopt POSIX APIs
  as Windows evidence without verification.
- Before completion, register only the current installation and its file
  associations. Old builds must not appear as additional app choices. Working
  copies for testing and GitHub drafts are not public approval.
- Delete original files only after successful archiving and a complete
  restoration/byte comparison. For separate cryptographic erasure, KPAR2 data
  must become unusable before the container. Negative cases without
  confirmation, after cancellation and with a plaintext container must retain
  all originals unchanged. Path changes reset confirmation; status, errors and
  completion messages follow the selected DE/EN language. This does not report
  backups, snapshots and physical SSD remnants as deleted. The macOS GUI
  counterchecks demonstrate deletion of selected copies and preservation of
  originals. However, a repeated GUI run found a delayed text-change event
  that reset the completion message to “Noch keine Datei analysiert” (no file
  analyzed yet). The completion status must survive programmatic clearing of
  the path and subsequent DE/EN switching. Every new nonempty path, even a
  single space, must instead reset status and confirmation, as must clearing
  a path that was only analyzed. On Windows, actual delayed event delivery,
  both initial languages, language switching and another erasure operation
  must be checked independently. The macOS regression test
  `gui.erase-completion-status` passed the targeted retest. The repeated visible
  check on the updated Development candidate under PID 34669 also passes,
  including DE/EN/DE and selecting a new path. Verification of the final
  Developer ID artifact remains separate.


## 10. Installation and rollback contract as the Windows foundation

This section describes properties to be transferred. It claims neither an
already implemented Windows installer nor passed Windows tests. The current
macOS implementation adds a self-contained signed installer with a prebuilt
verifier and deletion helper; the complete current macOS release run continues
to be accepted separately in the associated audit report.

- A public installation package must contain all required checked components.
  Neither a source workspace nor an SDK, package restore or compiler may be
  required on the target device. A reference to an installer that is not
  included does not satisfy this contract.
- If the complete package set cannot be found beside the running installer,
  an explicit folder picker may select another source. This selection is not
  authentication: the entire selected set must pass the same type, link,
  identity, copy and signature checks. Missing neighbors must not trigger a
  fallback to unchecked files or installation of individual components. App
  Translocation is a macOS case; on Windows, package paths, selection
  cancellation and the corresponding reparse-point/replacement cases are
  checked separately.
- An inventory authenticated by both existing signature methods binds the
  complete expected set with paths, types, sizes, modes or platform-appropriate
  access rights, and digests. Version, build and product identities must match.
  Additions, omissions, ambiguous names, reparse points, hardlinks and special
  objects are independently checked with Windows-native APIs and held handles.
- Executable installer components are moved into an area protected against
  changes by the same user before use. Authentication, actual process identity,
  held file identity and protection of the entire parent chain must agree
  before the first privileged use. macOS root ownership, POSIX modes and ACL
  symbols are not adopted literally; Windows requires its own owner, DACL,
  handle and service/token boundaries. The user may read from the checked set
  and execute required programs but must not be able to replace it.
- A failed operation must exactly restore the previously authenticated old
  installation. Its inventory, file contents, identities and sidecars are
  bound before replacement and checked again after rollback. Old, valid
  version-dependent notices or signature metadata need not match the different
  bytes of the new candidate. The comparison does not replace Authenticode/
  hybrid verification and must not weaken the existing rollback protection.
- The macOS example distinguishes local ticket integrity and current Apple
  distribution policy. On Windows, the actually available Authenticode,
  certificate-chain, timestamp and revocation checks must be named and
  demonstrated with equal precision. A successful policy call is not
  automatically evidence of identical artifact bytes; binding to the final
  signed inventory remains necessary.
- The Darwin stat error found shows why a successful ARM64 run provides no
  ABI statement for other architectures. On Windows, structure sizes, field
  offsets, character encoding, calling convention and actual DLL exports must
  be independently checked for each supported architecture. Compilation,
  emulated execution and actual installation/GUI testing are reported
  separately. No passed evidence is inferred from an absent hardware check.

The approved key-sheet design, the unchanged password/PIN rules that apply
only during archiving, and the v12 byte contract remain additionally binding.
These installation requirements change neither the user-chosen password and
PIN nor container headers, KDF or KPAR2.

## 11. Interim state of the macOS reference on 7 September 2026

The new Development build is not yet a completed 5.0.2 release.
`approved-installer-development-build.log` documents 151 passed groups and
one failed group out of 152 in 492.8 seconds. The failed group
`packaging.hybrid-key-separation` had an outdated expectation of SDK/`xcrun`
lookup in the now deliberately SDK-free metadata verifier. The test assumption
has been corrected to fixed system tools without `xcrun`; the actual probe
with a hostile `PATH` is retained. The targeted follow-up of this metadata
group passed with 1 of 1 groups in 79.0 seconds. Evidence is
`sdk-free-metadata-targeted-evidence/results.json`, SHA-256
`b0bde7f61f03e712cf26e1d6478c2d791f0f7784629dfcf261cc3ca1debd1de6`.
Earlier 152/152 runs remain evidence for their respective older sources and
artifacts; the targeted follow-up does not replace a new overall run.

The source snapshots of this Development build still bind `InstallerMain.swift`
to SHA-256 `fbe13c7ea165e7d4f860b422dbf711c18a05870d1ce4511237ac7ae326861406`.
The later folder picker for App Translocation belongs to a separate source
state with SHA-256
`74b4e6ecb612a5b81d24569a4ee78a7e4c35453d03a98b540fd7d4a9022bbde1`.
For this state, compilation of both architectures with warnings treated as
errors and twelve filesystem cases each under ARM64 and Rosetta-x86_64 are
demonstrated. The picker checks exactly 20 package objects, including their
types and links; authentication remains unchanged. These component probes do
not replace an actual installer GUI/administrator run.

The real app GUI run with version 5.0.2, Build 13, PID 81532 confirms the
version display in DE/EN, localized analysis and rejection statuses, and
deletion of the selected copies. The original container, original KPAR2 file
and control file remained unchanged. The German success dialog and clearing
of the path and confirmation passed. The subsequently discovered delayed
event-delivery error is minimally corrected and covered by the new group
`gui.erase-completion-status`. 153 groups are now expected as a result. The
freshly built targeted run `Test-KeepVault --category GUI --parallel 1`
subsequently passed with 24/24 groups in 21.2 seconds, including
`gui.erase-completion-status` in 1.390 seconds. Beforehand, 1319 source inputs
were bound in `gui-fixes-source-before.json`. The Development run subsequently
started with 153 expected groups was interrupted by a Mac restart on
7 September 2026 at around 14:04. There is no JSON result for the attempt
recorded in `final-gui-development-build.log`; it does not count as passed.

The subsequent rerun in `restart-development-build.log` passed with 153 of
153 groups, zero failures and zero blocked groups in 405.4 seconds; the
summed group runtime is 921.4 seconds.
`restart-development-results/001-test-results.json` has SHA-256
`343a5bac41eda92892e1958a1c0e40acc3d0a548c96883ef820f69a763cbd049`.
The before/after snapshots match for all 1,319 source inputs; the installed
Development app is byte-identical to the freshly built bundle. The new package
passes verification of 20 root objects, 19 Mach-O files and 38 slices. Both
NativeAOT slices successfully performed the authenticated manifest verification,
ARM64 natively and x86_64 under Rosetta.

The visible GUI retest from 15:19:35 under PID 34669 confirms the readable
version number beneath the subtitle and all four path placeholders in DE/EN
for 5.0.2, Build 13. Actual cryptographic erasure removes exclusively the
selected container/KPAR2 test copies; originals and the control file remain
unchanged. The completion status persists after OK and DE/EN/DE. A new path
resets status and confirmation; the app was then closed with Cmd-Q. Evidence
is `gui-completion-retest-result.json`. The later Windows port must
independently check this macOS regression with its own event delivery.

Private evidence is under `build/audit/5.0.2-20260906/`:
`installer-translocation-review/results.json` and
`approved-layout-gui-first-erase-result.json`. The targeted GUI retest is in
`gui-fixes-targeted-evidence/results.json`, SHA-256
`b92cb9e4d435a3bf5449d28bb49f878aa12f7810600f41da78e0bd8cff8c3922`.
The new package and slice evidence is in `restart-development-kit-audit.json`
and `restart-development-native-aot-architectures.json`.

The subsequent Apple notarization of the final Developer ID candidate passed:
job `672ab61e-4909-4fe9-a9e2-1685ea774e09`, `Accepted`, `statusCode = 0`,
`issues = null`. All three apps pass stapling, `stapler validate` and Gatekeeper.
The original submission state is bound to all 38 architecture signatures;
76 raw Apple lines correspond to these signatures, including bundle aliases
and duplicates. The final package passes verification of 20 root objects,
19 Mach-O files and 38 unchanged slices. Only three ticket files and six
renewed manifest/signature files distinguish it from the submission. Hybrid
manifest verification actually passes for 149 entries on ARM64 and under
Rosetta-x86_64.

The ZIP prepared for publication comprises 43,678,062 bytes, SHA-256
`cac58f018ab60734e4565aea601d590e390d6640419eabe41e62a66f8e9c7484`.
`final-release-assets.json` binds this ZIP and exactly five sidecars;
`final-notarized-package-audit.json` and
`final-native-installation-verifier.json` demonstrate the separate checks.
The 1,319 source inputs remain unchanged. App installation and authentication
for the root ZPAQ anchor are complete. The complete test run of the notarized
Developer ID candidate passes with 153 of 153 groups in 405.5 seconds, with
no failures or blocked groups; the summed group runtime is 918.9 seconds.
`final-developer-id-results/001-test-results.json` has SHA-256
`8ec5a2d0a5b28c5b40f3e0ba7054cea27c46bb99c4b25a1a3e26c3e44c1db93d`.
The additional individual release checks for production workers, parallel MAC
KAT, v12/KPAR2 roundtrip, KPAR2 workers, physical EIO repair and the complete
ZPAQ matrix also pass. The performance matrix of all ten cipher suites passes
in 195.0 seconds, the 256-MiB Paranoia run in 75.4 seconds and the complex
Paranoia run with KPAR2 repair in 73.7 seconds. Result files `015`, `017` and
`019` with the suffix `-test-results.json` and their SHA-256 values are in
the current audit. The release build of 7 September 2026 is complete; final
artifacts are under `dist/Keep Vault-macOS/`. The native installer GUI run,
the last complex run after final installation, and the final commit, tag and
public stable release remain open.

The actual native installer GUI test on 8 September 2026 subsequently found
an error in the codesign argument form: `-R` with separated requirement text
is evaluated as a file path; the required form is `-R=<Anforderungstext>`.
Installation aborted with an invalid requirement specification. The previously
fully tested and Apple-accepted candidate is therefore superseded and must
not be published. The correction requires new signing, notarization, complete
release checks, an actual installer GUI retest and the last complex run after
final installation. The Windows foundation is established only after those
are complete and the corrected candidate has been publicly released.

The macOS corrections are now implemented. A second integration error
concerned numeric UID text in ACL assignment. The installer now binds the
system-side account name through UID reverse checking, assigns read/search/
execute-only rights before any native execution and avoids later ACL metadata
changes. The native signature verifier uses bounded bytes from held descriptors
because `/dev/fd` denied access to root files with a read ACL. Existing signature
and identity checks are retained. Real codesign/ACL counterchecks, 15 signature
tests and verification of the same old root/ACL intermediate copy with new
NativeAOT verifiers on ARM64 and under Rosetta pass. This is neither a complete
new installer run nor Windows evidence.

Nine source/test/build paths are changed and 1,320 source inputs frozen;
password/PIN rules and archive cryptography remain unchanged. The installer
entry-point test now runs automatically before signing. The new Developer ID
build runs under
`build/audit/5.0.2-20260908/corrected-developer-id-build.log`. Apple has now
accepted the corrected candidate under job
`c4d7f3a5-3a54-4954-af83-d003bc194824` with `Accepted`, `statusCode = 0` and
`issues = null`. The original submission ZIP hash is
`72de4c27b7271fa264447d535826afb425f5c7ce0c5a07538eb25113478ac76b`.
All 38 original architecture signatures are bound;
`source-after-apple.json` confirms 1,320 unchanged source inputs. Stapling,
ticket validation and Gatekeeper acceptance for all three corrected apps now
pass. The final package passes with 20 root objects, 19 Mach-O files and
38 unchanged slices. Hybrid inventory verification with 149 entries and ZIP
verification including all sidecars pass on ARM64 and under Rosetta. The final
ZIP has 43,681,703 bytes and SHA-256
`820863042b5cfacb6643b1696c8fbf8412c9529d82d921d3bb7174db3dedf81d`;
`final-release-assets.json` binds all six new files.

The corrected notarized candidate also passes with 153 of 153 test groups
in 410.1 seconds, with no failures or blocked groups; the summed group runtime
is 932.8 seconds.
`corrected-developer-id-results-resumed/001-test-results.json` has SHA-256
`c9ddc29c752b5c451fd6e1a9d4c30770a368b248463ddcd6c157f34746f58147`.
All additional individual release checks and manual production measurements
have now passed: test times of 194.6 seconds for the performance matrix,
81.6 seconds for 256-MiB Paranoia and 78.3 seconds for the complex Paranoia tree
with KPAR2 repair. Total runtimes are 194.7, 81.7 and 78.4 seconds. The complex
run comprises 18 files, 20 directories and 221,327,790 input bytes; one damaged
unit is repaired. The corrected release build has finished with exit code 0.
All 20 result/timing files agree with the index; `source-after-build.json`
confirms 1,320 unchanged source inputs and `published-dist-assets.json`
confirms the six locally provided files as byte-identical to the privately
secured final assets. The actual GUI counterchecks for startup-dialog
cancellation, an incomplete package and folder-picker cancellation have now
passed. After each case, all 129 checked entries of the installed apps,
sidecars and root anchor retain identical bytes, metadata and inodes; atime
is excluded. The evidence files are `gui-installer-negative-cases.json` and
the three associated post-comparisons. This does not test cancellation of
the macOS administrator dialog; the separate folder picker does not
demonstrate actual App Translocation. Normal installation of the complete kit
under PID 9073 subsequently failed at a false identity rejection. The following
correction requires a new build and its own release evidence. Results remain
assigned to their respective candidates and do not replace Windows testing.
Rosetta does not demonstrate a test on separate Intel hardware. The
[current macOS audit report](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md) records further
retests through the final release. None of these macOS checks is a Windows
PASS; the Windows port starts only from the reference finally confirmed,
pushed and approved there.

## Further installer correction on 8 September 2026

The candidate documented above with Apple job
`c4d7f3a5-3a54-4954-af83-d003bc194824` passed 153 test groups and all additional
release checks but subsequently failed during actual GUI installation with
exit code 2. The existing installation remained unchanged in all 129 checked
entries. This candidate is not publishable; its results remain historical
evidence.

`installer-identity-trace/finding.json` isolates the cause of the false
identity rejection: immediately after successful verification of all 149
inventory entries, only ctime of the installer app directory changed. The
specific operating-system process or xattr trigger is not proven. The
correction excludes only this field from the longer-held installer directory
binding. All other identity fields and symlink/write-protection checks are
retained; the package root and regular helpers continue to bind ctime. Native
verification for each verifier call, as well as signatures, inventory and the
protected intermediate copy, remain unchanged.

19 regressions pass. A countercheck with the old ctime behavior restored fails
specifically; an independent source review confirms the limited scope and the
retained negative cases. Long messages now use a bounded, scrollable,
selectable and read-only detail area. 18 presentation tests pass. The synthetic
GUI check confirms DE/EN long text through the final marker, the English short
text visually and through Accessibility, and the German short text through
Accessibility. It does not replace actual installation.

Exactly five source/test/build paths were changed again; password/PIN rules
and archive cryptography remain unchanged. 1,320 source inputs are frozen
for the repeated build in
`build/audit/5.0.2-20260908/installer-ctime-fix/` and confirmed unchanged before
notarization. The new submission candidate is prepared: ZIP of 43,679,426 bytes,
SHA-256 `6bd960726f41189635343d5e47f0b509297ca4d17de06eb1038412ac0ba0aa74`.
`notary-candidate/submission-input-audit.json` confirms 5.0.2, Build 13 for
all three apps, 20 root objects, 19 Mach-O files and 38 slices. Apple has now
accepted this submission under job `de8618c3-7404-4b7f-b35e-591fd5fd92c2` with
`Accepted`, `statusCode = 0` and `issues = null`. The Apple service evidence
has SHA-256
`3fb3e3a2dfaab7b0f15f9321a07a6effe887ef866f826367c5389efa628ffc1d`;
`apple-submission-bound-audit.json` binds it to the original ZIP and all 38
original slices. `source-after-apple.json` confirms 1,320 unchanged source
inputs. The build was resumed after a single submission of `NOTARIZED`.
The new complete test run passes with 153 of 153 groups in 396.2 seconds,
with no failures or blocked groups; the summed group time is 910.3 seconds.
Evidence `corrected-developer-id-results/001-test-results.json` has SHA-256
`b7f068c25e9be40612fa869b2b88437dbf21f267ad5c6c3cf52924b522c89a6f`.
All six additional individual checks pass, as do the three production
measurements: performance matrix 196.1 seconds, 256-MiB Paranoia 81.8 seconds
and complex Paranoia tree 75.4 seconds test time. The complex run comprises
18 files, 20 directories, 221,327,790 input bytes and one successful KPAR2
repair. The build finished with exit code 0. All three apps pass stapling,
`stapler validate` and Gatekeeper. The final ZIP has 43,685,318 bytes and SHA-256
`c4f069e0091259a0c6a1f76d880879facec689625b059e5d5659b70e5af112e1`.
`final-notarized-package-audit.json` binds all 38 unchanged slices to Apple;
the permitted difference comprises only three ticket files and six manifest
files. The native verifier confirms 149 manifest entries and the ZIP with all
sidecars for both arm64 and x86_64/Rosetta, four calls with exit code 0.
`final-release-assets.json` and `published-dist-assets.json` bind the six final
files to the local distribution directory.
`source-after-build-independent.json` confirms 1,320 unchanged inputs.
This evidence is under `build/audit/5.0.2-20260908/installer-ctime-fix/`;
it confirms neither a public GitHub release nor separate Intel hardware.

The three repeated actual GUI counterchecks of the new signed installer pass:
startup-dialog cancellation, an incomplete package before authentication and
folder-picker cancellation. All 129 checked installed entries remain unchanged
after each case, including bytes, ctime and inodes. The German package error
message is fully readable in the screenshot.
`installer-ctime-fix/gui-installer-negative-cases.json` and its three state
comparisons demonstrate this. Administrator cancellation and actual App
Translocation are not demonstrated by these checks. Normal process PID 34713
has ended without an observed installation completion.
`gui-normal-resume-state.json` subsequently confirms 129 completely unchanged
entries. The new normal start PID 37155 is initially captured in
`gui-normal-resumed-start.json` before local macOS authentication. After local
confirmation, its normal actual installation passed:
`gui-normal-success.json` demonstrates the complete “Installation abgeschlossen”
(installation completed) window observed through AX and a screenshot.
`gui-normal-installed-audit.json` confirms both app trees at version 5.0.2,
Build 13, ten external sidecars and the root-owned ZPAQ anchor as byte-identical
to the final package. Physically, only the canonical main app is installed;
21 additional LaunchServices entries still await cleanup in this capture.
The actual separate folder-picker installation under PID 46797 has now also
passed: `gui-fallback-success.json` documents the visible complete completion
message; `gui-fallback-installed-audit.json` again records byte-identical
installed content. This does not demonstrate actual App Translocation.
The final installed GUI PID 56850 then passes the visible DE/EN checks of
the version beneath the subtitle, PIN 6 to 16, integrity and archive-path
placeholder. German is restored and the app closed; evidence
`gui-main-final-de-en.json`. The 21 additional registrations of the project's
own main app were selectively removed. `final-registration-after.json`
confirms exactly `/Applications/Keep Vault.app` and zero further registrations.
`final-physical-app-inventory.json` reads all 82 immediate app bundles in both
Applications folders independently of their names without error and finds only
this Keep Vault main app at version 5.0.2, Build 13. The complete offline
production run has now passed. The last installed complex test has also passed
with the unchanged regular launcher, a fresh SDK/restore/build and exactly the
installed native bytes: exit code 0, 70.532 seconds, 18 files, 20 directories,
221,327,790 bytes and one KPAR2 repair. `final-installed-test-summary.json`
and `final-installed-test-evidence/results.json` bind the result; the result
file's SHA-256 is
`905fff24578fa1db1ae3ae0019c712b5705429f644e386bfdf85d9a37fb28f96`.
`source-after-last-functional.json` confirms 1,320 unchanged inputs;
`final-after-last-test-readonly.json` still confirms only the canonical main
app with zero further registrations. Technical macOS acceptance is therefore
complete within the described scope and prepared for publication. Commit, tag
and public GitHub release will subsequently be performed and confirmed
separately; this state does not claim that public publication has already
occurred.
The offline evidence is maintained separately from actual GUI acceptance under
the clarified credential contract: a fresh production-core process, frozen
local models, installed signed native bytes and an external network blocked
throughout the entire roundtrip. The new run
`offline-e2e-prepared/run-xdf2p6l8/` passes with exit code 0 in 79.562 seconds:
18 files, 20 directories, 221,327,790 bytes, one authenticated KPAR2 repair
and a complete structure/size/SHA-256 comparison. 77 periodic network checks
accompany the run; positive IPv4/IPv6 probes pass before and after it. Wi-Fi
is restored and the watchdog did not trigger. `result.json` has SHA-256
`1c15da13a461236e81eaab8ab9bc683c3cc042503c3a84701a752ff3b44d400d`.
The independent follow-up audit `offline-e2e-independent-audit.json` passes
with 2,814 checks and 79 offline snapshots including the before/after control.
Periodic measurements are not a packet capture; cross-process time ordering
is demonstrated with UTC and an interval from the same orchestrator clock,
not with different process-local monotonic values. Factor generation in the
core test uses synthetic test samples. A complete offline GUI roundtrip is
not claimed; the obligation of fully offline operation remains unchanged.
Individual evidence and limitations are in the
[current macOS audit report](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md).

For Windows, the resulting requirement must be implemented separately and
tested on Windows: content/object replacement and harmless operating-system
metadata must not be equated on the basis of a timestamp transferred without
verification. The macOS ctime exception is not a blanket Windows exception.
Every exception needs a causal finding, a positive probe and tampering
counterchecks that continue to reject unchanged. Message presentation needs
corresponding DE/EN GUI checks on Windows. Neither the macOS probe nor Rosetta
demonstrates Windows testing or testing on separate Intel hardware.
