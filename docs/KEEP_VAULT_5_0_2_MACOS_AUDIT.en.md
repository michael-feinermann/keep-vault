# Keep Vault 5.0.2: macOS audit report

[Deutsch](KEEP_VAULT_5_0_2_MACOS_AUDIT.md) | English

Technical acceptance completed on September 8, 2026: Keep Vault 5.0.2,
Build 13 is prepared for release within the documented audit scope.
Container v12 and KPAR2 v4 remain unchanged. Only the final candidate under
`build/audit/5.0.2-20260908/installer-ctime-fix/` is authoritative,
with Apple job `de8618c3-7404-4b7f-b35e-591fd5fd92c2`, status `Accepted`.
All three apps pass Developer ID, stapling, and Gatekeeper checks.
The final ZIP has SHA-256
`c4f069e0091259a0c6a1f76d880879facec689625b059e5d5659b70e5af112e1`.
All six release files and 38 original slices are independently bound;
1,320 source inputs remain unchanged through the end of the last functional
test.

153 of 153 full test groups, six additional individual checks, and three
production measurements pass. Both actual GUI installation paths, the final
DE/EN interface, and the installed app/sidecar/anchor bytes are verified.
Only the canonical main app `/Applications/Keep Vault.app` at version 5.0.2,
Build 13 is physically installed and registered. The full fresh offline
production core run passes in 79.562 seconds; the actual GUI evidence is
separate from it. As the last functional execution, the unchanged regular
test launcher passes against the final installation with a complex
Paranoia/KPAR2 round trip in 70.532 seconds. The approved key sheet design,
paper printing, QR copying, original deletion, and cryptographic erasure are
documented within their respective actual audit scopes.

This report records technical acceptance before commit, tag, and GitHub
upload. It does not claim that a public release has already occurred.
The intended stable release is
[v5.0.2](https://github.com/michael-feinermann/keep-vault/releases/tag/v5.0.2)
with exactly the six verified files; public visibility, tag association, and
uploaded bytes must subsequently be confirmed in practice.
The technically completed earlier version 5.0.1 remains at commit
`e52159e7a569a8b77fe7732006388c4401c4009f` and tag `v5.0.1`;
its GitHub entry remains a draft. Its
[audit log](KEEP_VAULT_5_0_1_MACOS_AUDIT_PROGRESS.en.md) is separate from the new
release.

The development and intermediate states below remain historical evidence.
Earlier candidates, errors, and gates that were open at the time are not
retroactively declared passed. The final status is in the acceptance table
and the last sections of this report.

## Audit scope

- Version display below the German and English subtitles.
- Unchanged previous password/PIN selection rules, supplemented by local
  complete-password models, PIN pair validation, and date/number patterns.
- Selection checks exclusively during archiving; separate technical input
  limits and unchanged KDF bytes during extraction, listing, and repair.
- Bundled, hashed, and signed model data, including attribution.
- GUI, existing security regressions, production KDF, both universal slices,
  signatures, notarization, installation, and release artifacts.

The [credential contract](KEEP_VAULT_V12_CREDENTIAL_POLICY.en.md),
[macOS release requirements](KEEP_VAULT_V12_MACOS_RELEASE.en.md), and
[PIN model log](KEEP_VAULT_5_0_2_PIN_MODEL_AUDIT.en.md) describe the mandatory
checks. The [model documentation](../KalynaArchiver/Resources/PasswordModel/README.md)
states finite coverage and limits. Model scores are not measured entropy.

## Previous independent findings

The source comparison confirms the unchanged earlier PIN and password
checks after subtracting the additive model integration. The files
`V12MasterKdf`, `RecoveryService`, `SuiteKeySchedule`, `KdfPrimitives`,
`KdfSalts`, and `EncryptionSuite` remain byte-identical to the completed
5.0.1 state. Pair validation is at the shared creation entry point.

Six frozen synthetic v12/KPAR2 test archives contain secrets that are empty,
short, above the previous selection limits, and rejected by new rules.
Their generation uses the documented 5.0.1 source state with only three
selection checks removed, the verified SDK, fresh private package stores,
and unchanged production KDF parameters. However, the historical generator
invocation included `--force-evaluate`, which overrides locked restore.
A separate strict repeat verification without that option passes with both
unchanged archived lockfiles and 87 unchanged source/project files; the
archived commands are not changed retroactively. File and provenance hashes
and six credential values independently recalculated using Python SHA3
match. The integrated 5.0.2 read test, which has now passed, is documented in
the repeat run below.

The independent model review found additional cases for BIP39 variations and
regularly inserted invisible characters. The corrections and stronger variant
regressions were included in the successful integrated runs documented
below. These also pass the checks for technical error messages in the
extraction dialog and factor format messages in both languages.

## First integrated run and corrections

The first fresh run contained 152 groups: 144 passed, eight failed, none
blocked. Runtime was 334.3 seconds. The observed before/after source
comparison of all 1,303 recorded files remained identical, including the
lockfiles. This is a diagnostic result, not release approval.

The failures concern the mistaken inclusion of private audit projects in
the build directory, a test assertion still fixed at Build 12, and six new
compatibility assertions that looked for native filenames in the wrong
output channel. For all six archive cases, the previous direct decryption
had already succeeded byte-for-byte. The actual listing, extraction, and
repair checks were repeated fully and successfully after the correction,
as documented in the following section.

The independent review also found conflicting restore options:
`--force-evaluate` overrides `--locked-mode`. The corrected macOS test and
build launchers do not use this option, set `RestoreForceEvaluate=false`,
and check for unchanged lockfiles. The separately identified outdated
verifier lock was corrected: its seven target/package entries match the
already completed 5.0.1 app lock in version, content hash, and dependency
edges. All four affected Microsoft packages additionally pass author and
repository signature verification. The corrected verifier passes a fresh
strict restore and release build with zero warnings/errors and 13 unchanged
input files. This does not yet test standalone AOT publishing or signed
program execution. Microsoft describes the behavior in
[NU1512](https://learn.microsoft.com/en-us/nuget/reference/errors-and-warnings/nu1512).

The new lock-checking functions of the three macOS launchers pass twelve
separate cases with valid, modified, missing, and symbolically linked files.
The new readable model-data notice is bound with 72,883 bytes and SHA-256
`fcc48f7f9d123570230f6e0fdb45a9e172c9addea17a619081392a3d8ec57ea2`.
Its isolated checking functions pass seven shell and 25 .NET cases;
verification of the signed app remains a separate gate.

## Successful integrated repeat run

With the corrected sources, the full run passes on macOS 26.6.2, arm64,
10 logical CPUs, and 16 GiB of RAM: 152 of 152 macOS full test groups,
zero errors, and zero blocked tests. Runtime is 367.7 seconds, total group
runtime 843.2 seconds, parallelization factor 2.29. The fresh release build
reports zero warnings/errors. The launcher uses effectively locked restore,
private SDK/package/artifact directories, and the native components belonging
to the installed trusted 5.0.1 app. This is not yet a build of the signed
5.0.2 distribution app.

All four new PIN/encoding groups, six password model groups, eight credential
compatibility groups, and the new DE/EN interface gate pass. The six frozen
archive cases pass, including listing, extraction, authentication, tamper
rejection without plaintext output, and exact KPAR2 reconstruction while the
damaged source remains unchanged. The effective model-access guard reports
no calls in these read paths. Actual desktop windows, offline first launch,
and a new archive round trip created with human mouse input were still
pending at this point. Later GUI results and remaining checks appear below.

The 1,306 recorded source/project/resource/test files are identical in content
and mode before and after the repeat run. The test inventory hash is
`d5991f97fe5fbccd2f97cc7c0ffdb3e2fff8a579449a0d0b4d535cbfd5049a76`.
Local records: `build/audit/5.0.2-20260906/full-repeat.log`,
`full-repeat-results.json`, `full-repeat-timings.json`, and
`source-after-full-repeat.json`.

## Signed development build of September 7, 2026

After the user confirmed unlocking, the fresh universal build passes with
the existing USB keys. Keep Vault and QR-Scanner are installed under
`/Applications` at version 5.0.2, Build 13. This candidate carries an Apple
Development signature and the existing hybrid signatures; it does not yet
constitute Developer ID notarization or a public release.

The full test set passes again with the freshly signed native components:
152 of 152 groups, zero errors, zero blocked, 383.8 seconds. The 1,306
recorded input files remain identical in content and mode before and after
the build. .NET compilation reports zero warnings/errors; native Crypto++
compilation contains the existing signedness-comparison warning.

The separate app-pair audit confirms complete path, type, size, and byte
comparisons between development output, installed apps, and ZIP, including
ten external sidecars and 32 architecture CDHashes in 16 Mach-O files.
Both Apple codesign checks pass. Extended attributes and ACLs are outside
this byte comparison. Evidence is under
`build/audit/5.0.2-20260906/development-build-results-20260907/` and in
`development-installed-pair-audit-20260907.json`.

Final Developer ID installation, notarization, and cleanup of app
registrations remained pending at this intermediate stage.

After this tested build, only the DE/EN print message in
`KeepVaultMac/Gui/MainWindow.Localization.cs` and the XML comment in
`KeepVaultMac/Services/KeySheetService.cs` were corrected. The printing path
already submits two separate jobs of two pages each; the old message
incorrectly claimed a three-page job. The corrected message confirms only
submission to CUPS, not completed paper output. Functional code remained
unchanged. The new snapshot `source-after-print-text-fix-20260907.json`
still contains 1,306 files and, compared with the signed development state,
exactly these two expected file changes with unchanged modes. The diff and
before/after hashes are in `print-log-text-fix-20260907.patch` and
`print-log-text-fix-20260907.json`. At this point, the product source state
was frozen again. The subsequent Developer ID build must pass the full tests
again with this new state; the previous 152/152 apply to the previously
built Development state.

## Ongoing GUI checks and separate production measurements

The installed app ran for the first GUI checks under the process profile
`(version 1)(allow default)(deny network*)`. A private LaunchServices audit
launcher retained the app association and started the sandbox, network probe,
and unchanged signed original launcher exclusively through fixed `exec`
calls. Bootstrap, rejected TCP probe, and installed core had the same PID
53907. The positive TCP control worked immediately before and after outside
the profile. Runtime bundle ID, bundle path, and core path subsequently
matched the canonical installation. This was a process-level check; operating
system services were not isolated system-wide.

An earlier direct launch without LaunchServices had no runtime bundle ID.
A separate attempt with a different audit bundle ID was also unsuitable for
GUI control. These launch attempts do not count as passed visible GUI checks.
The subsequent visible launch with PID 53907 used the original network block
without UNIX socket exceptions and did not change any signed app files.
Evidence: `offline-ls-canonical-gui-20260907.json` and
`offline-ls-canonical-runtime-20260907.json` in the private audit directory.

The actual windows show `Version 5.0.2` below the German and English
subtitles. The version line and expandable rule help were also visually
checked in a reduced-size window. The additional assessment of the synthetic
word password `Sommer Wiese Mond Vulkan Fluss Orange Wolke 2026!` shows 120
instead of the required minimum of 128 and rejects it. The German GUI rejects
`07092026` as today's local date and blocks a complete PIN inside an otherwise
accepted password. A separate permissible PIN with 16 digits is accepted.
These version, help, and selection checks were performed under the first
network block. Preparatory automated GUI events are not identified as human
entropy.

The subsequent first GUI archiving attempt failed because of this additional
external audit profile: `MacZpaqSeatbelt.RunCanaryAsync` could not bind its
local TCP listener in the parent process (`PermissionDenied`). No archive
was created. The synthetic source fixture with five files, 15 subdirectories,
and 34,832,501 bytes remained unchanged. The first factor generation was
discarded; its key sheets previously exported by Keep Vault remain solely
evidence of PDF output.

Both PDFs from this generation pass the independent check: two pages each,
all four pages visually complete and readable, four factor QRs each containing
exactly their own 256 ASCII hexadecimal characters, and two back-page QRs
containing exactly the printed download-source URL. The factors are separate;
password and PIN are absent from text, metadata, and QR payloads. QR decoding
by macOS Vision and a separate analysis of its corrected data bytes agree,
including terminator and full padding without additional segments. PDF hashes
and file identities remained unchanged. Evidence:
`build/audit/5.0.2-20260906/pdf-review-first-generation/final-qa.json`,
`visual-qa.json`, and `independent-qr/independent-qr-verification.json` in
the same directory. This is not a camera, paper-printing, or successful
archive test.

The second GUI attempt used the external audit profile
`(version 1)(allow default)(deny network-outbound)` under PID 54923.
The outbound connection was demonstrably blocked; local canary listeners
were permitted. Nevertheless, archiving failed at the inner `sandbox-exec`
before executing ZPAQ: exit code 71, no standard output, and 53 bytes of
error output. An independent minimal cross-check with inner `allow default`
and `true` under the same external profile reproduces exactly
`sandbox-exec: sandbox_apply: Operation not permitted` with a trailing newline.
Apple's SDK header `usr/include/sandbox.h`, documentation of `sandbox_init`,
also describes an error when a sandbox already exists. Evidence:
`offline-outbound-gui-20260907.json` and
`offline-nested-sandbox-control-20260907.json` in the private audit directory.

The subsequent full GUI archive test therefore followed a normal app launch
without an additional external Seatbelt profile. The product's internal ZPAQ
sandbox remains unchanged and mandatory. A full archive round trip under the
external network block has not been demonstrated; the offline checks that
already passed establish the GUI selection checks listed above.

In the actual GUI, extraction of the frozen compatibility fixture with an
empty password and empty PIN passed first. The success dialog and the
independently verified file `canary.txt` with 81 bytes and the expected
SHA-256 agree. Evidence: `gui-compat-empty-20260907.json`. This technically
valid read case was therefore also executed through the interface, in
addition to the integrated test group.

For the new test archive, the displayed mouse sample count rose from one
preparatory sample to 9,306 after the user moved the mouse; all nine pools
showed 1,034 samples each. Generation subsequently reset the source pool
display to zero. The preparatory initial value is not counted as human input;
sample counts are not evidence of entropy. This new factor generation was
not exported as a test PDF.

On September 7 at 10:27:01, separate print jobs were submitted directly from
Keep Vault to `Brother_MFC_L3750CDW_series`. CUPS listed jobs 15 and 16 with
105,472 bytes each. The correctly queried completed list contains both jobs;
the queue subsequently had no pending jobs. Evidence:
`gui-print-cups-completed-20260907.json` with exit code zero and
`bothFound = true`. The earlier `lpstat` call, which failed because a job
number was used instead of the printer name, remains documented separately
in `gui-print-cups-jobs-20260907.json` and is not evidence of success.
The user confirmed the actual paper output through specific layout feedback
and then held printed key sheet A in front of the camera. The scanner
recognized both identical codes; the actual Copy button and subsequent paste
into Keep Vault transferred exactly the expected factor with 256 ASCII
hexadecimal characters. Automatic clipboard clearing was then confirmed in
the scanner interface. Evidence: `gui-printed-camera-copy-20260907.json`.
A CUPS completion alone would not have been sufficient evidence of this.

At 10:27:46, the GUI reported successful creation of
`archives/paranoia-502-print-test.kzpaq` including KPAR2, with Paranoia,
compression level 5, a 16-digit PIN, and password model score 144.
The integrated byte comparison of five files and 34,832,501 bytes passed
before the explicitly selected original deletion. The separate follow-up
`gui-original-deletion-20260907.json` confirms: all five original files
removed, the 15 directories retained, their path set unchanged, and the
separate control file unchanged. Archive and KPAR2 are recorded with size
and SHA-256; no new test PDF was created.

The subsequent GUI extraction of this new archive also passes. The
independent comparison `gui-real-tree-comparison-20260907.json` confirms
exactly five files, 15 subdirectories, and 34,832,501 bytes with no missing
or additional paths. Path, type, size, and SHA-256 match the frozen reference;
all five direct file-stream comparisons against `reference-source` also
pass. Empty, hidden, and Unicode paths are included; links and special files
are excluded, and observed identities remain unchanged during the check.
This does not establish extended attributes, ACLs, or a file tree made
immutable by privileged protection. This is the successful GUI round trip
of the installed development candidate, not yet a test of the later
Developer ID artifact.

The additional frozen fixture `oversized-raw.kzpaq` could also be extracted
through the GUI: 262 UTF-16 code units in the password, including leading
and trailing spaces and a decomposed umlaut sequence, plus a 17-digit PIN
with a leading zero. The resulting `canary.txt` contains exactly the expected
81 bytes. Evidence: `gui-compat-oversized-raw-20260907.json`. Together with
the empty read case, this confirms GUI processing without archiving selection
rules, truncation, or Unicode normalization for these specific test inputs.

Separate cryptographic erasure was tested through the GUI exclusively on
standalone copies of the new test container and its KPAR2 file. Without the
confirmation checkbox, after canceling the final prompt, and with a plaintext
file carrying a `.kzpaq` extension, all control hashes remained unchanged.
A path change reset the confirmation checkbox. The confirmed positive run
removed KPAR2 and the container; the original pair, plaintext sample, and
control file outside the input remained unchanged. Afterward, the input
path and confirmation checkbox were cleared. Evidence:
`gui-crypto-erase-{before,unchecked,cancelled,plain-rejected,success}-20260907.json`.
This check does not establish deletion from backups, snapshots, or SSD reserves.

A GUI localization error was found during this check: analysis, rejection,
and completion messages appeared in English despite German being selected.
The interface now uses stable bilingual status keys and renders the current
status again on a language change. The erasure decision and ordering in the
shared erasure services were not changed. The corrected interface had thus
been compiled. The later visible retest confirms the DE/EN analysis and
rejection displays but found another error in persistently retaining the
completion message. This finding, its correction, and the separate evidence
are in the current section further below.

After this GUI cycle, the key sheet layout was revised at the user's request.
The visible title and PDF document title contain the actual app version and
A or B respectively. Three full writing lines spaced 9 mm apart and the
notice `PIN nicht eintragen` or `Do not write down the PIN` are reserved
explicitly. The factor size of 14 points and both QR symbols at 132 points
are retained. Four actual PDFs from the product service were generated and
visually checked on all eight pages; the fresh, strictly isolated build and
`keysheet.full-factor-print` pass. The source comparison before and after
the build covers an unchanged set of 1,306 files. Evidence is under
`key-sheet-layout-preview`. At the time of this first preview, the explicitly
required layout approval was still pending. This intermediate state did not
constitute acceptance of the final Developer ID artifact.
After the first preview, the user additionally requested that the four
metadata labels, including the colon, be bold while their values remain
regular, in German and English. This correction is implemented with separate
width measurement of both font weights. The new actual PDF generation under
`key-sheet-layout-preview/bold-labels` passes the strictly isolated build and
the complete factor-text test; the 1,306 source inputs remain unchanged
during the build. All eight new pages were visually checked again. Independent
verification confirms all 16 actual bold label spans, including the colon,
regular value spans, and twelve fully decoded QR raw payloads including
terminator and padding. The record
`independent-bold-qa-02/independent-final-qa.json` binds these results to the
four specific PDF hashes. The public installation page now links to the
instructions for the respective release and refers to the factor QR codes
on the key sheets. The user has now explicitly approved exactly this corrected
preview with “Sieht gut aus. Setzt das um” (“Looks good. Implement it”).
Approval is documented on September 7, 2026 in the `approval` section of
`user-printed-layout-feedback-20260907.json` and bound to source hash
`06760cf6c4db0df7a028ef1c408eca0b6e009e458bd705395ab535e7108ded55`
and `key-sheet-layout-preview/bold-labels/output/pdf`. The earlier
`false`/`NOT_APPROVED` entries in the file remain historical intermediate
states. Layout approval is therefore complete. Separate test, notarization,
and public release results are recorded in the current acceptance status
below.

Three separate fresh test launchers use the currently installed signed
native components and each pass without errors:

- Production worker equality across all ten suites: 8.5 seconds.
- Primitives and complete containers for all ten suites, including reference
  comparison and pipeline scaling: 184.2 seconds.
- 256 MiB, Paranoia, compression level 5, and production Argon2id: 72.4 seconds
  of test runtime, 71.843 seconds of measured execution. Archiving and
  encryption, KPAR2 creation and verification, and decryption and extraction
  pass with a complete data comparison.

Result and timing files are under `manual-production-worker-20260907-*`,
`manual-cipher-suites-20260907-*`, and `manual-paranoia-256mib-20260907-*`
in the private audit directory. These measurements replace neither testing
of the later Developer ID artifact nor the final complex folder run.

## Self-contained installation kit and supplementary security review

The previous review found an actual packaging error: the native ZIP contained
only the app pair with ten sidecars, while archive operations require the
ZPAQ v12 anchor set up with elevated privileges. Simply including the shell
installer, which depends on the workspace, would still have required Xcode
or a compiler and SDK on the target device. This historical finding is retained;
its correction is now implemented as product and packaging code.

The newly built Development ZIP contains `Keep Vault Installer.app`. The app
contains a universal NativeAOT verifier, the precompiled deletion helper,
and installation scripts protected by the Apple bundle signature. The fixed
package contains three apps at its root, ten app-pair sidecars,
`INSTALLATION.txt`, and `installation-manifest.json` with five sidecars of its
own, 20 entries in total. The structure of the six external release assets,
the ZIP and five signature/hash files, remains unchanged. Operational package
mode requires no installation of .NET, an SDK, a compiler, or Xcode on the
target. Package construction and NativeAOT checks are documented below.
The first full test run contains one failure; the later repeat passes 153
of 153 groups. The practical installer run has not yet been accepted.

The inventory is first checked against both compiled-in signature pins.
Then complete paths, types, file sizes, SHA-256 values, POSIX modes, and the
version, build, and identifier of all three apps are checked. Additional,
missing, ambiguous, linked, or special objects are rejected. Only the six
separately authenticated manifest files sit outside their own content list.
After stapling and `stapler validate` for all three apps, the final inventory
must be regenerated and hybrid-signed. The ZIP and its external signatures
follow only afterward.

The Apple system check `syspolicy_check distribution` alone is not evidence
of intact local ticket bytes. Isolated cross-checks under
`staple-policy-review-p8s9x5i9` sometimes accepted damaged or unrelated existing
tickets through this check while `stapler validate` rejected them. The target
adapter therefore combines Apple's current distribution policy with exact
ticket binding: `Contents/CodeResources` of the staged or installed app must
be byte-identical to the final signed inventory. Complete inventory and
object verification surrounds this comparison. Such a combination is not
presented as equivalence between `syspolicy_check` and `stapler validate`.

The native entry point authenticates the installer that is actually running
and binds its active CDHash to the copy. A separate Apple check covers all
universal slices. Before script or verifier execution, only the fixed package
is copied into a private root-owned directory; foreign ACLs are removed,
and links, unsafe types, and unsafe modes are rejected. The user receives
only read, traverse, and execute access. The inventory is checked before
and after granting these ACLs. Subsequent installation runs as the logged-in
user from this immutable set; the ZPAQ anchor, rollback boundary, and existing
transaction controls remain mandatory. A bounded regular `.DS_Store` file
in the download folder may be ignored; it is not copied. Private copies are
cleaned up only when root/device/inode identity matches.

An additional first-launch case has now been added to the native entry
point: Gatekeeper App Translocation may separate the launched installer from
its adjacent package files. Apple describes this exact limit of bundle-relative
access in the [App Translocation Notes](https://developer.apple.com/forums/thread/724969).
The previous automatic search in the bundle's parent folder is then
insufficient. The entry point now offers a native folder picker if a complete
package is absent there. The precheck uses `lstat` to check the fixed 20 entries,
their expected directory/file types, and a single link for files. The physical
folder check rejects symbolic links. The selected folder must subsequently
pass the same root-protected copy process, dynamic CDHash binding, Apple
check, and full inventory verification. No authentication boundary was relaxed
for selection. `installer-translocation-review/results.json` binds the
correction to the SHA-256 of `InstallerMain.swift`,
`74b4e6ecb612a5b81d24569a4ee78a7e4c35453d03a98b540fd7d4a9022bbde1`.
Both architecture slices compile with `-warnings-as-errors`; twelve filesystem
cases each pass under ARM64 and Rosetta-x86_64. This does not include an actual
administrator or installer GUI invocation. That remains pending.

Rollback after an error checks the authenticated previous state. It compares
the entire old app, including five sidecars, metadata, directories, file
modes, and ticket bytes, against the previously bound fingerprint and repeats
Apple/hybrid verification. A valid 5.0.1 ticket is neither compared with the
different 5.0.2 ticket nor bound to new 5.0.2 notice requirements.
Under `prior-release-rollback-lxxcg737`, actual Apple/hybrid verification of
the old pair, eleven negative checks, and a private execution of the product
rollback function with an actual `NSFileManager` replacement pass. Its deletion
helper was limited to the project's own private test objects; this evidence
is not a full privileged package installation run.

The native verifier also accounts for the different Darwin ABIs: ARM64 uses
`fstat`/`lstat`, while x86_64 uses the symbols `fstat$INODE64` and
`lstat$INODE64`. The independent C probe under `darwin-stat-abi-8_8c8frg`
shows that unqualified x86_64 `fstat` populates the 64-bit structure used
incorrectly. ARM64 and x86_64 under Rosetta confirm the corrected mapping.
This is ABI evidence on the available Apple Silicon Mac; installation on a
separate physical Intel Mac is not claimed.

The limited verifier evidence under `native-install-verifier` covers
72 synthetic cases, 13 CLI cases, comparison of all 16 Mach-O files in the
previously installed pair with the build tools, and 14 checks of the previous
state fingerprint. The native entry-point slices compile for ARM64 and x86_64
with `-warnings-as-errors`. The private tests
`tools/Test-InstallerEntry-macOS.py` and `tools/Test-PackageMode-macOS.py`
check, among other things, literal handling, staging responses, object
replacement, ticket differences, and early blocking of unprotected package
sources. These are targeted component checks. The universal NativeAOT verifier
now produced additionally passes verification of the new Development kit
on both slices actually launched:
`approved-installer-native-aot-architectures.json` records exit 0 and
146 authenticated inventory entries for each. The independent private kit
audit under `installation-kit-audit-selfcheck-20260907` confirms exactly
20 roots, 19 Mach-O files, 38 slices, and ZIP bytes and Unix modes. This evidence
replaces neither the full successful test set nor the actual installer GUI
run, Apple Accepted, stapling, final installation comparison, or public
stable release.

## Current Development run and subsequent GUI corrections

`approved-installer-development-build.log` ends with 151 of 152 groups
passed, one failure, and zero blocked groups. Runtime is 492.8 seconds;
total group runtime is 962.1 seconds. The only failed group is
`packaging.hybrid-key-separation`. Its assertion still expected the earlier
SDK/`xcrun` integration in `Verify-ReleasePairMetadata-macOS.sh`, which is now
intentionally SDK-free. The actual finding is therefore an outdated test
assumption; the failed run nevertheless remains 151/152 and is not retroactively
reclassified as a success.

The test assertion was updated to the fixed absolute system tools and the
absence of `xcrun`. The actual cross-check with a hostile `PATH` and shell
startup files remains intact. The separate rerun of this group passed with
1 of 1 groups in 79.0 seconds. The record
`sdk-free-metadata-targeted-evidence/results.json` has SHA-256
`b0bde7f61f03e712cf26e1d6478c2d791f0f7784629dfcf261cc3ca1debd1de6`.
This targeted retest does not replace a new full run.
`approved-installer-development-source-before.json` and `-after.json`
still contain the installer source hash
`fbe13c7ea165e7d4f860b422dbf711c18a05870d1ce4511237ac7ae326861406`.
The full run therefore does not establish the later folder selection with
the above hash `74b4e6ec…22bbde1`.

The installed app 5.0.2, Build 13 was visibly tested under PID 81532.
The version remains readable below the subtitle in German and English;
analysis of an encrypted container and rejection of a plaintext file follow
the DE/EN language switch. Positive cryptographic erasure removed the selected
standalone container/KPAR2 copies. The original container, original KPAR2,
and separate plaintext control file remained identical. The success dialog
appeared in German; the path and confirmation checkbox were cleared.
These results are recorded in `approved-layout-gui-first-erase-result.json`.

The same visible run found a remaining interface error: after the success
dialog closes, a delayed `TextChanged` event overwrites `eraseCompleted`
with `eraseNotAnalyzed`. The actual copy deletion and unchanged originals
are documented; correct persistent completion display had therefore not
yet passed. The minimal correction preserves completion status when the
path is cleared programmatically. Every new nonempty path still resets
analysis and confirmation. The erasure service, factors, and cryptographic
ordering remain unaffected.

The new regression `gui.erase-completion-status` uses actual delayed Avalonia
event delivery and checks completion display, empty path, reset confirmation,
subsequent path changes, and language switching. It was added to the test set,
which now expects 153 groups. Before the targeted build, 1,319 inputs were
recorded in `gui-fixes-source-before.json`. The fresh run
`Test-KeepVault --category GUI --parallel 1` passes 24 of 24 groups in
21.2 seconds; the new regression passes in 1.390 seconds. The record
`gui-fixes-targeted-evidence/results.json` has SHA-256
`b92cb9e4d435a3bf5449d28bb49f878aa12f7810600f41da78e0bd8cff8c3922`.
This is a targeted GUI test run, not a new full 153-group run or another
visible erasure check of the installed candidate.

The following Development run with 153 expected groups is documented in
`final-gui-development-build.log`. It was interrupted by a Mac restart on
September 7, 2026 at about 14:04; no JSON results are available for this
attempt. The attempt is counted neither as passed nor as a completed test set.

The four path placeholders for archive destination, input archive, extraction
destination, and erasure container are also localized in German and English.
The approval already granted for the corrected key sheets remains valid;
no new design approval is required.

The repeat in `restart-development-build.log` completed successfully with
exit code 0: 153 of 153 groups passed, zero errors, and zero blocked groups,
405.4 seconds overall and 921.4 seconds of aggregate group runtime.
The record `restart-development-results/001-test-results.json` has SHA-256
`343a5bac41eda92892e1958a1c0e40acc3d0a548c96883ef820f69a763cbd049`.
The before/after snapshots `restart-development-source-before.json` and
`-after.json` match for all 1,319 source inputs. The installed Development app
is byte-identical to the freshly built bundle.

`restart-development-kit-audit.json` confirms the new package with exactly
20 root objects, 19 Mach-O files, and 38 slices. Both NativeAOT slices actually
executed authenticated manifest verification successfully: ARM64 natively
and x86_64 under Rosetta, documented in
`restart-development-native-aot-architectures.json`. This does not establish
a GUI run on a separate Intel Mac.

The subsequent visible GUI retest started on September 7, 2026 at 15:19:35
under PID 34669. It confirms the readable version number below the subtitle,
all four path placeholders, and the PIN hint from 6 to 16 in German and
English. Actual cryptographic erasure removed only the selected standalone
container/KPAR2 copies; originals and control file remained unchanged.
After the success dialog, the completion display persists both after OK and
when switching languages DE/EN/DE. The path is empty; confirmation is off.
A new path resets status and confirmation. The app was then exited with
Cmd-Q, and the process is no longer present. The record is
`gui-completion-retest-result.json`.

These results concern the current Development candidate. Subsequent Apple
and package acceptance of the final Developer ID candidate is documented
separately in the next section.

## Apple notarization and final package

Apple accepted the original submission under job ID
`672ab61e-4909-4fe9-a9e2-1685ea774e09` with `Accepted`, `statusCode = 0`,
and `issues = null`. The private records are under
`build/audit/5.0.2-20260906/notary-502-kh3uwr54/`.
`notary-direct-service-log.json` has SHA-256
`a995cff5d3317c6cbb1d7ceaaa6dead83c6d6b312063753dcd58a9697b4e1310`;
the originally submitted ZIP has SHA-256
`a7c94ceebd88eb0b2cf4da289ce3d8ec6f5b8a306196bcb44e51ee29cb4990cb`.
`apple-submission-bound-audit.json` confirms binding of all 38 original
architecture signatures. The 76 raw lines in the Apple log correspond
exactly to these 38 signatures: the three bundle main executables also
appear under their bundle paths for each architecture; the remaining lines
are exact duplicates. `apple-ticket-multiplicity-audit.json` documents that
no additional or missing binary accounts for them.

`final-developer-id-build.log` confirms Developer ID signatures, successful
stapling, `stapler validate`, and Gatekeeper acceptance for Keep Vault,
QR-Scanner, and Keep Vault Installer. The subsequent
`final-notarized-package-audit.json` passes for exactly 20 root objects,
19 Mach-O files, and all 38 unchanged slices. Compared with the submission,
only three ticket files were added and the six external manifest/signature
files renewed. All other paths, types, modes, and bytes are identical. This
comparison is documented separately from Apple ticket validation and hybrid
manifest verification.

Actual hybrid verification of the final inventory passes with 149 entries
in both NativeAOT slices, ARM64 natively and x86_64 under Rosetta.
`final-native-installation-verifier.json` documents this execution against
the extracted `final-installer-kit`; it is not an actual GUI installer run
or a test on separate Intel hardware. `final-release-assets.json` binds
exactly six files prepared for release. The final ZIP contains 43,678,062 bytes
and has SHA-256
`cac58f018ab60734e4565aea601d590e390d6640419eabe41e62a66f8e9c7484`.
It differs from the original submission ZIP because of the stapled tickets
and renewed manifest.

The 1,319 source inputs remain unchanged. The candidate is still based on
commit `e52159e7a569a8b77fe7732006388c4401c4009f` with the audited 5.0.2
working state, which has not yet been finally committed. App installation
and authentication for the root ZPAQ anchor are now complete. The final test
run in `final-developer-id-build.log` passes 153 of 153 groups, zero errors,
and zero blocked groups in 405.5 seconds; aggregate group runtime is
918.9 seconds. The record
`final-developer-id-results/001-test-results.json` has SHA-256
`8ec5a2d0a5b28c5b40f3e0ba7054cea27c46bb99c4b25a1a3e26c3e44c1db93d`.

The additional individually launched release checks also pass: production
worker equality in 7.7 seconds, independent parallel MAC-KAT in 0.4 seconds,
v12/KPAR2 round trip in 25.1 seconds, KPAR2 worker equality in 0.2 seconds,
physical EIO repair in 0.6 seconds, and complete ZPAQ matrix in 21.6 seconds.
These are the respective overall runtimes; result files with the prefixes
`003`, `005`, `007`, `009`, `011`, and `013` and suffix `-test-results.json`
are in the same results directory.

The production checks performed afterward also pass:

| Release check | Overall runtime | Result file | SHA-256 |
| --- | ---: | --- | --- |
| Primitives and complete containers for all ten cipher suites | 195.0 s | `015-test-results.json` | `61ee88f33e04edd89a6c1b4d2bf0392a74735e8b0bfdc1ecbec8c3241ad8f35e` |
| 256 MiB, Paranoia, level 5, production KDF | 75.4 s | `017-test-results.json` | `a1765a599d66237cad65235954982be18155d7441b66d3ec4ab680e8f747ff1b` |
| Complex Paranoia directory tree with KPAR2 repair | 73.7 s | `019-test-results.json` | `d22fbd7f36ad7864faa6d8c0ef1ab54f52c1a208bee1f77f80ee5459b38e6f8f` |

The performance matrix stays within the limit of 25 percent relative to the
specified reference measurement on the same Mac. The complex run processes
18 files, 20 directories, and 221,327,790 input bytes; one damaged unit is
repaired by KPAR2. These measurements use the production Argon2id parameters.
The separate pipeline scaling within the performance matrix explicitly uses
the test KDF memory size and is not presented as a production KDF measurement.

`final-developer-id-build.log` ends with `release_publish_swap=complete`
and the final app/ZIP paths under `dist/Keep Vault-macOS/`. The local release
build of September 7, 2026 is therefore complete. The actual native installer
GUI run and the final complex Paranoia run after final installation remain
separately pending. Commit, tag, upload verification, and the public stable
release follow only after these results.

## Installer GUI finding and required repeat

The actual native installer GUI test on September 8, 2026 failed with
“Installation angehalten” (“Installation stopped”) and the codesign error
`No such file ... invalid requirement specification`. The requirement was
passed as a separate argument after `-R`. `codesign` interprets this form as
a file path; a requirement supplied as text requires `-R=<Anforderung>`.
Verification stopped the installation instead of ignoring the error. The
finding concerns installer execution and was not captured by the previously
passed component, build, and notarization checks.

In the following private integration run, the corrected codesign check
passed. ACL granting then failed with `user:501` because `chmod` could not
translate the numeric text into a user UUID. No app was installed; the failed
staging copy was removed. The correction determines the account name with
`getpwuid_r`, checks its reverse resolution with `getpwnam_r`, and additionally
checks the UID on the root side. The ACL commands actually generated use this
bound account name and grant only read, traverse, and execute access.

ACLs are also granted before the first system policy check and execution of
native programs. This avoids any subsequent ACL metadata change to native
files that have already launched. Another cross-check found access to
`/dev/fd/6` by the previous native signature verifier blocked for root-owned
files with mode 0600 and a read ACL. The correction reads bounded signature
bytes directly from the held file descriptor and verifies them with the
shared signature API. The previous signature, size, and identity checks remain
intact.

These product corrections are now implemented. The private records
`installer-literal-requirement-regression-20260908.json` and
`installer-account-acl-regression-20260908.json` in the September 6 audit
directory confirm the actual codesign and ACL commands, including deliberately
reintroduced errors. `held-signature-regression-20260908.json` confirms
15 passed checks of held signature bytes, SHA-256
`e1a7966944f70bf01b71ffba33f8115fca8cf03eaac0496e60ab8e5560f93982`.

`build/audit/5.0.2-20260908/root-acl-native-before-after.json` shows, against
the same unchanged root/ACL staging copy: the old verifier aborts with the
`/dev/fd` access error, while the newly built NativeAOT verifiers pass with all
149 inventory entries on ARM64 and under Rosetta-x86_64. A corrected external
verifier was executed against the existing old staging copy. This is targeted
component evidence, not a successful new complete installer run. Verification
of the installer entry point is now automatically mandatory in package
construction before signing; `installer-entry-release-gate.log` in the new
audit directory confirms it.

`correction-source-delta.json` binds exactly nine changed source/test/build
paths and the transition from 1,319 to 1,320 source inputs. Password/PIN rules
and archive cryptography were not changed by these corrections; the shared
hybrid signature API was extended without weakening its previous checks.
The frozen new state is being built in
`build/audit/5.0.2-20260908/corrected-developer-id-build.log`.
The previously documented Apple acceptance, ZIP hash, and all build PASS
results remain historical evidence for the faulty candidate. They must not
be transferred to the changed installer artifact. Version 5.0.2, Build 13
remains the target before the first public release; the corrected candidate
requires its own signature, notarization, stapling, and complete test evidence.
The actual installer GUI run and final complex run after final installation
are required again. The README example was corrected to the text form `-R='…'`.

## Historical candidate with Apple acceptance on September 8, 2026

Apple accepted the new submission under job ID
`c4d7f3a5-3a54-4954-af83-d003bc194824` with `Accepted`, `statusCode = 0`,
and `issues = null`. The original submission ZIP has SHA-256
`72de4c27b7271fa264447d535826afb425f5c7ce0c5a07538eb25113478ac76b`.
The service record
`build/audit/5.0.2-20260908/notary-candidate/notary-direct-service-log.json`
has SHA-256
`386e1e7ac1b79ae3392a717c296c74589d784e3913d85818a1683f338cbd87a2`.
`apple-submission-bound-audit.json` in the same day's directory confirms all
38 original architecture signatures; the 76 raw Apple lines are mapped to
these signatures. `source-after-apple.json` contains 1,320 source inputs,
no changes, and `matchesPrevious = true`.

This new acceptance applies to the corrected candidate and is separate from
the superseded job `672ab61e-4909-4fe9-a9e2-1685ea774e09`. The submission
ZIP hash must be distinguished from the subsequent stapled release ZIP.
Stapling, ticket validation, and Gatekeeper acceptance of all three corrected
apps have now passed in the new build log.

`final-notarized-package-audit.json` in the September 8 audit directory
confirms the final package: 20 root objects, 19 Mach-O files, and 38 unchanged
slices. Compared with the new submission, only the three ticket files were
added; the six manifest/signature files were renewed. All other paths, types,
modes, and bytes match. `final-native-installation-verifier.json` confirms
both the hybrid inventory with 149 entries and the ZIP with all five sidecars
on ARM64 and under Rosetta-x86_64. All checked files remained unchanged.
`final-release-assets.json` binds exactly six files. The final ZIP has
43,681,703 bytes and SHA-256
`820863042b5cfacb6643b1696c8fbf8412c9529d82d921d3bb7174db3dedf81d`.

The full test run of the corrected notarized candidate passes 153 of 153
groups, zero errors, and zero blocked groups in 410.1 seconds; aggregate group
runtime is 932.8 seconds.
`corrected-developer-id-results-resumed/001-test-results.json` has SHA-256
`c9ddc29c752b5c451fd6e1a9d4c30770a368b248463ddcd6c157f34746f58147`.
All additional individual release checks also pass: production worker equality,
parallel MAC-KAT, v12/KPAR2 round trip, KPAR2 worker equality, physical EIO
repair, and the complete ZPAQ matrix. Production measurements are also complete:

| Corrected candidate check | Test time | Overall runtime | Result file |
| --- | ---: | ---: | --- |
| Performance matrix for all ten cipher suites | 194.6 s | 194.7 s | `015-test-results.json` |
| 256 MiB Paranoia with production KDF | 81.6 s | 81.7 s | `017-test-results.json` |
| Complex Paranoia tree and KPAR2 repair | 78.3 s | 78.4 s | `019-test-results.json` |

The three result files are in `corrected-developer-id-results-resumed/`.
Their SHA-256 values are
`1e1448823dfb6ea904800aebdce4b15d128c6327615ca364bed7583288cabaca`,
`95b1ed62d72a9cbc12db8f250feb45292ff1d166749d401e7f978f53ee621af5`,
and `0ccb528d57c0bf86460aa95abc292554024cd38642f04f7abb76aba27b1d6679`.
The results index binds a total of ten result files and ten timing files;
all 20 files are checked against their index hashes. The complex run processes
18 files, 20 directories, and 221,327,790 input bytes and repairs one damaged
unit with KPAR2.

The corrected release build is complete with exit code 0 and
`release_publish_swap=complete`. `source-after-build.json` confirms all
1,320 source inputs are unchanged. `published-dist-assets.json` confirms that
the six files under `dist/Keep Vault-macOS/` exactly match the privately
preserved final assets. This is local provisioning, not yet a public release.
The additional actual installer GUI negative checks have now passed:
canceling the start dialog, selecting an incomplete package, and canceling
folder selection. `gui-installer-negative-cases.json` has SHA-256
`6f3dd5afc283f4631219b5494ea359d8f992c984985401f2167aea5ba39fa211`.
After every case, a separate comparison confirms that the same 129 entries
of both installed apps, their ten sidecars, and root anchor files, including
the minimum version, remain unchanged. Checked properties are types, bytes,
modes, inodes/devices, owners/groups, link count, flags, and mtime/ctime;
atime is excluded. The records are `gui-cancel-initial-after.json`,
`gui-incomplete-package-after.json`, and `gui-cancel-folder-after.json`.
The state comparison executed no LaunchServices or app commands. Cancellation
of the macOS administrator dialog was not tested here; separate folder
selection is not evidence of actual App Translocation.

Normal installation from the complete package with 20 root objects under
PID 9073 failed after local administrator approval with exit code 2:
`The bound package, installer, verifier or rollback helper changed
identity.` Previously, repeated verification of all 149 inventory entries
and Apple checks had passed. `gui-final-installer-normal-failure.json`
documents the failure; `gui-installer-normal-failure-state.json` confirms
all 129 previously installed entries are unchanged. The passed build and
Apple acceptance therefore do not make this candidate releasable.

## Proven ctime error and a new candidate

The separate repeat in `installer-identity-trace/finding.json` shows the
precise failure boundary: after successful native verification of all
149 inventory entries, the immediately following directory binding failed.
Only the ctime of `Keep Vault Installer.app` changed, from 1788870435 to
1788870436. Device, inode, owner, mode, size, mtime, and link count remained
the same. The source/staging-copy comparison confirms 156 entries with
unchanged types, modes, and bytes. The execution log
`installer-identity-trace/sealed-install-xtrace.log` has SHA-256
`059a3509f31dd12ef84b020562f5f51fd00069010a8455b79c9d654d1a80cbf9`.

This causally establishes the false rejection by ctime binding. Which
operating system process or specific xattr operation changed ctime has not
been established. A metadata change by macOS remains an inference. The xattr
mutation in the regression deliberately reproduces the same field change but
does not identify the original trigger.

The correction omits only ctime from the longer-lived binding of the installer
app directory. Its other identity fields and symlink and write-protection
checks remain intact. The package root and regular helpers continue to bind
ctime; helpers are additionally bound to SHA-256. Root ownership, protected
staging copy, Apple signatures, and the complete hybrid inventory remain
mandatory. Native directory binding within a verifier call remains unchanged.

`package-ctime-regression.json` documents 19 passed cases. They check the
permitted ctime-only change to the installer directory and the continued
rejection of changes to root ctime, helper ctime, mode, writability, mtime,
inode, and symlink, as well as the previous helper, ticket, and SDK-independence
checks. Deliberately restoring the old directory ctime comparison causes the
new positive test to fail. This mutation cross-check confirms that the test
detects the original error. `package-ctime-tests-independent-review.json`
documents the separate read-only review of the 19 cases and their evidential
limits.

Error presentation is also corrected: a process log about 131 KB long is
shown in full in a 600 × 240 point vertically scrollable text field. The system
font is 13 points; the text is selectable and read-only. Short messages remain
directly readable. The message for an incomplete package is available in German
and English. The private harness passes 18 presentation cases in both languages
without visible windows. The synthetic native GUI check confirms long German
and English text, including scrolling to the last marker, the short English
text through a screenshot and Accessibility, and the short German text through
Accessibility. No additional screenshot is available for the short German
text. The records are in `installer-alert-preview-20260908/test-result.json`
and `installer-alert-preview-20260908/gui-preview-result.json`. The preview
performed neither installation nor authentication.

Exactly five paths have changed compared with the previously built candidate:
`InstallerMain.swift`, `Build-InstallerKit-macOS.zsh`,
`PackageRuntime-macOS.sh`, `Test-InstallerEntry-macOS.py`, and
`Test-PackageMode-macOS.py`. Both private harness checks run automatically
before signing. Password/PIN rules and archive cryptography remain unchanged
by these changes. `installer-ctime-fix/source-start.json` again binds
1,320 source inputs. The new build runs in
`installer-ctime-fix/corrected-developer-id-build.log` and resumed after the
new Apple acceptance. Previous PASS results and Apple jobs are not transferred
to this candidate.

The new submission candidate is in `installer-ctime-fix/notary-candidate/`.
Its ZIP has 43,679,426 bytes and SHA-256
`6bd960726f41189635343d5e47f0b509297ca4d17de06eb1038412ac0ba0aa74`.
`submission-input-audit.json` confirms version 5.0.2, Build 13 for all three
apps, the 20 root objects, 19 Mach-O files, 38 universal slices, and the match
between package and ZIP. The record has SHA-256
`92b208729a15a23d3a5001b5db16d73ea9408b61ee850c05ee8382f96b1191b6`.
This input check is not Apple notarization acceptance and replaces neither
the final hybrid inventory nor later ticket validation.
`installer-ctime-fix/source-before-notary.json` confirms all 1,320 source
inputs with `matchesPrevious = true` and no changes. Complete original copies
for the Xcode comparison are preserved with 332 entries.

Apple accepted this submission under job
`de8618c3-7404-4b7f-b35e-591fd5fd92c2` with `Accepted`, `statusCode = 0`,
and `issues = null`. The service record
`installer-ctime-fix/notary-candidate/notary-direct-service-log.json` has
SHA-256 `3fb3e3a2dfaab7b0f15f9321a07a6effe887ef866f826367c5389efa628ffc1d`.
`installer-ctime-fix/apple-submission-bound-audit.json` binds acceptance to
the original submission ZIP and all 38 original slices; the 76 raw Apple
lines yield 38 unique path/architecture mappings.
`installer-ctime-fix/source-after-apple.json` confirms 1,320 unchanged source
inputs with `matchesPrevious = true` and no changes.

The confirmation `NOTARIZED` was supplied to the waiting build exactly once.
Stapling, `stapler validate`, and Gatekeeper acceptance for Keep Vault,
QR-Scanner, and Keep Vault Installer pass in the new build log. The new full
test run passes 153 of 153 groups, zero errors, and zero blocked groups.
Overall runtime is 396.2 seconds; aggregate group time is 910.3 seconds.
The record
`installer-ctime-fix/corrected-developer-id-results/001-test-results.json`
has SHA-256
`b7f068c25e9be40612fa869b2b88437dbf21f267ad5c6c3cf52924b522c89a6f`.
All six additional individual checks pass: production worker equality,
parallel MAC-KAT, v12/KPAR2 round trip, KPAR2 worker equality, physical EIO
repair, and the complete ZPAQ matrix. The three production measurements also
pass: performance matrix 196.1 seconds, 256 MiB Paranoia 81.8 seconds, and
complex Paranoia tree 75.4 seconds of test time. The complex run processes
18 files, 20 directories, and 221,327,790 input bytes and repairs one damaged
unit. Results are in `015-test-results.json`, `017-test-results.json`, and
`019-test-results.json` in the new results directory. The build is complete
with exit code 0.

The final release ZIP is 43,685,318 bytes and has SHA-256
`c4f069e0091259a0c6a1f76d880879facec689625b059e5d5659b70e5af112e1`.
`installer-ctime-fix/final-notarized-package-audit.json` confirms all
38 unchanged original slices. Compared with the submission, only three ticket
files and the six manifest files change. The record has SHA-256
`07ede9cf135b55f11490118c14ac20b00ce3e54566fd05d8567e9e36503b43be`.
`final-native-installation-verifier.json` confirms, using the actual native
verifier, `verify-installation` with 149 entries and `verify-artifact` with
all sidecars per architecture: four calls, all exit code 0. The x86_64 calls
run through Rosetta and are not a separate Intel Mac test.
`final-release-assets.json` binds the six final filenames, sizes, and SHA-256
values; the record's SHA-256 is
`194d33bbeead75bfca0b6a49f8312616468b7e9ae466c705274c73b1845454df`.
`published-dist-assets.json` confirms their byte equality with the local
`dist/Keep Vault-macOS`; this is not yet a GitHub upload.
`source-after-build-independent.json` confirms all 1,320 unchanged source
inputs, `matchesPrevious = true`, and no changes.

The repeated actual GUI negative checks of the new signed installer pass:
canceling the start dialog, rejecting an incomplete package before
authentication, and canceling folder selection. After every case, all 129
checked installed entries remain unchanged, including bytes, ctime, and
inodes. `installer-ctime-fix/gui-installer-negative-cases.json` has SHA-256
`89f8dec05f53ebf4417dafd776bbdab8dc01412876c5d20ecff3f8e07553f51c`.
The associated records are `gui-cancel-initial-after.json`,
`gui-incomplete-after.json`, and `gui-cancel-folder-after.json`. The German
window for an incomplete package is fully readable in the screenshot without
clipped text, including OK. Cancellation of the administrator dialog or actual
App Translocation is not established by this. The first normal installer
process under PID 34713 has ended without an observed successful completion.
The subsequent state record
`installer-ctime-fix/gui-normal-resume-state.json` confirms 129 fully unchanged
entries. `gui-normal-resumed-start.json` documents the new normal launch under
PID 37155 initially before local macOS authentication. After local confirmation,
the actual window “Installation abgeschlossen. Keep Vault und QR-Scanner sind
unter Programme installiert.” (“Installation complete. Keep Vault and QR-Scanner
are installed in Applications.”) was observed through AX and a screenshot under
the same PID. The full text is visible without clipping; OK closes the dialog.
`gui-normal-success.json` has SHA-256
`449f1ef2e9e3e59010608d48cdcf643c025f2545d8c00925759c2df2ae3f820e`.
`gui-normal-installed-audit.json` subsequently confirms both complete app trees
at version 5.0.2, Build 13, all ten external sidecars, and the root-owned v12
ZPAQ anchor are byte-identical to the current final package. The installation
record has SHA-256
`1467f14ccce2b8af598c10d78642f8aa807068b37b893eb67602b7bff7d3bddf`.
Physically, only the canonical main app is installed in the checked Applications
folders; 21 additional LaunchServices registrations remain a separate pending
cleanup task at this point.

The separately launched actual installer under PID 46797 also passes after
selection of the complete final package folder and local authentication.
The short “Installation abgeschlossen” (“Installation complete”) window is
fully visible through AX and a screenshot; OK closes the dialog.
`gui-fallback-success.json` has SHA-256
`151fcdf95353ff18f1253c23222562f58ab0d6b6e3dfb4143a4880d6f58241eb`.
`gui-fallback-installed-audit.json` has SHA-256
`50683668f16e00de8bc791e6edc7d6b149e94003911e27cadc69912155cf416c`
and again confirms both apps, ten sidecars, and the root-owned ZPAQ anchor are
byte-identical to the final package. This establishes actual folder selection,
not App Translocation triggered by the operating system.

The actually installed main app under PID 56850 passes the final visual GUI
check through AX and screenshots in German and English. Version 5.0.2 appears
below the fully readable subtitle, the PIN hint and archive path placeholder
are localized, and integrity verification succeeds in both languages.
Afterward, German is restored and the app is exited with Command-Q.
`gui-main-final-de-en.json` has SHA-256
`8e0c71f6050c622bbf8b327833c43fa4c218d6def7c97c133fb0218c11e96a2c`.
This is a final GUI smoke test; the earlier complete archive, extraction,
printing, QR, and erasure records remain separate evidence for the respective
product functions, which have remained unchanged since then.

After the GUI checks, only the 21 additional main app registrations at
previously checked build, audit, dist, temporary, and Trash paths belonging
to the project were selectively deregistered. The canonical
`/Applications/Keep Vault.app` was registered. `final-registration-cleanup.json`
documents the actions without a global LaunchServices reset, app deletion,
or changes to QR-Scanner/Whisper registrations. `final-registration-after.json`
confirms exactly one canonical main app registration and zero additional
entries; SHA-256
`49271f5a0fa7832bd167a0c4b8c47108c8085d2a2d6276e5d1b66af8c2804934`.
`final-physical-app-inventory.json` checks all 82 immediate `.app` bundles
in `/Applications` and `~/Applications` independently of their display names,
reads all Info.plists without errors, and finds exactly one Keep Vault main
app: `/Applications/Keep Vault.app`, version 5.0.2, Build 13. The record has
SHA-256
`84665a7bd1d8e8947c6cd59ade4c6cb2a8c378f15777f28837a3efc3fcb80cc1`.

The full offline production run has now passed and is documented separately
from the GUI in the following section. The final installed complex test has
now also passed; its final records follow the offline evidence. Public release
follows as a separate Git/upload step. The submission ZIP hash must not be
reported as the hash of the stapled release ZIP. Both hashes and their
independent package/asset binding are documented separately above.

## Clarification of the offline evidence

Complete offline functionality remains mandatory. Section 3.2 of the user
document “Keep Vault: Sicherheitsmodell für PINs und Passwörter” (“Keep Vault:
Security model for PINs and passwords”) requires offline use, including first
launch, archiving, and extraction; section 6 requires complete workflows with
the network blocked and without preparatory model downloads. The appendix
does not mandate a particular form of GUI execution for this offline
cross-check. The earlier version of our
[credential contract](KEEP_VAULT_V12_CREDENTIAL_POLICY.en.md) connected the actual
GUI and the offline end-to-end check more closely.

The evidence is therefore separated precisely: actual GUI archiving and
extraction, a separate GUI first-launch/selection check with networking blocked,
and a full production core round trip in a fresh process without an external
network connection. The core run must execute the unchanged creation rules,
compression, encryption, KPAR2 creation and repair, authentication, decryption,
extraction, and a complete structure, size, and SHA-256 comparison. It uses the
frozen production sources, exclusively locally bundled models, and signed
native bytes from the final installation. Fresh preparation of the SDK and
NuGet is for the test build; it does not replace model data and is not a runtime
download by the app. External networking must remain disconnected from before
the fresh test process starts until it ends, with positive connection controls
before and after. Restoring networking prematurely invalidates the offline
evidence.

This offline core run passed under
`installer-ctime-fix/offline-e2e-prepared/run-xdf2p6l8/`. After a fresh
restore, build, and staging of the installed signed native bytes, the private
runner paused only before the functional process started. With Wi-Fi `en0`
disabled, the fresh test process starts and passes
`performance.paranoia-complex-tree-e2e` with exit code 0 in 79.562 seconds.
It processes 18 files, 20 directories, and 221,327,790 input bytes with
compression level 5 and the full Paranoia Argon2id profile. One damaged KPAR2
unit is repaired with authentication; the restored container hash and the
complete directory, path, size, and file hash sets match. The test samples
for factor generation are synthetic and are not identified as human entropy.

77 periodic measurements during the run check Wi-Fi state, interfaces,
IPv4/IPv6 routes, and numeric TCP connection probes. The network is also
disconnected after the process ends and before restoration. Positive IPv4/IPv6
controls pass immediately beforehand and after restoration. The independent
watchdog confirms Wi-Fi is reenabled and did not trigger prematurely. This is
not a packet capture and does not rule out an unobserved brief change between
measurement points. `result.json` has SHA-256
`1c15da13a461236e81eaab8ab9bc683c3cc042503c3a84701a752ff3b44d400d`;
`test-evidence/results.json` has SHA-256
`a867862a50b2596a9686035282ee7dd5f388b29a2300962d2db40dd8aff482cb`.

The independent read-only follow-up audit `offline-e2e-independent-audit.json`
passes with 2,814 checks. It independently evaluates the raw data: 79 offline
snapshots in total with 316 numeric TCP cross-checks, including one probe
before the start and one after the end. The observed offline interval is
81.457 seconds; the largest gap between measurement points is 1.154 seconds.
The record has SHA-256
`0352950c7de112e2afb4adbaed1897160354bbd1a3472d4caafe1e5361f4ea64`.
The observed Python monotonic values are not comparable across processes;
the follow-up audit uses UTC ordering for that purpose and additionally
confirms the interval using the same orchestrator clock. The unreliable
cross-process deadline comparison of the private pause hook is not counted
as a substantive safeguard. Orchestrator and watchdog each use their own
clock and time limit.

This establishes the full fresh offline production core run, not a full
observed offline GUI round trip. The actual GUI evidence remains independently
valid. This clarification concerns test methodology and weakens neither
product functionality, password/PIN rules, nor the offline requirement.
The failed external Seatbelt attempt remains documented as a separate audit
profile finding; the product's internal ZPAQ sandbox is not disabled.

## Last functional execution against the final installation

After all GUI, installation, offline, and registration work, the unchanged
regular launcher `tools/Test-KeepVault.sh` runs with a fresh verified SDK,
fresh restore/build, and the exact installed signed native bytes:
`KEEPVAULT_TEST_RELEASE_ROOT=/Applications`,
`--performance --only performance.paranoia-complex-tree-e2e --parallel 1`.
The run passes with exit code 0, one of one groups, zero errors, and zero
blocked groups in 70.532 seconds. With Paranoia, compression level 5, and full
production Argon2id, 18 files, 20 directories, and 221,327,790 bytes are
archived, one damaged KPAR2 unit is repaired, and data is decrypted and
extracted. Directory structure, paths, sizes, and SHA-256 match completely.
Here too, the test samples for factor generation are synthetic and are not
claimed to be human entropy.

`final-installed-test-summary.json` has SHA-256
`a0b750d8fce5ba12cbc76706bd5e2e6686b9abfd3df4ed4ecef8b20f4852268e`.
`final-installed-test-evidence/results.json` has SHA-256
`905fff24578fa1db1ae3ae0019c712b5705429f644e386bfdf85d9a37fb28f96`.
The complete log is `final-installed-complex-paranoia.log`.
`source-after-last-functional.json` confirms 1,320 unchanged inputs,
`matchesPrevious = true`, and no changes. The subsequent purely read-only
check `final-after-last-test-readonly.json` passes: installed app trees,
sidecars, and the root-owned ZPAQ anchor still match the final package; only
the canonical main app is installed and registered, zero additional
registrations. Only documentation, non-modifying source/package/Git checks,
commit, tag, and publication of the same artifacts follow afterward.

## Technical acceptance and release preparation

| Check | Status |
| --- | --- |
| Fresh test build and integrated test set | new de8618 candidate passed 153/153, 396.2 s overall runtime, 910.3 s aggregate, 0 errors, 0 blocked; earlier c4d7 GUI failure remains historical |
| DE/EN GUI, minimum size, and selection rules under the external network block | earlier version/rule windows and negative selection cases checked; final installed GUI PID 56850 passes DE/EN version, PIN 6–16, integrity, and archive path placeholder; German then restored and app exited |
| Full offline production run from a fresh process with local model data | passed in 79.562 s: 18 files, 20 directories, 221,327,790 bytes, and one KPAR2 repair; 77 periodic offline measurements, positive IPv4/IPv6 controls before/after, Wi-Fi restored, watchdog did not trigger; separate core/GUI evidence, no offline GUI claim |
| GUI extraction without archiving selection rules | empty inputs and unchanged 262-code-unit password with 17-digit PIN passed byte-for-byte on frozen fixtures |
| New GUI test archive, extraction, and complete structure/data comparison | passed in the Development candidate without an additional external audit profile; five files, 15 directories, 34,832,501 bytes |
| Verified original deletion in the new GUI archive run | five files removed after integrated byte comparison; directories and separate control file unchanged |
| PDF output from the discarded first factor generation | four pages and six QR codes passed; no archive or paper-printing evidence |
| Direct paper printing through Keep Vault for the new successful test archive | both jobs complete; paper output and actual camera recognition/copying of printed factor A confirmed |
| Cryptographic erasure through the GUI | negative cases and copy erasure passed with unchanged originals; corrected completion status under PID 34669 persisted after OK and DE/EN/DE, new path resets status and confirmation; all four path placeholders visibly passed in DE/EN |
| Revised DE/EN key sheets with version number, three password lines, and PIN notice | four actual service PDFs generated, eight pages visually checked; corrected design explicitly approved |
| Installation instructions and package contents | new de8618 installer: three actual negative GUI cases passed, 129 installed entries unchanged in each, German package message visually fully readable; actual normal GUI installation PID 37155 passed with a fully readable completion message; both apps, ten sidecars, and root-owned ZPAQ anchor byte-identical to the final package |
| First launch with package files separated by App Translocation | actual GUI negative checks for incomplete folder and folder cancellation passed; separate folder selection does not establish actual App Translocation; normal GUI installation and positive separate folder-selection run PID 46797 passed; actual App Translocation not established |
| Installer directory binding and message presentation | 19 regressions with an effective mutation cross-check, plus 18 presentation cases and synthetic DE/EN GUI passed; actual normal GUI installation and fully readable short completion message passed |
| Additional individual release checks | new de8618 candidate: all six additional individual checks passed |
| Manual cipher and Paranoia production measurements | new de8618 candidate passed: performance matrix 196.1 s, 256 MiB 81.8 s, complex Paranoia tree 75.4 s; 18 files, 20 directories, and one KPAR2 repair |
| Developer ID, Apple Accepted, stapling, Gatekeeper, and byte comparison | new Apple job de8618c3-7404-4b7f-b35e-591fd5fd92c2 Accepted and bound to ZIP and 38 original slices; stapling, Gatekeeper for all three apps, 38 unchanged slices, and six final assets passed; 149 manifest entries and ZIP/sidecars verified on arm64 and x86_64/Rosetta; c4d7 remains historical |
| Final installation and only current Keep Vault registration | both actual installation paths successful; 21 additional registrations belonging to the project selectively removed, then exactly one canonical main app and zero additional registrations; independent scan of all 82 immediate app bundles confirms exactly Keep Vault 5.0.2/13 under /Applications |
| Last complex Paranoia structure/repair run | regular unchanged test launcher, fresh build against final installation, exit 0, 70.532 s, 18 files, 20 directories, 221,327,790 bytes, and one KPAR2 repair; afterward 1,320 sources unchanged and only canonical main app registered |
| Verified commit, tag, upload digests, and public release | to be performed after this completed technical acceptance and confirmed separately; intended release v5.0.2 stable/latest with exactly six verified assets |

After the last functional gate, only non-modifying package/Git checks,
result documentation, and publication of the same artifacts take place.
A product or artifact change requires this gate again.

## Evidential limits

A passing test corpus confirms the checked properties and cases. It proves
neither freedom from defects nor guaranteed entropy of human-chosen secrets.
Source snapshots capture observed file/mode changes; they are not a build
tree made immutable by privileged protection and do not rule out temporary
replacement by the same user. The signed final artifacts are additionally
verified independently.

Windows will be tested later on Windows hardware according to the
[updated porting contract](KEEP_VAULT_V12_WINDOWS_UPDATE.en.md).
macOS results are not a Windows test.

## Public release on 9 September 2026

The stable [GitHub release v5.0.2](https://github.com/michael-feinermann/keep-vault/releases/tag/v5.0.2) was published on 09.09.2026 at 08:16:58 UTC and confirmed as the latest release. It is neither a draft nor a prerelease. The tag continues to resolve to reviewed commit `8df29a9e13eb65c0769666c3835b4cf0b96dad20`.

All six uploaded files were downloaded again and compared byte for byte with the verified originals. The ZIP contains 43,685,318 bytes and has SHA-256 `c4f069e0091259a0c6a1f76d880879facec689625b059e5d5659b70e5af112e1`. Release ID: `385333020`. Apple's acceptance and the functional evidence refer to the unchanged executables documented above.

The subsequent addition of German and English documentation changes neither the release tag nor executable files. It is not a new build or functional test. Historical drafts, in particular 5.0.1, retain their existing publication status. The complete language editions are linked in the [documentation index](README.en.md).
