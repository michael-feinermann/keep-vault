# Keep Vault v12: recheck with GPT-5.6-sol

[Deutsch](KEEP_VAULT_V12_GPT56SOL_RECHECK.md) | English

Historical record of the assignment of 2 September 2026. The following status
statements and assignment boundaries refer to that run at that time. Version
5.0.2 is governed by the current
[macOS release requirements](KEEP_VAULT_V12_MACOS_RELEASE.en.md), the
[password and PIN contract](KEEP_VAULT_V12_CREDENTIAL_POLICY.en.md) and the
[Windows porting assignment](KEEP_VAULT_V12_WINDOWS_UPDATE.en.md) based on them.
These references do not retroactively declare any check open at that time to
have passed. The later technical acceptance of the final macOS 5.0.2 candidate
is documented as complete on 8 September 2026 in the
[current audit report](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md): 153/153 groups,
additional release gates, actual installer/app GUI, complete offline core run
and last regular installed complex test. Public publication and tag assignment
follow separately. The intermediate states in this historical recheck record
are not a contrary current status report.

State of the assignment at that time: 2026-09-02. This audit assignment was
deliberately not a publication assignment. Its run was allowed to build, test,
commit and push, but to create neither a GitHub release nor a public ZIP nor
a notarization publication.

## Later context of 7 September 2026

The original assignment of 2 September and its findings at that time remain
historically unchanged. The later assignment for 5.0.2 explicitly includes the
complete testing, notarization, upload and stable public release run. The
restriction at that time to a nonpublic recheck is therefore not a current
publication block on this assignment. The final DE/EN key-sheet preview with
version number, three password lines, PIN notice and bold field labels has now
been approved with “Sieht gut aus. Setzt das um” (looks good, implement it).
This is not advance technical acceptance of the new release artifact.

Since then, the missing self-contained installation kit has been added to the
product and packaging code: native Installer.app, Universal NativeAOT verifier,
precompiled deletion helper, complete dual-signed inventory and a root-owned
copy that the logged-in user may only read and execute. The code identity
actually running is bound to the active CDHash; all Universal slices are checked
additionally. The final inventory is produced after successful stapling of all
three apps and also binds their local ticket bytes. The target adapter combines
this byte binding with the current Apple distribution policy. Counterchecks
explicitly show that `syspolicy_check distribution` alone does not reliably
reject damaged existing tickets.

Package rollback was aligned with exact restoration of the previously
Apple/hybrid-authenticated old state. Its valid old ticket and version-dependent
notices are not equated with the new 5.0.2 bytes. In addition, an
architecture-specific Darwin stat binding corrects the x86_64 ABI error; ARM64
and Rosetta-x86_64 probes confirm the different exports required. These results
do not demonstrate a run on a separate physical Intel Mac.

The folder picker for package neighbors separated by App Translocation has
now been implemented. It checks exactly 20 package objects with their types
and links; every selected source follows the same protected copying and
authentication path. This later `InstallerMain.swift` state has SHA-256
`74b4e6ecb612a5b81d24569a4ee78a7e4c35453d03a98b540fd7d4a9022bbde1`.
Compilation of both architectures with warnings treated as errors and twelve
filesystem cases each under ARM64 or Rosetta-x86_64 are demonstrated in
`build/audit/5.0.2-20260906/installer-translocation-review/results.json`.
These component checks performed no actual GUI or administrator installation.
The actual installer GUI and first-launch run remain to be checked separately.

The separate Development build in
`build/audit/5.0.2-20260906/approved-installer-development-build.log` ended with
151 passed groups and one failed group out of 152 in 492.8 seconds. Its
before/after source snapshots bind `InstallerMain.swift` to
`fbe13c7ea165e7d4f860b422dbf711c18a05870d1ce4511237ac7ae326861406`,
thus still without the later folder picker. The failed group
`packaging.hybrid-key-separation` contained an outdated expectation of SDK/
`xcrun` lookup in the deliberately SDK-free metadata verifier. This assumption
has been corrected to fixed system tools without `xcrun`; the real hostile
`PATH` probe remains. The targeted follow-up of the group passed with 1 of
1 groups in 79.0 seconds. Result evidence
`build/audit/5.0.2-20260906/sdk-free-metadata-targeted-evidence/results.json`
has SHA-256 `b0bde7f61f03e712cf26e1d6478c2d791f0f7784629dfcf261cc3ca1debd1de6`.
This follow-up does not replace a complete new test run. Historical 152/152
results are not transferred to these new sources.

The actual app GUI with PID 81532, version 5.0.2 and Build 13 confirms the
DE/EN version display and language switching of analysis/rejection statuses.
The selected container/KPAR2 copies were deleted; the original container,
original KPAR2 file and control file remained unchanged. The German success
dialog, cleared path and reset confirmation were also confirmed. Afterwards,
however, a delayed `TextChanged` overwrites the completion status with
`eraseNotAnalyzed`. This specific GUI finding is in
`build/audit/5.0.2-20260906/approved-layout-gui-first-erase-result.json`.
A minimal fix and the new group `gui.erase-completion-status` are implemented;
153 groups are therefore expected. The freshly built targeted run
`Test-KeepVault --category GUI --parallel 1` subsequently passed with 24/24
groups in 21.2 seconds. The new status group passed in 1.390 seconds. Before
the run, 1319 source inputs were bound in
`build/audit/5.0.2-20260906/gui-fixes-source-before.json`; the result evidence
is `gui-fixes-targeted-evidence/results.json` in the same audit directory,
SHA-256 `b92cb9e4d435a3bf5449d28bb49f878aa12f7810600f41da78e0bd8cff8c3922`.
The Development run subsequently started with 153 expected groups was
interrupted by a Mac restart on 7 September 2026 at around 14:04. The attempt
is recorded in `final-gui-development-build.log`, but produced no JSON result
and does not count as passed. The subsequent rerun in
`restart-development-build.log` passes with 153 of 153 groups, zero failures
and zero blocked groups in 405.4 seconds; the summed group runtime is 921.4
seconds. `restart-development-results/001-test-results.json` has SHA-256
`343a5bac41eda92892e1958a1c0e40acc3d0a548c96883ef820f69a763cbd049`.
All 1,319 source inputs match before and after the run; the installed Development
app is byte-identical to the freshly built bundle. The new package passes
verification of 20 root objects, 19 Mach-O files and 38 slices. Both NativeAOT
slices successfully performed the authenticated manifest verification, ARM64
natively and x86_64 under Rosetta. The evidence files are
`restart-development-kit-audit.json` and
`restart-development-native-aot-architectures.json` in the audit directory.

The visible GUI retest from 15:19:35 under PID 34669 confirms the version
display beneath the subtitle and all four path placeholders in DE/EN for 5.0.2,
Build 13. After actual cryptographic erasure of the test copies, the completion
status persists after OK and DE/EN/DE. The original container, original KPAR2
and control file remain unchanged; a new path resets status and confirmation.
The app was then closed with Cmd-Q. `gui-completion-retest-result.json`
documents this check. The regression must be independently tested during the
later Windows port, including delayed events, language switching and selecting
a new path. This macOS evidence replaces neither that check nor a separate
Intel hardware test.

The subsequent Apple acceptance of the final Developer ID candidate is
demonstrated: job `672ab61e-4909-4fe9-a9e2-1685ea774e09`, `Accepted`,
`statusCode = 0`, `issues = null`. All three apps pass stapling,
`stapler validate` and Gatekeeper. The original submission is bound to all 38
architecture signatures; the 76 raw Apple lines are fully explained by bundle
aliases and duplicates. The final package comparison passes with 20 root
objects, 19 Mach-O files and 38 unchanged slices. It reports only three new
ticket files and six renewed manifest/signature files. Actual hybrid inventory
verification passes with 149 entries on ARM64 and under Rosetta-x86_64.

The six prepared release assets include the ZIP of 43,678,062 bytes and
SHA-256 `cac58f018ab60734e4565aea601d590e390d6640419eabe41e62a66f8e9c7484`.
Evidence is in `final-release-assets.json`, `final-notarized-package-audit.json`
and `final-native-installation-verifier.json`; the original Apple submission
and service log are bound separately in the current 5.0.2 audit. The 1,319
source inputs remain unchanged. App installation and authentication for the
root ZPAQ anchor are complete. The complete test run of the notarized Developer
ID candidate passes with 153 of 153 groups in 405.5 seconds, with no failures
or blocked groups; the summed group runtime is 918.9 seconds.
`final-developer-id-results/001-test-results.json` has SHA-256
`8ec5a2d0a5b28c5b40f3e0ba7054cea27c46bb99c4b25a1a3e26c3e44c1db93d`.
The additional individual release checks for production workers, parallel MAC
KAT, v12/KPAR2 roundtrip, KPAR2 workers, physical EIO repair and complete ZPAQ
matrix also pass. The performance matrix of all ten cipher suites passes in
195.0 seconds, the 256-MiB Paranoia run in 75.4 seconds and the complex Paranoia
run with KPAR2 repair in 73.7 seconds. Result files `015`, `017` and `019`
with the suffix `-test-results.json` and their SHA-256 values are in the
current audit. The release build of 7 September 2026 is complete; the final
artifacts are under `dist/Keep Vault-macOS/`. The actual native installer GUI
run, the last complex run after final installation and stable publication are
still open. The final 5.0.2 commit, tag and upload comparison are also pending.

The subsequent actual native installer GUI test on 8 September 2026 failed
because of the codesign argument form. The form `-R` with separated requirement
text refers to a file; requirement text needs `-R=<Anforderungstext>`.
The installer aborted at this check. The previously tested, signed and
Apple-accepted candidate is therefore superseded and not approved for
publication. Its PASS results remain historically demonstrated. The correction
requires signing and notarization again, complete release checks, the actual
installer GUI retest and the last complex run after final installation.

The subsequent corrections are implemented: codesign requirement as a text
argument, account name with system-side UID reverse checking instead of numeric
UID text for ACLs, ACL assignment before policy checking and native execution,
and signature verification from held bytes instead of reopening through
`/dev/fd`. Existing signature and identity checks are retained. The real
codesign/ACL counterchecks and 15 signature regressions pass. Newly built
NativeAOT verifiers pass on ARM64 and under Rosetta against the same unchanged
old root/ACL intermediate copy where the old verifier aborts with an access
error. This targeted comparison does not demonstrate a new complete installer
run.

`build/audit/5.0.2-20260908/correction-source-delta.json` reports nine changed
source/test/build paths and 1,320 frozen source inputs. Password/PIN rules and
archive cryptography remain unchanged. The entry-point test is automatically
required before signing during package construction;
`installer-entry-release-gate.log` passes. The new Developer ID build runs in
`corrected-developer-id-build.log`. The corrected submission has now been
accepted by Apple under job `c4d7f3a5-3a54-4954-af83-d003bc194824` with
`Accepted`, `statusCode = 0` and `issues = null`. Its original ZIP has SHA-256
`72de4c27b7271fa264447d535826afb425f5c7ce0c5a07538eb25113478ac76b`.
All 38 original architecture signatures are bound;
`source-after-apple.json` confirms 1,320 unchanged source inputs. Stapling,
ticket validation and Gatekeeper acceptance for all three corrected apps now
pass. The final package comparison confirms 20 root objects, 19 Mach-O files
and 38 unchanged slices. Hybrid verification of the inventory with 149 entries
and of the ZIP with all sidecars passes on ARM64 and under Rosetta. The final
ZIP of 43,681,703 bytes has SHA-256
`820863042b5cfacb6643b1696c8fbf8412c9529d82d921d3bb7174db3dedf81d`.
`final-release-assets.json` binds exactly six new files.

The corrected notarized candidate passes with 153 of 153 test groups in 410.1
seconds, with no failures or blocked groups; the summed group runtime is 932.8
seconds. Evidence
`corrected-developer-id-results-resumed/001-test-results.json` has SHA-256
`c9ddc29c752b5c451fd6e1a9d4c30770a368b248463ddcd6c157f34746f58147`.
All additional individual release checks and manual production measurements
have now passed: test times of 194.6 seconds for the performance matrix,
81.6 seconds for 256-MiB Paranoia and 78.3 seconds for the complex Paranoia tree
with KPAR2 repair; total runtimes 194.7, 81.7 and 78.4 seconds. The complex run
comprises 18 files, 20 directories and 221,327,790 input bytes and repairs one
damaged unit. The corrected release build is finished with exit code 0; all
20 result/timing files agree with the index. `source-after-build.json`
confirms 1,320 unchanged source inputs; `published-dist-assets.json` confirms
that all six locally provided files are byte-identical to the privately secured
final assets. The actual GUI counterchecks for startup-dialog cancellation,
an incomplete package and folder-picker cancellation have now passed. All 129
checked entries of the installed apps, sidecars and root anchor retain
identical bytes, metadata and inodes after each case; atime is excluded.
`gui-installer-negative-cases.json` and the three post-comparisons demonstrate
this. Cancellation of the macOS administrator dialog is not tested; the
separate folder picker is not evidence of actual App Translocation. Normal
installation of the complete kit under PID 9073 subsequently failed at a false
identity rejection. The following correction requires a new build and its own
release evidence. Old PASS results and Apple jobs are not transferred to the
candidate changed again.

Targeted component, negative, ABI and private rollback checks, and compilation
of both installer entry-point slices, are documented. The complete current
build/GUI/installation run, the last complex Paranoia run and stable public
publication are complete only with their new artifacts and results. Current
evidence and open issues are in the
[5.0.2 audit report](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md). The immutable
installation copy is not retroactive proof for the separate historical finding
on securing the build source tree.

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
and archive cryptography remain unchanged. 1,320 source inputs are frozen for
the repeated build in `build/audit/5.0.2-20260908/installer-ctime-fix/` and
confirmed unchanged before notarization. The new submission candidate is
prepared: ZIP of 43,679,426 bytes, SHA-256
`6bd960726f41189635343d5e47f0b509297ca4d17de06eb1038412ac0ba0aa74`.
`notary-candidate/submission-input-audit.json` confirms 5.0.2, Build 13 for all
three apps, 20 root objects, 19 Mach-O files and 38 slices. Apple has now
accepted this submission under job `de8618c3-7404-4b7f-b35e-591fd5fd92c2` with
`Accepted`, `statusCode = 0` and `issues = null`. The Apple service evidence has
SHA-256 `3fb3e3a2dfaab7b0f15f9321a07a6effe887ef866f826367c5389efa628ffc1d`;
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
repair. The build finished with exit code 0.

The three repeated actual GUI counterchecks of the new signed installer pass:
startup-dialog cancellation, an incomplete package before authentication and
folder-picker cancellation. All 129 checked installed entries remain unchanged
after each case, including bytes, ctime and inodes. The German package error
message is fully readable in the screenshot.
`installer-ctime-fix/gui-installer-negative-cases.json` and its three state
comparisons demonstrate this. Administrator cancellation and actual App
Translocation are not demonstrated by these checks. Normal installation under
PID 34713 is waiting for local macOS authentication. Its successful completion,
the last installed complex test and public release remain pending. Individual
evidence and limitations are in the
[current macOS audit report](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md).

## Purpose of the original recheck

GPT-5.6-sol is to independently reread the complete v12 source tree and confirm
the following points with reproducible results. A roundtrip alone does not
count as independent evidence for cryptographic changes. Every primitive
change requires a known-answer test against a second implementation.

## Mandatory rechecks

| Area | Evidence that must be produced again | Status of this run |
| --- | --- | --- |
| v12 boundary | No v11 reader, no migration, no old magic/KDF/KPAR2 paths; all parsers reject older versions | confirmed by `spec.no-legacy-source` and `spec.normative-v12-docs` |
| Kalyna | Licensed source, v12 export list, scalar and parallel KATs, in-place/zero-length/counter boundaries, create and join failure KAT | Native-slice KATs passed for arm64 and x86_64; deterministic create-failure KAT remains open |
| Threefish | Reference vectors, parallel CTR against scalar countercheck, completion lifetime on create/join failure, Windows path | Native-slice KATs and create/join coverage available; ASan/TSan run remains open |
| Argon2id | PHC and independent Bouncy Castle comparison; immutable `t=4`, `p=4`; all workers safely completed on create/join failure | Lifecycle fix compiles and low-memory KAT passed; deterministic fault-injection KAT remains open |
| Poly1305 | RFC-8439 KAT, parallel and serial byte comparison including tail, overflow and error paths, no buffer reuse before workers end | Native parallel KATs including 256-MiB run passed; fresh trusted release-sidecar run remains open |
| Container pipeline | Archiving, compression, encryption, decryption and extraction bounded and parallel; authentication before plaintext output | Implementation and worker equivalence available; complete release suite blocked by missing root anchor or trusted test artifacts |
| Integrity/KPAR2 | SHA3/Skein leaves, KPAR2-v4 RS(20.3), dual authentication and deterministic error aggregation checked in parallel | KPAR2-v4 KATs passed; complete container/recovery suite open because of the same artifact and root-anchor gates |
| ZPAQ | v12 streaming, `--` argument boundary, FD/environment inheritance, Seatbelt/containment, kill/join and normative 6-GiB budget | Process resource, CPU and stall gates passed; root anchor and complete matrix remain open |
| Source TOCTOU | Build/packaging from a privileged-anchored, immutable commit/tree snapshot; no live-repository fallback; ABA, detach and mount-swap negative tests | release-blocking, still open |
| Secrets | No private keys, passwords or Keychain output in argv, logs, temporary artifacts or Git; only Keychain prompts with “Erlauben” (Allow) | USB public-key comparison and PFX file check passed; protective ACLs verified; no secrets logged |
| Toolchain | Pinned .NET-10 SDK, locked restore, native compiler/linker flags, license and provenance manifest unchanged relative to the checked commit | Native arm64/x86_64/Universal builds, locked-restore gate and tool-path self-tests passed |
| Release verifier | Every EXE, DLL, manifest, ZIP and companion artifact verified in a fresh destination directory; deliberate mutation is blocked | Prepared nonpublicly; complete trusted app/sidecar run remains open because of the missing root anchor |

## Execution record 2026-09-02

The run took place on real Apple hardware. Host data: Apple Silicon `arm64`,
macOS `26.6.2` (Build `25G83`), Xcode `26.6` (Build `17F113`), Clang `21.0.0`,
ten logical processors. The checked starting point was `master` at commit
`26cd3fba4bcb0b233d65009377a9e350c50663f6`; the changes from this run had not
yet been committed at that time.

After the checks were complete, the checked v12 state was pushed to
`origin/master` as commit `0dd3acc0e8e4254d345bfd9d9a6b487f8a0dbc19` with
tree hash `404c2fa03983db73b69ccecc8bf534befa84ee6d`.

Executed gates and results:

| Command or test ID | Result | Artifact or note |
| --- | --- | --- |
| `./tools/Build-Native-macOS.sh` | PASS | arm64, x86_64 and Universal; native Mach-O outputs created |
| `NativeKats.c` for each slice | PASS | `Native per-slice cryptographic KATs passed` for arm64 and x86_64 |
| `./tools/Build-Native-macOS.sh --verify-sources` | PASS | Manifest with 431 sources |
| `./tools/Build-Native-macOS.sh --self-test-atomic-publish` | PASS | Preflight failure, hard-link protection and atomic replacement passed |
| `./tools/Build-KeepVault-macOS.sh --tool-path-self-test` | PASS | Release tool paths verified |
| `./tools/Provision-VerifiedDotnet-macOS.sh --tool-path-self-test` | PASS | Pinned .NET-10 path verified (`10.0.400` in the provisioner) |
| `./tools/Stage-TestNatives-macOS.sh --tool-path-self-test` | PASS | Test-native staging paths verified |
| `./tools/Protect-HybridKeys-macOS.sh --verify-only` | PASS | Both Keychain ACLs and separate wrapping roles verified |
| `spec.no-legacy-source` | PASS | `/private/tmp/keep-vault-test-runner.S8hQD8lG/artifacts/bin/KeepVaultMac.Tests/release_osx-arm64/.test-results.json` |
| `spec.normative-v12-docs` | PASS | `/private/tmp/keep-vault-test-runner.aaYaKEDN/artifacts/bin/KeepVaultMac.Tests/release_osx-arm64/.test-results.json` |
| `packaging.keychain-secret-not-in-argv` | PASS | `/private/tmp/keep-vault-test-runner.B08SE34D/artifacts/bin/KeepVaultMac.Tests/release_osx-arm64/.test-results.json` |
| `zpaq.process-resource-limits` | PASS | CPU, RSS, wall-time, process-count and stall gates passed |
| `./tools/Test-KeepVault.sh --full --no-smoke --parallel 2` | 51 PASS, 50 FAIL | Result tree `/private/tmp/keep-vault-test-runner.Etk0mTNo/artifacts/bin/KeepVaultMac.Tests/release_osx-arm64/.test-results.json`; the 50 failures are missing signed sidecars, a missing final `dist` state or the deliberately required root-owned ZPAQ-v12 anchor, not silently skipped tests |

After evaluation, the complete result tree of the last run was archived
recoverably at
`/Users/michael/.Trash/keepvault-full-run.LCaUD8/keep-vault-test-runner.Etk0mTNo`.
Nothing was permanently deleted.

The USB drive was used exclusively for direct, in-memory authentication.
The ML-DSA public-key comparison succeeded (`usb_mldsa_public_match=true`),
and the PFX file was a regular protected file. Private keys, passwords and
Keychain contents were neither displayed nor copied into the repository.
The deliberately prompt-only Keychain ACLs were not weakened.

The performance and end-to-end gates `performance.cipher-suites`,
`performance.paranoia-256mib-e2e` and `performance.paranoia-complex-tree-e2e`
could not be executed as release evidence in this nonpublic run: before they
start, the test environment rejects the untrusted native libraries or those
without sidecar signatures and the missing root-owned ZPAQ anchor. No speed
values are therefore reported as measured.

## Mandatory runs on real Apple hardware

Results must be recorded with host, macOS version, architecture, commit/tree
hash, toolchain, worker limit, duration and exit code:

1. All smoke and comprehensive groups.
2. All ten cipher/cascade measurements with the same input data and reproducible
   warm-up/median rules.
3. The exact 256-MiB run with compression level 5, Paranoia and complete Argon2id.
4. As the last functional run, a complicated folder tree with empty, very small,
   large, random and highly compressible files, Unicode names and deep
   directories. No further functional mutation of the checked source state
   before the commit after this run.

## Security decision

Until the build uses an immutable source snapshot anchored against the same
user, GPT-5.6-sol must not present any public release as reproducible or secure.
The same applies to an open Argon2 worker lifecycle error or missing Poly1305
KATs. The decision must be recorded as “Release blockiert” (release blocked)
with source location and test command, and must not be bypassed through a
weakened test selection.

## Completion format

The recheck result contains:

* the checked commit and tree hash,
* every executed test ID with result and artifact path,
* all open findings with priority, file/line and reproducible command,
* a clear decision of `bereit für separates Release-Gate` (ready for a separate
  release gate) or `Release blockiert` (release blocked).

Private keys and app-specific passwords do not belong in this record.
