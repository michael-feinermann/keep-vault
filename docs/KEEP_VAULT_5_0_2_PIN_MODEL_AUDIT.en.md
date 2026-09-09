# Keep Vault 5.0.2: PIN model and acceptance set

[Deutsch](KEEP_VAULT_5_0_2_PIN_MODEL_AUDIT.md) | English

As of September 6, 2026. Model version `keep-vault-pin-patterns-2026-09-v1`. These rules apply to archiving. They provide no empirical guessing trials, no entropy assurance for human choices, and no additional bit threshold.

Technical macOS acceptance of the final 5.0.2 candidate was completed on
September 8, 2026. The [macOS audit report](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md)
separates source/policy evidence, GUI checks actually performed, the
offline core run, and the final installed complex test from the
subsequent public release.

## Rules and technical limit

All previous rules, including the entire blocklist, remain unchanged. New hard rules cover the complete PIN as a literal substring of the unchanged password, the four formats of today's date, and complete plausible dates. Missing or still syntactically incomplete inputs do not confirm a pair. The local current date is captured again at the final call; the test interface allows a fixed date without changing the global clock.

The additional model detects complete cyclic digit sequences, longer repetition periods, periodic constructions with a different final digit, palindromes, concatenated years, and date/year combinations. The curated list of constants contains the first 16 digits, including the integer part, of pi, e, the golden ratio, and the square root of 2. Telephone and numeric keypads have separate zero positions; only complete adjacent-key paths with at most two direction changes match. Arbitrary adjacent-key paths or individual date segments alone do not block a long PIN. These are documented product heuristics, not calibrated attack ranks.

The date model checks valid calendar days, including leap years, in `DDMMYY`, `MMDDYY`, `YYMMDD`, `DDMMYYYY`, `MMDDYYYY`, and `YYYYMMDD`. The fixed model range is 1900 to 2056. For two-digit years, both the 1900 and 2000 centuries are checked within this range. Ambiguous values count as a date as soon as one of these interpretations is valid. The independent block on today's date uses exactly `DDMMYY`, `DDMMYYYY`, `MMDDYY`, and `MMDDYYYY`, exclusively as a complete value.

KDF input validation allows up to 1,048,576 UTF-16 code units per secret. It requires neither the previous nor the new selection rules. The PIN remains a sequence of ASCII digits; no normalization or new Unicode requirements are introduced for the password. Empty strings are technically representable and remain permitted at this level. `ValidatePinSyntax` remains exclusively the historical syntax check for selecting new PINs. The v12 KDF file is unchanged.

## Reproducible acceptance set

Measured with SDK 10.0.400, the fixed date 2026-09-06, and an unchanged password without digits. The pair rule therefore produces no match in this set measurement. Six digits were exhaustively enumerated, including leading zeros. For each length from 7 to 16, 10,000 numeric values were drawn with `Random(0x5020609)` in a specified order. The old checker was taken unchanged from the actual source tree. No value rejected by the old checker was newly accepted anywhere in the entire recorded corpus.

| Digits | Sample size | Accepted under new rules | Previously accepted | New proportion | 95% interval |
|---:|---:|---:|---:|---:|---:|
| 6 | 1,000,000 | 732,438 | 803,723 | 73.2438 % | exact |
| 7 | 10,000 | 8,064 | 8,070 | 80.6400 % | 79.85 to 81.40 % |
| 8 | 10,000 | 7,835 | 7,853 | 78.3500 % | 77.53 to 79.15 % |
| 9 | 10,000 | 7,539 | 7,541 | 75.3900 % | 74.54 to 76.22 % |
| 10 | 10,000 | 7,191 | 7,208 | 71.9100 % | 71.02 to 72.78 % |
| 11 | 10,000 | 6,933 | 6,933 | 69.3300 % | 68.42 to 70.23 % |
| 12 | 10,000 | 6,761 | 6,761 | 67.6100 % | 66.69 to 68.52 % |
| 13 | 10,000 | 6,435 | 6,435 | 64.3500 % | 63.41 to 65.28 % |
| 14 | 10,000 | 6,224 | 6,224 | 62.2400 % | 61.29 to 63.19 % |
| 15 | 10,000 | 5,913 | 5,913 | 59.1300 % | 58.16 to 60.09 % |
| 16 | 10,000 | 5,671 | 5,671 | 56.7100 % | 55.74 to 57.68 % |

The six-digit diversity rule alone permits exactly 932,400 values. Under all previous rules, 803,723 values remain; under the expanded model, 732,438 remain. The additional rules thus exclude another 71,285 complete values.

The sample intervals are Wilson intervals with z = 1.959963984540054 under a model of uniformly distributed numeric draws. They describe only the estimated size of the accepted numeric set. The fixed pseudorandom corpus does not represent a distribution of human choices; acceptance rate, length, or absence of a pattern match does not imply human guessability. Rare additional patterns may be absent from the samples of long values; targeted test vectors check them separately.

## Evidence and limits

The three pure policy test groups pass in the isolated harness: the literal pair rule and pending pair check, local dates/time zones/midnight, patterns, and monotonic preservation of old rejections. Nine previous irregular positive PIN fixtures pass without special-case handling. The separate technical input check is tested up to and including the upper limit of 1,048,576 UTF-16 code units. A fourth integrated test group contains six v12 byte vectors independently calculated with Python hashlib.sha3_512 for empty and short inputs, inputs exceeding the old limits, leading zeros, and different Unicode representations. These four groups already passed in the earlier integrated 5.0.2 repeat run with 152/152 successful full test groups; the subsequently completed notarized Developer ID candidate passes with 153/153. Historical and current results are documented separately in the [macOS audit report](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md).

The targeted final recheck additionally confirms that missing PINs, PINs that are too short or too long, and PINs containing anything other than ASCII digits do not report a completed pair check. When a password is present, this does not produce a misleading message about a missing password. Separately, a syntactically complete PIN rejected on quality grounds remains a fully checked pair. This refinement of status reporting and tests does not change the acceptance set previously enumerated.

An independent source comparison against the completed 5.0.1 state confirms identical previous PIN analysis, password selection validation, and entropy estimation. After removing the additional model call and its result fields, the previous password analysis is also identical. `V12MasterKdf`, `RecoveryService`, `SuiteKeySchedule`, `KdfPrimitives`, `KdfSalts`, and `EncryptionSuite` are byte-identical. Only the technical credential validators are wired into the macOS extraction, listing, and recovery paths; pair and quality validation is at the start of core creation. This static finding establishes the separation in source code, but does not replace integrated evidence with independent KDF vectors and static v12 archives. The later Windows UI port is explicitly documented separately.

The supplementary read-only fixture review confirms all six archive/sidecar hashes, the manifest pin, and the 13 provenance file hashes. Applying the three documented removals of selection checks to commit `e52159e7a569a8b77fe7732006388c4401c4009f` exactly reproduces the private builder source hashes; the two snapshots of the 87 build inputs are identical. All six frozen SHA3 credential vectors additionally match an independent implementation of LE length framing and Python `hashlib.sha3_512`. For SHA3, the builder uses the same digest library as production but its own framing; the Python cross-check therefore provides supplementary independent digest evidence. The Skein oracle uses Bouncy Castle as the counterpart to the native macOS path. The intended integrated read tests check an effective model-access failure, absence of plaintext output on tampering, and exact KPAR2 reconstruction while the damaged source remains unchanged. These tests were not executed in this read-only review; the fixtures come from a private 5.0.1 source snapshot and do not by themselves demonstrate a successful 5.0.2 read or release run.

The isolated harness contains the unchanged new policy file and an automatically extracted PIN section from the current ContainerKeyDerivation.cs. The KDF byte vectors run against the real implementation in the full test project. The isolated run does not replace checks of the GUI, final core wiring, extraction compatibility, or signed release.

Local evidence: `build/audit/5.0.2-20260906/pin-policy/` with `acceptance.json`, source hashes, preservation checks, extracted source code, and an executable console project. Test sources: `KeepVaultMac.Tests/PinCreationPolicyTests.cs`. No HIBP dataset was imported; the small existing numeric blocklist and the documented patterns must not be described as comprehensive breach coverage.


Addendum after the integrated repeat run: All eight credential compatibility groups, including the six frozen archives, pass. The listing, extraction, authentication, and repair properties that were initially only described above have therefore actually been tested under the effective model-access guard. The historical fixture restore included an option that overrides locked mode; an additionally archived strict restore with `RestoreForceEvaluate=false` passes with unchanged lockfiles and 87 source/project inputs.

The final Developer ID candidate now passes 153 of 153 test groups in
405.5 seconds, with no errors or blocked groups.
`final-developer-id-results/001-test-results.json` in the audit directory has
SHA-256 `8ec5a2d0a5b28c5b40f3e0ba7054cea27c46bb99c4b25a1a3e26c3e44c1db93d`.
The additional individual release checks, the performance matrix in
195.0 seconds, the 256 MiB Paranoia run in 75.4 seconds, and the complex
Paranoia run with repair in 73.7 seconds also pass. The local release build
of September 7, 2026 is complete.

The actual DE/EN GUI check of the previous Development candidate confirms
the version display, PIN hint from 6 to 16, all four path placeholders, and
the completion status after deleting the project's own test copies. Apple
notarization of the final candidate is documented by job
`672ab61e-4909-4fe9-a9e2-1685ea774e09`, `Accepted`, `statusCode = 0`, and
`issues = null`. All three apps pass stapling, ticket validation, and
Gatekeeper. The actual native installer GUI run, the last complex run after
final installation, and the public stable release remain pending until
their own evidence is available. These macOS results provide no evidence of
a Windows GUI check or testing on separate Intel hardware.

In the subsequent actual installer GUI test on September 8, 2026, the
installer failed because of the codesign argument form: a separate `-R`
expects a file, whereas requirement text must be passed as
`-R=<Anforderungstext>`. Installation was aborted. The previously tested
and notarized candidate is therefore superseded; its results do not approve
the artifact to be corrected. New signing, notarization, full release checks,
and an actual installer GUI retest were therefore required for the correction
cycle; its current status follows below. This installer finding does not
change the documented password/PIN selection rules.

The installer corrections are now implemented and limited to nine
source/test/build paths. They concern the codesign text argument, ACL
grants bound to the account name, their ordering before native execution,
and signature verification directly from held bytes rather than through
`/dev/fd`. The password/PIN rules and archive cryptography remain unchanged;
the shared hybrid signature API retains its previous checks. Actual codesign
and ACL cross-checks, 15 signature regressions, and new NativeAOT verifiers
against the same unchanged old root/ACL staging copy pass on ARM64 and under
Rosetta. These are component findings, not a complete new installer acceptance.

The new Developer ID build runs with 1,320 frozen source inputs in
`build/audit/5.0.2-20260908/corrected-developer-id-build.log`. Apple has now
accepted the corrected submission under job
`c4d7f3a5-3a54-4954-af83-d003bc194824` with `Accepted`, `statusCode = 0`,
and `issues = null`. The original submission ZIP hash is
`72de4c27b7271fa264447d535826afb425f5c7ce0c5a07538eb25113478ac76b`.
`source-after-apple.json` confirms all 1,320 source inputs are unchanged.
Stapling, ticket validation, Gatekeeper, and final package comparison of the
corrected candidate now pass. The new ZIP has 43,681,703 bytes and SHA-256
`820863042b5cfacb6643b1696c8fbf8412c9529d82d921d3bb7174db3dedf81d`.
The new full test run passes 153 of 153 groups in 410.1 seconds, with no
errors or blocked groups; aggregate group time is 932.8 seconds.
`corrected-developer-id-results-resumed/001-test-results.json` has SHA-256
`c9ddc29c752b5c451fd6e1a9d4c30770a368b248463ddcd6c157f34746f58147`.
All additional individual release checks and manual production measurements
have now passed. Test times are 194.6 seconds for the performance matrix,
81.6 seconds for 256 MiB Paranoia, and 78.3 seconds for the complex Paranoia
tree with KPAR2 repair. This run covers 18 files, 20 directories, and
221,327,790 input bytes and repairs one damaged unit. The corrected release
build has completed with exit code 0; all 20 result/timing files are bound
to the index. `source-after-build.json` confirms 1,320 unchanged source inputs;
the six locally provided assets are byte-identical to the preserved final
files. The actual GUI negative checks for canceling the start dialog,
an incomplete package, and canceling folder selection have now passed. All
129 checked entries of the installed apps, sidecars, and root anchor retain
identical bytes, metadata, and inodes after each case; atime is excluded.
`gui-installer-negative-cases.json` and the three subsequent comparisons
document this. They do not establish cancellation of the macOS administrator
dialog or actual App Translocation. Normal installation of the complete kit
under PID 9073 subsequently failed because of a false identity rejection.
The following correction requires a new build and its own release evidence.
Old PASS results are not transferred to the candidate that has changed again.

## Further installer correction on September 8, 2026

The candidate documented above with Apple job
`c4d7f3a5-3a54-4954-af83-d003bc194824` passed 153 test groups and all
additional release checks, but subsequently failed during actual GUI
installation with exit code 2. The existing installation remained unchanged
in all 129 checked entries. This candidate cannot be released; its results
remain historical evidence.

`installer-identity-trace/finding.json` isolates the cause of the false
identity rejection: immediately after successful verification of all 149
inventory entries, only the ctime of the installer app directory changed.
The specific operating system process or xattr trigger has not been proven.
The correction excludes only this field from the longer-lived installer
directory binding. All other identity fields and the symlink/write-protection
checks remain intact; the package root and regular helpers continue to bind
ctime. Native verification per verifier call, signatures, inventory, and the
protected staging copy remain unchanged.

19 regressions pass. A cross-check restoring the old ctime behavior fails as
intended; an independent source review confirms the limited scope and the
continued negative cases. Long messages now use a bounded, scrollable,
selectable, read-only details area. 18 presentation tests pass. The synthetic
GUI check confirms DE/EN long text through the last marker, the short English
text visually and through Accessibility, and the short German text through
Accessibility. It does not replace an actual installation.

Exactly five source/test/build paths changed again; password/PIN rules and
archive cryptography remain unchanged. 1,320 source inputs are frozen for
the new build in
`build/audit/5.0.2-20260908/installer-ctime-fix/` and confirmed unchanged
before notarization. The new submission candidate is prepared: ZIP with
43,679,426 bytes, SHA-256
`6bd960726f41189635343d5e47f0b509297ca4d17de06eb1038412ac0ba0aa74`.
`notary-candidate/submission-input-audit.json` confirms 5.0.2, Build 13 for
all three apps, 20 root objects, 19 Mach-O files, and 38 slices. Apple has now
accepted this submission under job
`de8618c3-7404-4b7f-b35e-591fd5fd92c2` with `Accepted`, `statusCode = 0`,
and `issues = null`. The Apple service record has SHA-256
`3fb3e3a2dfaab7b0f15f9321a07a6effe887ef866f826367c5389efa628ffc1d`;
`apple-submission-bound-audit.json` binds it to the original ZIP and all
38 original slices. `source-after-apple.json` confirms 1,320 unchanged
source inputs. The build resumed after `NOTARIZED` was supplied once. The
new full test run passes 153 of 153 groups in 396.2 seconds, with no errors
or blocked groups; aggregate group time is 910.3 seconds. The record
`corrected-developer-id-results/001-test-results.json` has SHA-256
`b7f068c25e9be40612fa869b2b88437dbf21f267ad5c6c3cf52924b522c89a6f`.
All six additional individual checks pass, as do the three production
measurements: performance matrix 196.1 seconds, 256 MiB Paranoia
81.8 seconds, and complex Paranoia tree 75.4 seconds of test time. The complex
run covers 18 files, 20 directories, 221,327,790 input bytes, and a successful
KPAR2 repair. The build finished with exit code 0. All three apps pass
stapling, `stapler validate`, and Gatekeeper. The final ZIP has 43,685,318 bytes
and SHA-256
`c4f069e0091259a0c6a1f76d880879facec689625b059e5d5659b70e5af112e1`.
`final-notarized-package-audit.json` binds all 38 unchanged slices to Apple;
the permitted difference comprises only three ticket files and six manifest
files. The native verifier confirms 149 manifest entries and the ZIP with
all sidecars for both arm64 and x86_64/Rosetta, four calls with exit code 0.
`final-release-assets.json` and `published-dist-assets.json` bind the six
final files to the local distribution folder.
`source-after-build-independent.json` confirms 1,320 unchanged inputs.
This evidence is under `build/audit/5.0.2-20260908/installer-ctime-fix/`;
it does not confirm a public GitHub release or separate Intel hardware.

The three repeated actual GUI negative checks of the new signed installer
pass: canceling the start dialog, an incomplete package before
authentication, and canceling folder selection. All 129 checked installed
entries remain unchanged after every case, including bytes, ctime, and
inodes. The German package error message is fully readable in the screenshot.
`installer-ctime-fix/gui-installer-negative-cases.json` and its three state
comparisons document this. Administrator cancellation and actual App
Translocation are not established by this. The normal process PID 34713
has ended without an observed installation completion.
`gui-normal-resume-state.json` subsequently confirms 129 fully unchanged
entries. The new normal launch PID 37155 is initially recorded before local
macOS authentication in `gui-normal-resumed-start.json`. After local
confirmation, its actual normal installation passed: `gui-normal-success.json`
documents the complete “Installation abgeschlossen” window observed through
AX and a screenshot. `gui-normal-installed-audit.json` confirms both app trees
at version 5.0.2, Build 13, ten external sidecars, and the root-owned ZPAQ
anchor are byte-identical to the final package. Physically, only the canonical
main app is installed; 21 additional LaunchServices entries still await
cleanup at this point. The actual separate folder-selection installation
under PID 46797 has now also passed: `gui-fallback-success.json` documents
the visible complete completion message, and
`gui-fallback-installed-audit.json` again records byte-identical installed
content. This does not establish actual App Translocation. The final
installed GUI PID 56850 then passes visible DE/EN checks of the version below
the subtitle, PIN from 6 to 16, integrity, and archive path placeholder.
German is restored and the app exited; evidence is in `gui-main-final-de-en.json`.
The 21 additional registrations belonging to the project's own main app were
removed selectively. `final-registration-after.json` confirms exactly
`/Applications/Keep Vault.app` and zero further registrations.
`final-physical-app-inventory.json` reads all 82 immediate app bundles in
both Applications folders independently of their names without errors and
finds only this Keep Vault main app at version 5.0.2, Build 13. The full offline
production run has now passed. The last installed complex test has also
passed with the unchanged regular launcher, a fresh SDK/restore/build, and
the exact installed native bytes: exit code 0, 70.532 seconds, 18 files,
20 directories, 221,327,790 bytes, and one KPAR2 repair.
`final-installed-test-summary.json` and
`final-installed-test-evidence/results.json` bind the result;
the result file's SHA-256 is
`905fff24578fa1db1ae3ae0019c712b5705429f644e386bfdf85d9a37fb28f96`.
`source-after-last-functional.json` confirms 1,320 unchanged inputs, and
`final-after-last-test-readonly.json` still confirms only the canonical main
app with zero further registrations. Technical macOS acceptance is therefore
complete within the stated scope and prepared for release. Commit, tag, and
public GitHub release are performed and confirmed separately afterward;
this state does not claim an already completed public release.
The offline evidence is kept separate from actual GUI acceptance under the
clarified credential contract: a fresh production core process, frozen local
models, installed signed native bytes, and external networking blocked
throughout the round trip. The new run
`offline-e2e-prepared/run-xdf2p6l8/` passes with exit code 0 in 79.562 seconds:
18 files, 20 directories, 221,327,790 bytes, one authenticated KPAR2 repair,
and a complete structure/size/SHA-256 comparison. 77 periodic network checks
accompany the run; positive IPv4/IPv6 probes pass before and after it. Wi-Fi
is restored; the watchdog did not trigger. `result.json` has SHA-256
`1c15da13a461236e81eaab8ab9bc683c3cc042503c3a84701a752ff3b44d400d`.
The independent follow-up audit `offline-e2e-independent-audit.json` passes
with 2,814 checks and 79 offline snapshots, including the before/after checks.
Periodic measurements are not a packet capture; cross-process temporal order
is documented with UTC and an interval measured by the same orchestrator
clock, not different process-local monotonic values. Factor generation for
the core test uses synthetic test samples. No full offline GUI round trip is
claimed; the requirement for complete offline operation remains unchanged.
Individual records and limits are in the
[current macOS audit report](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md).
