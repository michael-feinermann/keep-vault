# Keep Vault v12 for macOS: normative release requirements

[Deutsch](KEEP_VAULT_V12_MACOS_RELEASE.md) | English

Status: binding specification and release checklist for the macOS edition of Keep Vault 5.0.2, Build 13. Windows is not part of this release and will be updated in a separate work step.

The [audit report for 5.0.2](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md) records the
state actually demonstrated and the remaining limitations. Technical acceptance
of the final macOS candidate was completed on 8 September 2026; the last regular
installed complex test passes in 70.532 seconds. The public release was separately confirmed on 9 September 2026; see the
[publication record](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md#public-release-on-9-september-2026).

## Format boundary

This application writes and reads only containers with magic `KZPAQ2\0` and `Version = 12`. `KZPAQ1\0` and every other magic are rejected before header processing and the KDF. All production crypto, role, tweak, nonce and authentication domains carry `/v12/`. There is no v11 reader, automatic migration, legacy domain or fallback to older formats. A container with a different version number must be rejected before the KDF, authentication, decryption and output.

KPAR2 remains a separate format at version 4. For encrypted archives, `ContainerVersion = 12` is bound in the locator and the authenticated metadata envelope. KPAR2 v4 must not repair containers of other generations. An unencrypted KPAR2 error-correction profile continues to use `ContainerVersion = 0` and makes no authenticity claim.

## Password and PIN acceptance

The [v12 password and PIN contract](KEEP_VAULT_V12_CREDENTIAL_POLICY.en.md)
is a binding part of this revision. All existing and new selection and strength
rules apply only at creation. Extraction, listing and recovery require no model
data and no repeated quality check. The raw-byte, header and KDF contract
remains unchanged. In addition to all previous gates, 5.0.2 must check the
corrected evaluation, pair/date rules, offline first launch, DE/EN version
display and static compatible v12 test archives.

## KDF and memory limit

The two Argon2id branches and, for Paranoia, the two rounds are executed strictly sequentially. Each Argon2id call continues to use `t = 4` and `p = 4`. `p = 4` is the internal Argon2 lane count and does not permit holding two Argon2 matrices simultaneously. Before the next branch or round, the preceding matrix must be released and its sensitive material erased. The peak must therefore not exceed one matrix plus clearly bounded buffers.

The v12 KDF requires all four factors and exclusively uses the v12 domains from `V12MasterKdf`, the role context `LE32(12)` and, in the production path, the native export `keepvault_argon2id_v12`. Static known-answer tests must check credential intermediate values, both Argon2 branches, the 1024-bit master values and the derived role keys independently of the container roundtrip.

The separate native export `keepvault_argon2id_v12_kat` is accessible only through an internal, asynchronously bounded test scope. It accepts exactly `m = 8192 KiB`, still with `t = 4` and `p = 4`, so that the production worker KAT can run through all ten suites twice. The production export must reject this reduced memory value. There is no user, environment or header option for it, and no container generated with it may be readable outside the KAT scope.

## Parallel production pipeline

Container encryption and decryption, the two container MAC trees, and ZPAQ compression and extraction may operate in parallel. The following immutable limits apply:

1. The worker count is positive, hardware-bounded and subject to a hard cap. Queues and concurrently held chunks are bounded. There is no unbounded task fan-out.
2. Chunks are processed with stable indices and written only in canonical order. Headers, nonces, associated data, tags and container bytes must not depend on scheduling.
3. Cancellation or an error terminates all producers, workers, writers and ZPAQ processes. All tasks are observed and joined, sensitive buffers are zeroed, and no partial destination is published.
4. Both global v12 container tags are verified before decryption into a visible output stream. With ChaCha20-Poly1305, each chunk is additionally authenticated before its plaintext is used.
5. ZPAQ receives or produces an ordered, bounded stream. Errors, traversal, tampered archives and premature process exit must leave neither partial output nor a successful commit.
6. A production KAT must execute the real production paths with one worker and with the production worker count using identical prepared entropy and identical plaintext. For each of the ten cipher suites, the complete containers must be byte-identical, both variants must yield the same plaintext and hash, and tampering must fail before any plaintext output. Merely parallelizing the test runner does not satisfy this gate.

The container pipeline permits one 16-MiB slot per four logical processors, rounded down, with a minimum of one and a maximum of 64. A conservative memory budget additionally limits the slot count: two chunk buffers plus a small overhead are budgeted per slot, totaling at most one sixteenth of the available GC memory budget where at least one slot fits. If the budget is unknown or too small, one slot is attempted; a failed safe allocation aborts the operation. Slots are allocated only as needed. The implementation processes bounded batches and writes in canonical order after joining them. It does not overlap the writer with the next batch.

The 1:4 ratio does not assign cores. Native transformations internally use at most 64 workers. A process-wide semaphore limits simultaneously active chunk transformations to `clamp(floor(2 * max(1, CPUs) / min(max(1, CPUs), 64)), 1, 64)`. Nested chunk/native parallelism therefore does not grow quadratically with CPU count. Cancellation waits for all teams already started and releases their permits. Actual performance must be measured on the target host; the policy does not guarantee universally optimal scaling.

The parallel container MAC uses 1-MiB leaves and at most 64 workers. At 1 MiB, Poly1305 switches to at most 64 block-aligned workers and retains a serial differential path. ZPAQ workers are also limited to 64. The pipe path limits each frame to 24 MiB compressed, 32 MiB uncompressed and 128 MiB model size, with at most 512 MiB of compressed frames waiting in total. The shared native processing budget is 6 GiB; a compression job reserves 384 MiB, a regular job 592 MiB. Regular jobs are limited to 64 MiB of output and 512 MiB model size. An already authenticated regular archive on stdin may be at most 512 GiB. Extraction destinations are limited to 500 GiB in total, 500 GiB per file, 500,000 entries, 512 MiB index and at most 2^26 fragments. These are format or resource limits and must not be bypassed through unbounded queues or silent resynchronization.

Regular verified ZPAQ inputs carry a 16-byte frame (`KV12VM` with two null bytes and a big-endian 64-bit length) exclusively on the internal pipe. The native process checks magic, size limit, exact length and EOF. It holds the data in anonymous private VM memory and, before parser access, reduces both current and maximum memory protection to read-only. Named POSIX SHM objects are prohibited in all sandbox profiles. This change affects no stored container format and claims neither unlimited RAM capacity nor exclusion of operating-system swap.

KPAR2 parity, shard checksums, verification and reconstruction distribute independent stripes or shards across at most 64 workers. Each worker writes exclusively to disjoint regions; the manifest, locator and repaired container remain canonically ordered. The one-worker path and the production path must produce byte-identical parity and reconstruction.

## Mandatory gates

Before a release, all the following gates must pass on real Apple hardware with the official SDK 10.0.400 pinned exactly by `global.json`. The macOS-arm64 SDK archive is additionally pinned to SHA-512 `e440e9a58d4ff7741c8342ac3e086fa9ee2dadc25e01c0449a88317a74cfbd63625b8092c3b2a131ae14b16ab3401e9cc470e578e4c65a72a0b5786bd2308cde` and must be checked before and after extraction. Restore, build, publish and test execution must use a freshly created private NuGet, SDK and artifact tree bound to owner, mode and device/inode number. Neither `obj` nor `bin` from the repository may enter a release process. A normal restore must use `--locked-mode` and `-p:RestoreForceEvaluate=false`; `--force-evaluate` is prohibited because it overrides locked mode. Verified lockfile hashes must be identical before and after restore/build.

1. Locked restore, release build and native build for arm64 and x86_64 or Universal. Test natives are staged into the test output directory only after the last project build. Tests then run with `--no-build --no-restore`.
2. Spec lint with no active v11 production class, v11 domain, version constant or v11 native export.
3. Static KATs and independent reference tests for the KDF, MACs, all ciphers and the ten suite compositions.
4. The complete test run executes in parallel with a safely determined worker count and the test coordinator's CPU, memory and exclusivity reservations. An additional serial full test is not planned, following the explicit project instruction of 05.09.2026. Internal 1-versus-N differential tests remain part of the complete test set.
5. The explicitly selected production KAT `containers.v12-production-worker-equivalence`.
6. The manual performance run `performance.cipher-suites` measures all ten cipher suites and cascades as 256-MiB raw primitives and three times each through the complete v12 container path for encryption and authentication before plaintext plus decryption. Container values use real production Argon2id and are reported as medians. In addition, `performance.paranoia-256mib-e2e` must completely archive, encrypt, check KPAR2, decrypt and extract exactly 256 MiB with compression level 5, Paranoia and real production Argon2id. Both run with `--performance --parallel 1` on an otherwise idle host and must not skip any security check.
7. KPAR2-v4 commit, repair, fault-injection and object-binding tests, plus container/ZPAQ end-to-end tests for creation, authentication, decryption and extraction.
8. Bundle, native-slice, entitlements, hybrid-signature, QR-companion and installation checks. Private keys, passwords and wrapping keys are neither displayed nor logged nor copied into the repository.
9. A public release requires a valid Developer ID Application signature, successful Apple notarization, locally stapled tickets and successful build checks with `stapler validate` and `spctl` for Keep Vault, QR Scanner and Keep Vault Installer. Both notarization routes must include all three apps. An Apple Development signature is not a publishable result.

The last functional release gate is `performance.paranoia-complex-tree-e2e`: a heterogeneous deep folder structure with empty, hidden and Unicode paths and widely varying file sizes is processed with compression level 5, Paranoia and real production Argon2id. Authenticated KPAR2 damage is then repaired and the complete set of paths, types, sizes and SHA-256 values is compared after decryption and extraction. After this gate, only non-mutating package, Git and publication checks may take place; any code or artifact change invalidates the gate.

The build may be described as publicly released only when the signed and notarized content exactly matches the verified archive, tag `v5.0.2` points to the verified commit, and the public release contains exactly these artifacts. A GitHub draft is not a public release. The technically completed and notarized version 5.0.1, Build 12 remains preserved as a GitHub draft; the current target version is 5.0.2, Build 13. An identical version/build combination already distributed publicly must not be overwritten retroactively.

## Self-contained macOS installation kit

The ZIP contains three apps, ten external sidecars for the app pair,
`INSTALLATION.txt`, and a complete `installation-manifest.json` with five
sidecars of its own. The outer release remains a ZIP with five signature/hash
files. The signed native entry point `Keep Vault Installer.app` contains the
Universal NativeAOT verifier, a precompiled object-bound deletion helper and
the sealed installation scripts. For this package mode, the target Mac needs
no .NET SDK, compiler, Xcode or source workspace. The required root-owned
ZPAQ-v12 anchor is established through the existing privileged installation;
a writable bundle fallback remains excluded.

A first launch must not depend on package neighbors remaining visible relative
to `Bundle.main`. [Apple DTS](https://developer.apple.com/forums/thread/724969)
describes how App Translocation can invalidate that assumption. If the complete
package is missing from the automatically determined location, a native picker
for the complete package folder should be offered. The selected source must
pass all normal authentication and copy checks. The native folder picker has
now been implemented. Before the unchanged authentication, the fixed 20 package
objects are checked with `lstat` for their expected types and links. Both
architecture slices compile with warnings treated as errors; twelve filesystem
probes each pass under ARM64 and Rosetta-x86_64. The actual installer GUI and
administrator run of this selection path has passed for the final candidate
under PID 46797; the [audit report](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md) binds it
to the unchanged installed app/sidecar and anchor bytes. This demonstrates the
folder picker and does not claim actual App Translocation.

Before being evaluated, the inventory must be verified with both fixed
signature pins and all five sidecars. It binds every expected file and
directory, including type, path, mode and, for files, size and SHA-256, together
with the matching release metadata of all three apps. Missing, additional,
duplicate, ambiguous, linked and special objects fail. The six manifest files
are separately and fully authenticated; they are the only exception to their
own content list.

Before operational execution, the native entry point copies the fixed 20
package entries into a private root-owned directory. Incoming ACLs are removed.
Only after the Apple signature, active-process CDHash and complete inventory
have been checked does the logged-in user receive exclusively read, search and
execute ACLs. A repeated check confirms this state. Scripts and native helpers
are then executed from this copy, which is protected against changes by the
same user. For Universal binaries, the active CDHash may be bound only to the
active architecture; the Apple requirement for all slices remains additionally
mandatory.

The build must staple all three apps and check them with `stapler validate`,
then regenerate and hybrid-sign the inventory. The final ticket bytes are part
of this inventory. On the target device, `syspolicy_check distribution` checks
the current Apple distribution policy; in addition, the target app's local
ticket bytes must match the authenticated release inventory. `syspolicy_check`
alone is not described as cryptographic ticket validation or as a replacement
with identical semantics for `stapler validate`.

A rollback binds the previously authenticated old app, including its old
notice and ticket bytes. The before/after fingerprint, original object
identity and repeated Apple/hybrid verification must agree. Requirements that
identify only the new candidate must neither replace nor distort this old-state
comparison. The existing anchor, pair, entitlement and transaction controls
are retained.

ARM64 and x86_64 system calls must be checked against the ABI actually used.
For the Darwin stat structure in use, this means `fstat`/`lstat` under ARM64
and `fstat$INODE64`/`lstat$INODE64` under x86_64. Rosetta probes, native-slice
compilation, actual installation and tests on other hardware are documented
as different kinds of evidence. A test not executed on a separate Intel Mac
is not reported as passed evidence.

The implementation and targeted component checks are demonstrated in the
5.0.2 audit report. They do not preempt complete current acceptance of the
build, GUI, installation, notarization and stable public release.

## Current acceptance status and GUI completion state

The earlier complete Development run ends with 151 of 152 groups passed in
492.8 seconds. The sole failure concerns the outdated SDK/`xcrun` expectation
in `packaging.hybrid-key-separation`. The assertion was adapted to the fixed
absolute system tools of the SDK-free metadata verifier; the real hostile
`PATH` countercheck remains mandatory. The separate follow-up of this group
passed with 1 of 1 groups in 79.0 seconds. Its result is at
`build/audit/5.0.2-20260906/sdk-free-metadata-targeted-evidence/results.json`,
SHA-256 `b0bde7f61f03e712cf26e1d6478c2d791f0f7784629dfcf261cc3ca1debd1de6`.
The earlier 152/152 results demonstrate only the source states at those times.

The visible app check under PID 81532 confirms the version display in DE/EN,
language switching of analysis/rejection displays, and targeted deletion of
independent copies with unchanged originals for 5.0.2, Build 13. However, a
subsequently delivered `TextChanged` overwrites the completion display after
the German success dialog. The minimal correction retains completion after
programmatic clearing and continues to reset confirmation and analysis when
a new path is entered. In addition, four path placeholders for archiving,
extraction and deletion were localized.

The new regression `gui.erase-completion-status` must cover real delayed event
delivery and DE/EN language switching. The fresh targeted GUI run passes with
24 of 24 groups in 21.2 seconds, including this regression in 1.390 seconds.
The Development run subsequently started with 153 expected groups was
interrupted by a Mac restart on 7 September 2026 at around 14:04. There is no
JSON result for this attempt; `final-gui-development-build.log` is not evidence
of a passed test set. The earlier 151/152 Development build also still contains
the installer state preceding the later folder picker. Its separate
architecture and filesystem checks do not replace a new overall build or an
actual installer run. Artifact paths and source hashes are assigned in the
[current audit](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md).

The rerun in `restart-development-build.log` passes with 153 of 153 groups in
405.4 seconds, with no failures or blocked groups. The summed group runtimes
are 921.4 seconds. The result evidence
`restart-development-results/001-test-results.json` has SHA-256
`343a5bac41eda92892e1958a1c0e40acc3d0a548c96883ef820f69a763cbd049`.
All 1,319 source inputs match between the before/after snapshots; the installed
Development app is byte-identical to the new bundle. Package evidence confirms
20 root objects and 19 Mach-O files with 38 slices; both NativeAOT slices
successfully verify the manifest, ARM64 natively and x86_64 under Rosetta.

The visible retest on 7 September 2026 from 15:19:35 under PID 34669 confirms
the readable version number beneath the subtitle and all four path placeholders
in DE/EN for version 5.0.2, Build 13. Actual cryptographic erasure removes only
the test copies of the container and KPAR2; originals and the control file
remain unchanged. The completion status persists after OK and DE/EN/DE; a new
path resets status and confirmation. The app was then closed with Cmd-Q.
The evidence is `gui-completion-retest-result.json` in the same audit directory.

The final Developer ID candidate has now been accepted by Apple: job
`672ab61e-4909-4fe9-a9e2-1685ea774e09`, `statusCode = 0`, `issues = null`.
`final-developer-id-build.log` confirms stapling, `stapler validate` and
Gatekeeper acceptance for all three apps. The 76 Apple ticket lines are fully
mapped to the 38 original architecture signatures through bundle aliases and
duplicates. The final package comparison passes for 20 root objects, 19 Mach-O
files and 38 unchanged slices. Only three ticket files were added; six
manifest/signature files were renewed. All other bytes and modes are unchanged.
The native verifier successfully checks the 149 inventory entries on ARM64 and
under Rosetta-x86_64.

The final ZIP of 43,678,062 bytes has SHA-256
`cac58f018ab60734e4565aea601d590e390d6640419eabe41e62a66f8e9c7484`.
It is prepared for publication together with its five sidecars. The original
Apple submission, service log and all verification evidence are bound
separately in the [current audit](KEEP_VAULT_5_0_2_MACOS_AUDIT.en.md).
All 1,319 source inputs remain unchanged; a final 5.0.2 commit and release tag
do not yet exist for this work state. App installation and authentication for
the root ZPAQ anchor are complete. The complete test run of the notarized
Developer ID candidate passes with 153 of 153 groups in 405.5 seconds, with
no failures or blocked groups; the summed group runtime is 918.9 seconds.
`final-developer-id-results/001-test-results.json` has SHA-256
`8ec5a2d0a5b28c5b40f3e0ba7054cea27c46bb99c4b25a1a3e26c3e44c1db93d`.
The additional individually started release checks also pass: production
worker equivalence, parallel MAC KAT, v12/KPAR2 roundtrip, KPAR2 worker
equivalence, physical EIO repair and the complete ZPAQ matrix. Their total
runtimes and individual evidence are assigned in the current audit. The
performance matrix of all ten cipher suites passes in 195.0 seconds, the
256-MiB Paranoia run in 75.4 seconds and the complex Paranoia run with KPAR2
repair in 73.7 seconds. Result files `015`, `017` and `019` with the suffix
`-test-results.json` are bound with SHA-256 in the current audit. The release
build of 7 September 2026 is complete with `release_publish_swap=complete`;
the final artifacts are under `dist/Keep Vault-macOS/`. The native installer
GUI run, the last complex run after final installation and stable publication
remain open.

The subsequent actual native installer GUI test on 8 September 2026 failed.
The separated argument form `codesign -R <Anforderungstext>` was interpreted
as a reference to a requirements file and rejected with
`invalid requirement specification`. Requirement text requires
`-R=<Anforderungstext>`. Installation stopped at this check. The preceding
build and Apple results therefore apply only to the superseded candidate and
do not permit publication. The correction requires signing and notarization
again, complete release checks, the actual installer GUI retest and the last
complex run after final installation. The target before public release remains
5.0.2, Build 13.

The corrections have now been implemented. In addition to the codesign
argument, the failed ACL assignment using numeric UID text was replaced with
a system user checked back against UID and account name. ACLs are assigned
before policy checks and native execution. The native verifier checks signature
bytes directly from held descriptors because reopening through `/dev/fd`
failed for root files with a read ACL. The existing signature and identity
checks are retained. Real codesign/ACL counterchecks, 15 signature regressions
and both new NativeAOT slices against the same unchanged root/ACL intermediate
copy pass. This component evidence does not replace a complete new installer
run.

Exactly nine source/test/build paths were changed; 1,320 source inputs are
frozen for the new Developer ID build. Password/PIN rules and archive
cryptography remain unchanged. The installer entry-point test is now an
automatic gate before signing. Evidence is under
`build/audit/5.0.2-20260908/`; `corrected-developer-id-build.log` documents the
ongoing build. Apple's new acceptance of the corrected candidate is now
demonstrated by job `c4d7f3a5-3a54-4954-af83-d003bc194824`, `Accepted`,
`statusCode = 0` and `issues = null`. The original submission ZIP has SHA-256
`72de4c27b7271fa264447d535826afb425f5c7ce0c5a07538eb25113478ac76b`.
All 38 original architecture signatures are bound;
`source-after-apple.json` confirms 1,320 unchanged source inputs. Stapling,
ticket validation and Gatekeeper acceptance have now passed for all three
corrected apps. The final package comparison confirms 20 root objects,
19 Mach-O files and 38 unchanged slices; hybrid verification of the inventory
with 149 entries and of the ZIP with all sidecars passes on ARM64 and under
Rosetta. The final ZIP of 43,681,703 bytes has SHA-256
`820863042b5cfacb6643b1696c8fbf8412c9529d82d921d3bb7174db3dedf81d`.
The six new files are bound in `final-release-assets.json`.

The complete test run of the corrected notarized candidate passes with 153 of
153 groups in 410.1 seconds, with no failures or blocked groups; the summed
group runtime is 932.8 seconds. Evidence
`corrected-developer-id-results-resumed/001-test-results.json` has SHA-256
`c9ddc29c752b5c451fd6e1a9d4c30770a368b248463ddcd6c157f34746f58147`.
All additional individual release checks and manual production measurements
have now passed. Test times are 194.6 seconds for the performance matrix,
81.6 seconds for 256-MiB Paranoia and 78.3 seconds for the complex Paranoia tree
with KPAR2 repair; total runtimes are 194.7, 81.7 and 78.4 seconds. The complex
run processes 18 files, 20 directories and 221,327,790 input bytes and repairs
one damaged unit. All 20 result/timing files agree with the result index.
The corrected release build has finished with exit code 0;
`source-after-build.json` confirms 1,320 unchanged source inputs.
`published-dist-assets.json` confirms that the six locally provided files are
byte-identical to the secured final assets. The additional actual GUI
counterchecks for startup-dialog cancellation, an incomplete package and
folder-picker cancellation have now passed. After each case, all 129 checked
entries of the installed apps, sidecars and root anchor retain identical bytes,
metadata and inodes; atime is excluded. `gui-installer-negative-cases.json`
and the three associated post-comparisons demonstrate this. Cancellation of
the macOS administrator dialog was not tested; the separate folder picker
does not demonstrate actual App Translocation. Normal installation of the
complete kit under PID 9073 subsequently failed at a false identity rejection.
The following correction requires a new build and its own release evidence.
New and superseded candidates, as well as submission and final ZIPs, remain
bound separately.

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

## Confidential printout

The corrected DE/EN design was explicitly approved on 7 September 2026 with
“Sieht gut aus. Setzt das um” (looks good, implement it). It uses the actual app
version in the visible title and PDF title, at least three full password
writing lines, the notice `PIN nicht eintragen` or `Do not write down the PIN`,
and bold metadata labels including their colons, with values in regular type.
Approval applies to the specific preview reviewed; a layout change and
acceptance of the final signed product must be treated separately.


Physical key-sheet printing writes no app PDF. Nevertheless, CUPS, printers, network print servers or device storage can cache the secret print job. Before spooling, the app must explicitly warn and require confirmation. Printing is permitted only to a trusted, physically controlled printer. Keep Vault cannot delete copies outside its own process.
