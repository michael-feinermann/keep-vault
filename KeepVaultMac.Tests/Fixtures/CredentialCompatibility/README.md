# Synthetic v12 credential compatibility fixtures

[Deutsch](README.de.md) | English

These files contain only public, deliberately synthetic credentials and a fixed text canary. They are not archives created by a released application. Never use their factors, credentials, salts or nonces for real data.

The purpose is to keep archive readability separate from the rules for selecting new credentials. All six `.kzpaq` files are real v12 containers with a real, dual-authenticated/encrypted KPAR2 v4 sidecar bound to ContainerVersion 12. The producer used production PMI-derived Argon2id memory, t=4 and p=4. No memory-cost override was enabled. The PIN-substring case uses the two-round Paranoia suite; the other cases use AES-256.

| Fixture | Selection-policy violations and raw-byte sentinels |
| --- | --- |
| `empty` | Empty password and empty PIN |
| `short` | One-character password and one-digit PIN |
| `oversized-raw` | Password longer than 256 UTF-16 code units, 17-digit PIN, leading/trailing spaces, decomposed Unicode, leading PIN zero |
| `pin-substring` | Entire PIN occurs literally inside the password; Paranoia suite |
| `date-2026-09-06` | PIN is DDMMYYYY for the frozen local date 2026-09-06 |
| `model-and-old-pattern` | Previously passing German word phrase and ascending `123456` PIN |

The manifest pins the actual UTF-8 password bytes, ASCII PIN bytes, both complete v12 credential hashes, file hashes and sidecar hashes. The fixture-date policy assertion uses the frozen date explicitly; the test does not depend on the day on which a later CI run executes.

## Producer provenance

The private source snapshot comes from commit `e52159e7a569a8b77fe7732006388c4401c4009f` (5.0.1). `generator-policy-patch.json` records exactly three removed checks, each replaced with an explicit NURTEST comment:

1. The writer's password creation-policy check.
2. The writer's PIN creation-policy check.
3. The old PIN selection check in `DeriveMaster`.

No product escape hatch was introduced. `V12MasterKdf.cs`, `KdfPrimitives.cs`, `SuiteKeySchedule.cs` and `RecoveryService.cs` are byte-identical to the frozen commit, as recorded in `source-provenance.json`. The writer and derivation wrapper differ only by the documented policy comments. `FixtureBuilder.cs.txt` contains the exact producer source and is deliberately not compiled by the product or tests.

The native components were copied without modification from the installed 5.0.1, build 12 application. `native-provenance.json` records each SHA-256. No native compilation, re-signing, installation or notarization was performed. ZPAQ uses the existing protected native anchor through the ordinary production API.

Final generation used SDK 10.0.400, commit `14fbf8d527`, runtime 10.0.11, provisioned by the repository's `Provision-VerifiedDotnet-macOS.sh`. The provisioner verified the pinned Microsoft archive SHA-512 before execution. The generator used an empty private HOME, private NuGet/cache/scratch directories and a clean environment. Every direct package version in its private project graph was pinned exactly. A fresh official-feed restore created private lockfiles, followed by `build --no-restore --no-incremental`. The historical second restore combined `--locked-mode` with `--force-evaluate`, so it must not be treated as effective locked-mode evidence. The historical `source-provenance.json` and `package-provenance.json` wording is superseded by the separate strict-restore verification below. The generator is deliberately JIT-only, with AOT and trimming disabled. It is not a release executable.

The exact private project files, two lockfiles, NuGet configuration and clean-environment run script accompany the fixtures. `package-provenance.json` records all 56 resolved package identities/content hashes; they match the corresponding frozen 5.0.1 dependencies. `verified-source-before.json` and `verified-source-after.json` demonstrate that all 87 source/project inputs remained identical during the final build and generation. Native components were staged only after the build, using `Stage-TestNatives-macOS.sh`; the staging gate passed signature/team/entitlement verification and original-versus-copy byte comparisons.

The earlier Homebrew-SDK fixture generation was completely replaced. Two subsequent ambient reader-build diagnosis attempts stopped before compilation: NU1004 when disabling AOT/trimming changed the locked dependency set, then NU1403 for the ambient ILCompiler/ILLink 10.0.11 cache. No mismatching package was accepted, and no repository lockfile or global package cache was changed. Final current-reader tests run separately through the verified `tools/Test-KeepVault.sh` pipeline.


## Strict dependency verification addendum

`strict-restore-addendum.json` records a later check using the exact archived private lockfiles and original verified SDK, without changing any package hash or regenerating any fixture. The effective MSBuild properties were explicitly verified as `RestoreLockedMode=true` and `RestoreForceEvaluate=false`. Restore then ran with `--locked-mode --force -p:RestoreForceEvaluate=false` and exited successfully. Both private lockfiles remained byte-identical to their archived copies; all 87 source/project inputs also remained identical. `strict-restore-check.sh.txt` and `strict-restore-check.log.txt` preserve the exact command and output.

The original manifest and producer transcripts retain their historical hashes. The test independently pins this addendum and its transcript hashes, so the corrected dependency evidence is checked alongside the original manifest. This is a strict dependency-consistency check for the already generated fixtures, not a new fixture generation or a release build.

## Independent byte oracle

The producer frames raw fields itself using four-byte little-endian lengths. It uses Bouncy Castle 2.6.2 SHA3-512 for both factor halves and its keyed, personalised Skein-MAC-1024-1024 implementation for the full-factor branch. It does not use production framing or digest helpers for those expected values. Both independent results must equal the production credential functions before a fixture is written. This checks the internal KDF inputs independently of a container roundtrip.

The original, decomposed and whitespace-preserving strings remain the cryptographic inputs. Normalized strings are used only as negative sentinels in the test. The fixture generator uses deterministic synthetic factors/salts/nonces and the regular sidecar generator. Timestamps and sidecar entropy mean regeneration can produce different container or sidecar bytes; regeneration requires a new review and explicit updates to every pinned hash.

## Registered tests

`CredentialCompatibilityTests.Tests` exposes two light groups and six production-Argon groups:

- `credentials.static-fixture-provenance` verifies the pinned manifest, producer evidence, files, raw encoding and independent credential vectors. It positively verifies that the model-forbidding test hook fires at both evaluation and direct model loading, before any resource read.
- `credentials.creation-still-rejects` checks existing/new policy reasons and rejects actual new-archive attempts before any output is published. The model-phrase case must specifically use an available model to reduce an old score of at least 128 below 128, so missing model data cannot masquerade as a successful correction.
- `credentials.read-*` performs direct decryption, ZPAQ listing, extraction, healthy dual KPAR2 verification, manipulated-container rejection before any plaintext, exact KPAR2 reconstruction into a separate candidate, and decryption of the repaired candidate. The short case also rejects a wrong recovery password. Every read operation runs under a scope that throws on any password-model evaluation or direct loading; the final attempt count must be zero.

The six read groups reserve 4 CPU tokens and 2560 MiB, use Argon, and hold the ZPAQ process constraint. They do not use GUI, camera, installation or signing services.
