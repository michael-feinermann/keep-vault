# Keep Vault 5.0.3: REV11 progress and elapsed-time review

Development verification on macOS, 1 October 2026. This report distinguishes
implemented contracts and targeted tests from the final signed installation.
The latter requires fresh release evidence. Windows and real multi-TiB runs are
outside the explicitly agreed scope.

## Time-limit inventory

| Location | REV11 behavior |
|---|---|
| `OperationExecutionBudget` | No wall, cumulative CPU or no-progress timer. Linked cancellation, actual error propagation and ownership remain. Elapsed/CPU/stall values are observations only. |
| `ArchiveOperationPolicy`, macOS Resources | No hours/CPU-time/stall fields. New bounded preference schema cannot restore an old deadline. |
| ZPAQ native launcher/control | CPU permits, memory admission, output limits, parser bounds and explicit cancellation remain. No archive wall/CPU/stall deadline. Native integration tests are recorded separately. |
| `ZpaqService` five-second diagnostic child/pipe joins | Only after cancellation/error cleanup. They report failed cleanup; the outer owner barrier still waits for actual child termination and all started callbacks before releasing memory, CPU and source ownership. They do not limit a running archive's duration. |
| `MacZpaqSeatbelt` five-second cleanup joins | Join a failed canary/its pipe readers. The canary's normal execution receives the caller's cancellation token. |
| `KeySheetService` bounded print/tool waits | Printer enumeration and CUPS submission, not archiving, extraction or repair. Retained. |
| Test harness timeouts | May terminate a deliberately stuck fixture and report failure. They are not copied into product policy. |

The source inventory searches policy, lifetime, managed/native ZPAQ, process
launchers, linked tokens, timeout constructors, `CancelAfter`, waits and RLIMIT /
job-limit settings. Removing a wall deadline does not remove memory, disk, parser,
signature, MAC, AEAD or cancellation checks.

## Observer contract

One operation owns a pull-only `OperationProgressTracker`. Sources carry an
operation-owned identity, phase and sequence. Absolute per-source counts are
summed once; duplicates, regressions, stale phases and terminal updates cannot
advance work. Registration is bounded to 64 active sources. Counts and totals
are checked 64-bit integers. Native progress has no plan, authorization, result
commit or success capability.

Known input sizes and validated plans may define phase totals. Unknown extraction
sizes remain unknown; the finite extraction allowance is not a progress total.
Different phases and units are not added into invented overall percentages.
The overall ETA remains unknown because there is no validated model of all
future phases. A finished payload phase cannot mark the whole operation complete.
The outer GUI lifecycle marks success only after its result verification, commit
and cleanup complete. Cancellation and errors stay terminal.

Pool preparation counts completed public preparation steps. KDF reports only
completed sequential branches, without matrix/PMI/credential detail or a
secret-dependent ETA. The progress DTO contains only reviewed numeric counters,
identifiers, enums and durations; no paths, credentials, records, keys or byte
payloads. There is no external telemetry.

## Clock, estimator and presentation

The monotonic macOS clock uses `mach_continuous_time`; the difference from
`mach_absolute_time` identifies sleep. UTC, time zones and calendar changes are
not inputs to durations or rates. Sleep/resource/user pauses remain in elapsed
duration, are excluded from active rate time and reset estimation. Ordinary
pipeline and I/O waits remain part of throughput measurement.

Sampling is no more frequent than 250 ms. Warmup requires both four intervals
and two active seconds. For an interval `dt`, completed delta `dx` and time
constant 15 s, `alpha = 1 - exp(-dt/15)` and
`rate = alpha*(dx/dt) + (1-alpha)*previousRate`. Zero-work intervals are included.
Known remaining work divided by the rate gives phase ETA. A 30-second stale
count hides the ETA without cancelling or pausing work. Invalid clocks and
impossible counts degrade the display; they do not authorize or abort crypto.

Avalonia polls every 250 ms and skips hidden/minimized windows. UI work does not
run on producer threads. Screen-reader naming changes at phase/terminal
boundaries, without four-per-second live announcements. DE/EN labels distinguish
phase counts, unknown total duration, elapsed time, cancellation and completion.
Durations beyond 24 hours retain days rather than wrapping.

## Targeted evidence

The verified official .NET SDK 10.0.400 built the managed macOS app and harness
with zero warnings/errors. Package locks were preserved. The ambient Homebrew
library-pack hash mismatch was resolved by provisioning the verified SDK, not by
weakening NuGet verification.

`work/v13-evidence/rev11-development/progress-isolation-results.json` records
12 passed Progress groups: counts, ordering, unknown totals, independent ETA,
stale values, clocks, overlap, completion, bounds, equivalence, privacy and hot
update allocation. The constant-rate oracle independently expects 2007.04 s.
Long-duration tests use simulated monotonic time; they are not actual multi-day
processing evidence.

The equivalence group encrypts and decrypts fixed public input through all twelve
actual suites with no observer, frequent polling and a broken test clock. Every
container is byte-identical across observer modes, including headers, nonce
fields, ciphertext and tags. Its explicit 8-MiB test-only KDF override is not a
production KDF memory test. Production KDF/KAT gates remain separate.

On 2026-10-01 at 08:07:58 UTC, one million warmed producer updates took 39.6648 ms
and allocated 40 bytes in the measuring thread. This is a single-process M5
measurement of the counter path, not a many-core or real-GUI performance claim.
Machine-readable values are in
`work/v13-evidence/rev11-development/root-final-bin/progress-overhead-public.json`.

All 30 GUI groups passed in the final Build5 development harness, including
`gui.resource-policy`, `gui.rev11-preference-restart`, `gui.rev11-progress`,
`gui.rev11-observer-isolation`, cancellation lifetime and complete synthetic
creation. The 12 Progress groups, read-only golden verifier and three Spec
groups also passed again. Results are `gui-final5-results.json`,
`progress-final5-results.json`, `golden-final5-results.json` and
`spec-final5-results.json`; `root-final5-binaries.json` binds the actual DLLs
and staged native inputs. GUI tests drive actual Avalonia controls with a
headless backend; installed visual, keyboard and accessibility review remains
a separate release gate.

`v13-progress-native-ipc` and `v13-zpaq-bound-source` passed in the managed
development harness. They exercise real local socket framing, a queued CPU-one
grant unblocked by a release on the same connection, ordered close, allocation
ownership, invalid write completion and an incomplete following header. The
source test rejects a changed inventoried object without cloning its data.

The separate ARM64 native harness passed Plain Add/Read-at Extract and Pipe
Add/Extract with 2 MiB of public data, Unicode, empty files and empty directories
at compression levels 0 and 5. A shared simulated parent/child compute ceiling
remained at one. These are isolated native protocol results, not final installed
product evidence. The same four level-5 roundtrips and five negative/cancellation
cases also passed with AddressSanitizer and UndefinedBehaviorSanitizer enabled
(LeakSanitizer disabled on macOS). Exact commands, binary hashes and original
results are in `work/rev11-zpaq-control/protocol-level5-sanitized.json` and its
log. Final installed-operation results must still be appended after execution.
