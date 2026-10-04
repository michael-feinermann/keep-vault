# Keep Vault 5.0.3: REV12 resource implementation review

Current source contract: 3 October 2026, REV12. This report covers the shared
resource policy and distinguishes its current implementation from the dated
REV11 development evidence below. The filename retains the REV10 artifact name
required by REV12 section 11. It does not claim completion of the current full
regression, production workflows, native/AOT build, installed GUI or signed
release gates. The [REV12 acceptance matrix](KEEP_VAULT_5_0_3_REV12_GATE_STATUS.md)
records those separate gates.

## Contracts

`ResourcePreferences` stores Auto/Manual modes and optional manual ceilings.
Effective CPU counts and memory observations are never written back as user
preferences. Copies preserve preferences. Removing a manual preference resolves
a fresh automatic default. `ResolvedOperationPlan` is a public, secret-free phase
plan; `ResourceUsage` reports concrete held memory leases. The authorization for
unknown extraction is initially 256 MiB, visibly separate from expected output;
the user can explicitly select a larger finite allowance. This protects against
unrequested expansion and is not a free-space reservation. The agreed 512-MiB
Paranoia fixture uses its explicit 1-GiB test allowance.

The default container read bound derives from `CryptoUsageBudget`'s 64-TiB
payload, worst-case 16-byte per-chunk outer tags, bounded header/framing and
192 bytes of global tags. The recovery read ceiling is the same finite bound.
The metadata authorization derives from four full 204-byte-per-MiB record tables
at that bound. These are read/parser ceilings, not four resident caches or
requested disk allocations. Actual generated recovery size remains estimated by
`RecoveryService` from the actual container and RS(20,3) geometry.

## Memory observation and admission

On macOS the observer reads `hw.memsize`, `host_page_size` and
`host_statistics64(HOST_VM_INFO64)` through the public SDK ABI. The revision-1
prefix is 152 bytes on the supported 64-bit ABIs. `free_count` already includes
speculative pages; speculative and purgeable counts are not added again. Free
plus inactive pages is an explicitly conservative *candidate reclaimability
observation*, not a guarantee that a subsequent allocation or lock will succeed.
The observer also reads actual process resident bytes and the runtime process
limit. The latter is a ceiling only, never used as current free memory.

The total host/process ceiling retains max(128 MiB, 1/16 of the smaller physical
or runtime limit) for the OS/runtime. New admissions additionally retain
max(128 MiB, 1/32 of physical RAM) from observed reclaimable capacity. These are
headroom rules, not operations' allocations. Reclaimable capacity below 1/8 of
physical RAM is elevated pressure and below 1/16 is critical pressure. Missing
or inconsistent observations produce a controlled resource error. No fallback
to unbounded capacity or weaker cryptographic parameters exists.

Only 64 KiB of bounded operation-lifetime accounting is charged when acquiring
an owner. Concrete working buffers, index segments, native models and KDF matrices
must acquire their actual component leases. Nested service owners share that
root. Concurrent operations and live/detached entropy records share the global
ledger. There is no 6-GiB reservation and no memory/8 entropy deduction.

A lease first counts as an outstanding allocation. `CommitAllocation` may only
be called after the allocation exists; then current OS free-space measurements
already reflect it and it is not subtracted a second time. Opaque native KDF
calls expose no intermediate allocator callback. Their known matrix lease
therefore remains conservatively pending for the synchronous
allocate/use/wipe/free call and is released on return. This may deny overlapping
optional work conservatively, but does not lower the KDF or retain the matrix
reservation into the following phase. A successful lease is not proof that an
allocation/lock succeeded; those failures still fail closed.

## Parallel work

Container Auto executes its first actual batch with one slot under fresh
admission. That cold batch supplies no accepted throughput baseline. After a
complete joined batch, a seekable source with more than one 16-MiB chunk of
concretely known remaining input may request the initial two-slot window. The
request still passes fresh CPU, RAM, queue, pressure and remaining-work limits.
An unknown nonseekable pipe does not imply two ready chunks: without a verified
read-ahead interface it retains one outer slot and the unchanged native block
parallelism within the actual chunk.

The shared bounded `AdaptiveChunkWindow` retains the accepted window and its
comparison rate during an adjacent larger probe. Three complete healthy batches
may request a one-slot increase, subject to the same fresh limits. A probe rate
at least 10 percent below the accepted rate causes immediate rollback. Otherwise
exactly three complete probe batches must show at least 5 percent median benefit
to accept the larger window; insufficient benefit returns to the accepted window.
A rejected neighbor is not retried because of ordinary noise while the accepted
resource window remains unchanged. A real admission change can invalidate that
earlier rejection. Partial tail batches supply no scaling evidence; nonpositive
and nonfinite rates cannot authorize growth.

Both Auto and fixed diagnostic requests run the same fresh OS observation and
pure planning at initial and fully joined boundaries. A fixed test value is only
a requested window within current admission, never an exemption. Manual values
are ceilings, not commands to create idle workers. CPU ceilings remain
topology-dependent with no global 64/1024-core cut-off, and manual 1 is valid.
Actual locked-memory and CPU leases remain authoritative. Native
producer/consumer permit coordination is a separate required gate.

The [adaptive review](KEEP_VAULT_5_0_3_RESOURCE_ADAPTATION_REV12_REVIEW.md) binds the
new regression and the separate schema-3 focused pipeline comparison. The old
schema-2 failure remains preserved. Focused pipeline rates use the explicitly
isolated test KDF and do not establish production end-to-end or installed AOT
performance. New complete release results remain separate.

## Disk accounting

Extraction and metadata maxima no longer become reservations. RAM-only capture
with zero disk-index bytes does not inspect or create a working directory.
An unavailable explicitly selected working directory fails only when a disk
index is actually required. Original input bytes are not extra output bytes.

Each bounded write can hold a device-keyed `OperationVolumeLedger` lease across
the actual write. Admission reads current free capacity under the same ledger
lock and includes other outstanding writes. The pending bytes are rounded to
4-KiB blocks, with sixteen further blocks (64 KiB) of bounded transaction/entry
headroom. Zero pending work requires zero bytes. This replaces the unconditional
256-MiB floor. A ledger is not an OS disk reservation; foreign writes, quotas,
short writes, ENOSPC and flush/rename failures must still be handled by bound
transactions. Unknown extraction sizes are not fabricated from authorizations.

## Historical REV11 targeted evidence

On 2026-10-01 the following macOS test groups passed in the development harness:

* `resources.rev11-auto-planner`: Auto/copy/manual-reset preservation, 1/2/odd/
  above-cap CPU limits, 1031-CPU arithmetic without creating workers, small/long
  work, measured-growth hysteresis, pressure reduction, missing-observer failure
  and a real current macOS memory observation.
* `resources.operation-storage-plan`: large allowed limits do not reserve disk,
  tiny output accepted on a small synthetic free-space observation, absent unused
  workspace, actual required workspace rejection, descriptor/volume rejection,
  finite output authorization and competing live writes.
* `resources.shared-memory-budget`: actual phase charges and release, nested
  ownership, construction faults, cancelled contention, retained live records,
  controlled pressure failure and standalone pre-KDF index leases.

These are targeted source-level results, not claims of final installed-GUI,
release, multi-TiB or Windows verification. The final integration run must cover
all actual consumers of these contracts and retain fresh source/build hashes.

## Native model and preprocessing admission

`libzpaq::compressBlock` retains the existing input-dependent numeric-method
expansion, including the actual period analysis. A bounded header compilation
then describes the selected model. Checked integer arithmetic charges each VM
array, register array and predictor component, including `Array`'s 128-byte
alignment/guard addition and the native allocator's actual metadata/margin
charge. One shared function selects the LZ hash table or input-sized suffix/
inverse-suffix array for both planning and allocation. The two divsufsort scratch
buckets and the small compressor read window are included. There is no blanket
one-GiB model reservation. Input, queued compressed output and runtime/stack
charges are independently owned by the native caller.

The admission owner is declared before `Compressor` and is destroyed after its
models and the preprocessor. Failed divsufsort allocation now propagates its
error instead of leaving an incomplete suffix array usable. Decompressors have
one small bounded parser/buffer owner and a separate model owner admitted only
before actual predictor initialization. Header-only scans do not reserve unused
model arrays. The next block frees old predictor/VM/postprocessor allocations
before releasing their owner while preserving unread compressed input.

This is a configuration-dependent peak admission, not a measurement of
simultaneously resident bytes. Compiler, suffix-sort scratch and model portions
do not all have identical lifetimes. Therefore the parent keeps this opaque
lease pending until native destruction; it does not falsely mark the whole peak
resident. OS free-memory observations may conservatively count its effects again
while it exists. A targeted test proves controlled denial of an additional
optional allocation in that state, absence of cancellation authority, and
successful admission after native release. macOS builds use `NOJIT`; this report
does not claim parent accounting of executable JIT mappings on other builds.
The existing independent native model-format ceilings are retained.

`native/tests/zpaq_model_budget.cpp` was compiled on macOS arm64 with
`clang++ -std=c++17 -O1 -DNOJIT -DBSD`, linked to the changed `libzpaq.cpp`.
The harness tracks all C/C++ allocations, including the native 80-byte allocator
charge, and verifies that the concrete admission covers the allocation peak and
outlives every model allocation. Methods 0, 1, 2, 3, 4, 5, 6 and 9 roundtrip a
4-KiB input. Their encoder admission ranges from 301134 bytes to 93572027 bytes;
these are particular tested method/input plans, not new global limits. Model
denial emits neither an archive header nor decoded plaintext. Multiple blocks,
header-only scanning, 32 allocation failure sites for method 2, 160 for method 5
and 18 for decompression all pass with released owners and buffers. Evidence:
`work/v13-evidence/rev11-resources/native-model-budget.log`.

## Historical REV11 final resource checks and source comparison

The final managed resource run uses the separately provisioned, verified SDK
and locked package restore through
`work/v13-evidence/rev11-development/run-dotnet.zsh`. Resource tests passed 7/7
and storage policy passed 1/1. The independent single-file allowance now defaults
to the selected finite total extraction allowance; an explicit single-file cap
remains independent. A changing synthetic CPU observation also proves that
published phase ceilings match the corresponding resolved plan.

The storage run includes an actual separate APFS image of 256 MiB with ownership
enabled. An output-volume lease rejects a work-index descriptor on that other
volume; the working-volume lease admits its concrete 204-byte write. The owned
image was detached after the run. The earlier GUI-capacity fixture has ownership
disabled and correctly failed the existing filesystem security gate; that gate
was not relaxed. Logs and result manifests are `resources-final.*`,
`storage-final.*` and `separate-volume-evidence.txt` in the evidence directory.

The protected chunk test covers 1 KiB and 16 MiB minus one, exactly, and plus one
through deliberately short nonseekable reads. Tiny input retains tiny locked
buffers; unknown larger input grows under actual leases, product chunk framing
stays unchanged and cleanup returns both locks and charges. Earlier targeted
`v13-std-framing`, `security.composite-secret-cleanup`,
`security.pipeline-worker-policy` and `security.pipeline-native-concurrency`
runs also passed using trusted installed native test artifacts. Full integration
against newly built, newly anchored native artifacts remains a separate gate.

`crypto-core-baseline-audit.json` compares the current crypto core to pre-REV11
commit `536d7c2afc47a27397f5a611b7ca4a0127067c82`. Of 24 selected managed/native
core files, 23 are byte-identical; `threefish_ref_export.c` differs only by working
copy LF/CRLF normalization. Eleven container methods covering actual chunk
ciphers, nonces, tweaks, strict header validation and key derivation are
byte-identical, as is header creation. Removing only the new progress statements
makes `V13MasterKdf.cs` byte-identical to the baseline. The reader's global and
local checks still compute and require both independent MAC comparisons before
verified state/plaintext delivery. Source comparison and targeted tests establish
these specific invariants; they are not an external audit or a general security
proof. Windows and multi-TiB runtime behavior were not exercised in this run.

## Original deletion is bound before archive creation

The previous macOS deletion path first recorded the source after the archive
had been created. A byte-identical file replacement with restored modification
time could therefore become the newly accepted object. `CreationSnapshot` now
records descriptor-validated source file and directory identities before archive
creation when original deletion is requested. The GUI performs this cancellable
metadata walk on a worker task. No source payload is copied. Entry and metadata
allowances apply incrementally, and working-memory owners remain alive for the
inventory and its derived comparison state.

The snapshot binds file metadata and complete selected-directory topology,
including empty, hidden and Unicode directories. An individual selected file's
parent is bound by identity, so creating an archive beside it may legitimately
change the parent timestamps. Source checks before and after the byte comparison
must agree with the creation inventory. Extracted file and directory sets must
agree in both directions. Byte comparison and its SHA-512 run under a short CPU
grant after each read; buffers use concrete working-memory leases. A comparison
without the pre-creation snapshot cannot grant deletion authority, and a disposed
snapshot cannot be reused.

The same creation identity is retained through the existing quarantine and
rollback protocol. Descriptor and directory-entry checks immediately before
rename reject replacements; the final unlink also checks the bound quarantine
metadata, including change time, so restoring modification time alone cannot
hide a concurrent write. Existing archive digest, symlink/hard-link refusal,
exclusive rollback and descriptor-based cleanup checks remain in force.

The targeted `deletion.rev11-creation-binding` group covers a successful deletion
with a newly created sibling archive, comparison-only refusal, byte-identical
replacement before and after verification, complete empty/Unicode topology,
recreated source directories, disposed/cancelled/over-limit inventories and
released working owners. Live hooks inject replacement immediately before
quarantine rename and before final unlink, plus an in-place quarantine mutation
with restored modification time. Exact final test results and tested DLL/source
hashes are retained in `work/v13-evidence/rev11-resources/deletion-final*`.
The final shared managed build completed without warnings or errors. All five
macOS deletion groups passed against that build and trusted installed native
test artifacts, including the three live race injections. A first copy of the
shared build had overwritten the local signed native test stage; its resulting
native-library refusal is retained separately as `deletion-final-untrusted-stage*`.
Restoring the trusted native test bytes resolved that staging error without any
verification bypass or product change. Newly signed release integration remains
a separate gate.
