# v13 native cryptographic checks

`test_xchacha_v13.py` checks the production native ABI using public synthetic
inputs. It compares complete ciphertext and detached tag bytes against both
libsodium through PyNaCl 1.6.2 and Go `golang.org/x/crypto` v0.43.0. An additional
full `CryptoPP::XChaCha20Poly1305` oracle does not use Keep Vault's HChaCha20 or
transcript implementation. The scalar Keep Vault path shares the construction
and is only a differential reference.

The fixed vectors retain their original identifiers:

* draft-irtf-cfrg-xchacha-03 section 2.2.1: HChaCha20 subkey.
* draft-irtf-cfrg-xchacha-03 appendix A.3.1: complete AEAD ciphertext and tag.
* RFC 8439 raw ChaCha20 counter tests use the separate test primitive ABI.

The suite covers every one of the 24 nonce bytes, all 16 tag bytes, key and AAD
mutation, empty payload/AAD, pad16 and 64-byte boundaries, 256-KiB and 1-MiB
worker thresholds, 16 MiB minus one and exactly 16 MiB, rejection of larger
calls, worker counts 1/2/3/4/7/8/16/32/64, exact in-place processing, partial
alias rejection, null pointers, explicit key/nonce/tag/output lengths, and raw
counter overflow before output. It also runs 10,000 reproducible randomized
small records using seed `0x4b565f563133`. No record exceeds 16 MiB.

The repository stores dependency versions, Go module checksums and source
hashes in `xchacha-reference-provenance.json` and `xchacha_go_reference/go.sum`.
The bundled libsodium version is taken from PyNaCl's release metadata because
its Python extension does not export `sodium_version_string`. These dependencies
are tests only and are not included in application bundles.

Example from the repository root with an already verified Go installation:

```sh
python3 -m venv work/v13-native/venv
work/v13-native/venv/bin/pip install PyNaCl==1.6.2
(cd native/tests/xchacha_go_reference && go build -o ../../../work/v13-native/xchacha-go-oracle .)
work/v13-native/venv/bin/python native/tests/test_xchacha_v13.py \
  work/v13-native/libxchachapoly_v13.dylib \
  --go-oracle work/v13-native/xchacha-go-oracle \
  --report work/v13-native/xchacha-interop-arm64.json
```

The ctypes runner deliberately tests a specified build directly. It does not
replace the application's native hash/signature verification or installed-app
checks. `KeepVaultMac/Packaging/NativeKats.c` exercises the same published KATs
for each executable macOS slice, including the independent ML-DSA adapter.
Windows execution is a separate gate.

## Product ABI

The managed product uses `keepvault_xchacha20poly1305_v13_encrypt_with_budget`
and `keepvault_xchacha20poly1305_v13_decrypt_with_budget` in
`xchachapoly_v13.dll` or `libxchachapoly_v13.dylib`. Parameter pairs are:

```
key pointer, key length (32)
nonce pointer, nonce length (24)
AAD pointer, AAD length
input pointer, payload length (0..16777216)
output pointer, output capacity (at least payload length)
tag pointer, tag length (16)
worker grant including caller (uint32_t, at least 1)
```

All lengths are `size_t` / managed `nuint`, with the platform C calling
convention. Status 0 is success, 1 invalid arguments, 3 worker failure,
4 counter/length exhaustion, 5 cryptographic failure and 6 tag mismatch.
The unchanged planner may return its existing additional status codes. An
invalid tag writes no plaintext. Input/output may be exactly identical;
partial overlaps and mutable-output overlap with key, nonce, AAD or tag are
rejected before key derivation. Separate explicitly named test exports select
worker counts, shared scalar construction, full Crypto++ oracle and HChaCha20.
No old 12-byte product AEAD exports are available.
The versioned convenience exports without `_with_budget` retain the same
pointer/length pairs and execute with a grant of one.

HChaCha20 is implemented directly from the draft's algorithm with 20 rounds,
no feed-forward, and little-endian output words 0,1,2,3,12,13,14,15. No upstream
implementation text was copied. Derived key/nonce and Poly1305 key/tag scratch
are wiped by scope guards, including exceptional paths. This is not a claim
that compiler registers, library-internal state or the operating system can be
fully erased by the application.

## Measured optimization choices

On the current macOS arm64 host, the duplicate ChaCha `SetKeyWithIV` call was
removed; the subsequent `SetKey` already contains the IV and InitialBlock and
uses the specified 20 rounds. Independent oracles and both macOS slice KATs
pass. Seven alternating measured samples after warm-up showed median gains of
1.8% at 64 bytes, 1.2% at 4096 bytes and 4.5% at 16 MiB. The large-message timings
have visible scheduler noise and are not a container performance claim.

A per-worker CTR key-schedule reuse candidate was measured for AES, MARS and
SHACAL-2. It improved throughput for AES and SHACAL-2
but regressed MARS by approximately 12.7%, so that early broad candidate was
rejected. REV9 subsequently explicitly requires operation-local worker schedule
reuse when supported. The final shared driver therefore keys once per exclusive
worker and constructs fresh CTR state per absolute claim; the old measurements
are historical, not final-revision performance evidence. Full raw measurements are under
`docs/evidence/v13-native-20260921`. Manual Windows processor-group pinning was
removed because it can narrow the modern Windows scheduler's allowed set;
Windows host validation remains required.

## REV9 Camellia, Serpent and shared executor

`camellia_serpent_reference` is an independent Bouncy Castle 2.6.2 program.
It calls only block encryption and implements full-width big-endian CTR itself.
Its locked dependency and the published vectors in
`camellia-serpent-vectors.json` are test-only. `test_camellia_serpent_v13.py`
compares both actual product libraries against this program, including 10,000
deterministic small records per cipher and boundary/invalid-ABI cases.

`generate_ctr_corpus.py` materializes public reference records for the separate
C runner `ctr_corpus_runner.c`, usable under Rosetta and instrumented builds.
`run_ctr_sanitizers_macos.py` compiles the new adapters, fixed-access Camellia
and shared CTR driver under ASan/UBSan and TSan, then runs the corpus. The
linked vendor archive is not instrumented. Apple arm64 LeakSanitizer is
unavailable and is explicitly disabled; this is not a leak-free claim.

`managed_executor` links the actual managed executor with test-only fault
injection. It checks joins after failed submissions, subsequent reuse and
all eight real cipher implementations with worker grants through 4096.
These are logical jobs on the measured host, not a 4096-physical-core test.
`worker_budget_macos.c` samples actual thread counts while comparing grants
and ciphertexts; source review supplements its finite sampling interval.

`native_benchmark` links the same executor and actual product exports. Every
timed run processes 256 MiB in sixteen 16-MiB calls, with a complete warmup
and five repetitions. It can compare shared execution with bounded standalone
native teams. This primitive measurement excludes KDF, container nonces,
global MACs and I/O. `build_claim_grain_macos.py` and `claim_grain` build and
compare isolated preferred-grain candidates without changing production
sources. Conclusions and limitations are in
`docs/KEEP_VAULT_5_0_3_OPTIMIZATION_REPORT.md`; raw evidence and exact native
binary hashes are in `docs/evidence/v13-native-rev9-20260928`.

Sources: [XChaCha draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03),
[PyNaCl 1.6.2](https://github.com/pyca/pynacl/tree/1.6.2),
[Go reference](https://pkg.go.dev/golang.org/x/crypto@v0.43.0/chacha20poly1305),
[Windows processor groups](https://learn.microsoft.com/en-us/windows/win32/procthread/processor-groups).

`complete_cascade_outer_v13.py` finishes the shared Standard/Paranoia
composition fixture using the exact ciphertext after its final inner CTR stage.
Both independent AEAD implementations (libsodium and Go) must agree with each
other and with the actual native product at grants 1/2/10 before the fixture is
written. It records full source, oracle executable and native-library hashes.
It never substitutes a separately chosen message for the cascade output.
