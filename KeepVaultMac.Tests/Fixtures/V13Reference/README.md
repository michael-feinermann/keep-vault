# v13 independent composition vectors

The original composition vectors were generated on 2026-09-21 using .NET SDK 10.0.400 and BouncyCastle.Cryptography 2.6.2, with no Keep Vault production assembly or production helper.

`Generator.cs.txt` contains the complete standalone source. Compile as a net10.0 executable referencing the locked Bouncy Castle 2.6.2 assembly; run with no arguments. `vectors.txt` is the captured output. All credentials, factors, salts and keys are public synthetic test data. Argon2id uses the actual PMI-derived production memory, t=4, p=4 and version 0x13, sequential branches, full prior master as the round-2 secret.

These vectors bind the new v13 domains. They do not establish external audit or cross-platform release evidence.

## REV9 public shuffle vectors, 2026-09-28

`pool_shuffle_rev9_reference.py` is an independent Python model using hashlib
and a prefix-selection encoder. All 13,299 records are public, synthetic and
fully reproducible. SHA512-based public candidate streams are domain-separated
by purpose and round; they are not a production RNG implementation.

`pool_shuffle_rev9_public_vectors.json` is frozen and its SHA-256 is pinned by
`EntropyRev9GoldenTests.cs`. `verify_pool_shuffle_rev9.py` only reads it, compares
all values and checks that its original bytes remain unchanged. The product test
uses actual protected stores, both actual shuffles and both actual replay APIs,
with forward, reverse and parallel pool execution.

To propose a new reference, run the generator with `--candidate NEW_PATH`.
It rejects the frozen fixture path and existing output files. Review any proposed
algorithm, input, fixture and pinned-hash changes together. Neither the verifier
nor an ordinary test run regenerates expected values.

The new reference was created because there were no earlier shuffle vectors;
historical release outputs and historical model PASS claims are not treated as
its provenance. Python objects do not model protected memory or reliable erasure.

## Isolated REV9 pool finalization and 320-byte XOR

`pool_finalization_rev9_reference.py` independently encodes the 80-byte final
transcript in Python and prints public candidate values to stdout. The frozen
`pool_finalization_rev9_vectors.json` pins 22 SHA3/SHA512 outputs across all eleven
purposes and epoch boundaries 0, 1, 2^32-1 and 2^64-1, plus the two five-pool
320-byte XOR values. Its SHA256 is
`87156ec384cc129f233e93bb07bc23c9ff5c0f61aba1f0e2f70852eb491fabbd`.

`check_pool_finalization_rev9.py` reads only: it checks the pinned bytes, all
values and 22 invalid candidate mutations. `entropy.rev9-finalization-golden`
exercises the actual protected finalization helper and the actual product XOR
helper. These are new REV9 public vectors, not historical release outputs.

## Frozen Standard/Paranoia composition, 2026-09-28

See [CASCADE_REFERENCE.md](CASCADE_REFERENCE.md) for all 28 exact four-/eight-stage cases, the separate MARS/SHACAL implementations and published block anchors, actual libsodium/Go completion, fixed SHA-256 and read-only verification. This provenance explicitly distinguishes a separately executed transcription from an independently developed third-party library.

## Raw credential encoding under v13 domains

`credential_encoding_v13_reference.py` independently encodes the six technical credential-limit fixtures with Python `hashlib.sha3_512` and little-endian byte-length prefixes. Empty/short credentials, inputs beyond the creation limits, composed/decomposed Unicode and .NET UTF-8 surrogate replacement are preserved byte-for-byte. Only the mandatory v12-to-v13 domain transition changes the expected digests. Before replacing the six anchors, the same independent encoder reproduced all six historical v12 outputs. The public frozen candidates are in `credential_encoding_v13_vectors.json`; the generator prints candidates without changing that file or either platform's literal test expectations. These fixtures exercise technical reading limits, not password creation acceptance.
