# Keep Vault 5.0.3: read-only golden verification

Verified on macOS on 1 October 2026. The historical REV9 document defect is not
accepted as evidence: a verifier must not regenerate its own expected values.
The repository already separates the public shuffle generator and verifier.
REV11 adds real filesystem-level failure tests and complete reference-set
negative checks.

`pool_shuffle_rev9_reference.py --candidate NEW_PATH` requires an explicit new
file and refuses the frozen fixture and existing destinations. The normal
`verify_pool_shuffle_rev9.py` reads only and compares the complete independent
public model, including eleven pools, counts, order hashes, both replay rounds
and public XOR outputs. Missing, invalid and modified fixtures fail without
being created, repaired or replaced. Self-test mutations live only in an
exclusive temporary directory and are checked unchanged after rejection.

`verify_reference_set_rev11.py` checks the frozen shuffle, finalization, nonce
and composition references. Fourteen real on-disk mutations cover both factor
halves, second-round outputs, record layout, both five-pool nonce XORs, nonce
basis/routing, AAD and tag. The shuffle/finalization/nonce checks compare against
independently computed Python models. Composition checking pins the reviewed
fixture hash and structure; the separate product composition/KAT tests provide
the actual cryptographic comparison. A hash check alone is not an independent
cipher oracle.

The shuffle self-test rejected eleven missing/invalid/changed files; the broader
set rejected all fourteen additional mutations. Original fixture hashes remained
unchanged. `v13-golden-readonly` passed in the macOS managed harness. Evidence:
`work/v13-evidence/rev11-development/golden-readonly.json`,
`golden-reference-set.json` and `v13-golden-readonly-latest-results.json`.
Reports contain actual UTC execution times and source/verifier/fixture hashes;
the historical fixture-generation dates remain in the reference README.

These public deterministic models do not establish protected-memory erasure,
OS RNG quality, production KDF capacity or release readiness. No historical
shuffle values existed before this project change; no old release result is
claimed as their source. No frozen expected value was changed for REV11.
