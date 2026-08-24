/*
 * Table-driven Kalyna-512/512 encryption, checked against the reference.
 *
 * The reference in external/Kalyna-reference computes every GF(2^8) product of
 * the MDS multiply at run time, one bit at a time: 512 MultiplyGF calls per
 * round, 18 rounds, 9216 per 64-byte block. It is meant to be read, not run.
 *
 * This is the construction the cipher's authors use in their optimised code:
 * the round's S-box substitution, row shift and MDS multiply collapse into
 * eight tables of 256 64-bit words, so a round becomes 64 lookups and 56 XORs.
 * The tables are derived at start-up from the reference's own S-boxes and MDS
 * matrix, so there is no second copy of the constants to keep in step.
 *
 * The reference stays in the binary and stays the arbiter: kalyna_fast_ready
 * refuses the fast path unless it reproduces both the DSTU 7624:2014 vector
 * and the reference's own output on a set of derived keys and blocks.
 */
#ifndef KALYNA_FAST_H
#define KALYNA_FAST_H

#include "../external/Kalyna-reference/kalyna.h"

/*
 * Builds and verifies the tables once per process.
 *
 * Returns 1 when the fast path reproduced the reference exactly and may be
 * used, 0 when it did not. A caller that gets 0 must not fall back quietly:
 * the tables come from the same constants as the reference, so a mismatch
 * means the machine or the build is not doing what the source says.
 */
int kalyna_fast_ready(void);

/*
 * Encrypts one 512-bit block with a key schedule the reference produced.
 *
 * round_keys is kalyna_t.round_keys after KalynaKeyExpand: 19 rows of 8 words.
 * in and out may not overlap.
 */
void kalyna_fast_encipher_512(
    uint64_t* const* round_keys,
    const uint64_t in[8],
    uint64_t out[8]);

#endif /* KALYNA_FAST_H */
