/*
 * See kalyna_fast.h for what this is and why the reference stays the arbiter.
 */
#include "kalyna_fast.h"

#include "../external/Kalyna-reference/tables.h"
#include "../external/Kalyna-reference/transformations.h"

#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#endif

#define KALYNA_FAST_NB 8
#define KALYNA_FAST_NR 18
#define KALYNA_FAST_REDUCTION 0x011d

static uint64_t g_tables[KALYNA_FAST_NB][256];
static int g_usable;

/* The reference's MultiplyGF, kept here so the tables are built from the same
   arithmetic they will be checked against rather than from a second reading of
   the specification. It runs 2048 times at start-up and never again. */
static unsigned char multiply_gf(unsigned char x, unsigned char y)
{
    unsigned char result = 0;
    unsigned char high_bit;
    int i;

    for (i = 0; i < 8; ++i) {
        if ((y & 0x1) == 1) {
            result ^= x;
        }
        high_bit = (unsigned char)(x & 0x80);
        x = (unsigned char)(x << 1);
        if (high_bit == 0x80) {
            x ^= (unsigned char)KALYNA_FAST_REDUCTION;
        }
        y = (unsigned char)(y >> 1);
    }

    return result;
}

/*
 * Table b answers: what does the byte sitting in row b of a column contribute
 * to that column once it has been substituted and multiplied by the MDS
 * matrix? Every row of the output takes mds[row][b] times it, so the whole
 * contribution is one 64-bit word and the round is a XOR of eight of them.
 *
 * The S-box index follows the row, and the row shift moves bytes between
 * columns without changing their row, so substitution folds in here and the
 * shift becomes the column each lookup reads from.
 */
static void build_tables(void)
{
    int b;
    int x;
    int row;

    for (b = 0; b < KALYNA_FAST_NB; ++b) {
        for (x = 0; x < 256; ++x) {
            unsigned char substituted = sboxes_enc[b % 4][x];
            uint64_t word = 0;
            for (row = 0; row < 8; ++row) {
                uint64_t product = multiply_gf(substituted, mds_matrix[row][b]);
                word |= product << (row * 8);
            }

            g_tables[b][x] = word;
        }
    }
}

static void encipher_round(const uint64_t in[KALYNA_FAST_NB], uint64_t out[KALYNA_FAST_NB])
{
    int column;

    for (column = 0; column < KALYNA_FAST_NB; ++column) {
        /* Row b of this column was shifted here from column (column - b): that
           is the whole of ShiftRows for a 512-bit block, where the shift equals
           the row index. */
        uint64_t source0 = in[(column + 8 - 0) & 7];
        uint64_t source1 = in[(column + 8 - 1) & 7];
        uint64_t source2 = in[(column + 8 - 2) & 7];
        uint64_t source3 = in[(column + 8 - 3) & 7];
        uint64_t source4 = in[(column + 8 - 4) & 7];
        uint64_t source5 = in[(column + 8 - 5) & 7];
        uint64_t source6 = in[(column + 8 - 6) & 7];
        uint64_t source7 = in[(column + 8 - 7) & 7];

        out[column] =
            g_tables[0][(unsigned char)(source0)] ^
            g_tables[1][(unsigned char)(source1 >> 8)] ^
            g_tables[2][(unsigned char)(source2 >> 16)] ^
            g_tables[3][(unsigned char)(source3 >> 24)] ^
            g_tables[4][(unsigned char)(source4 >> 32)] ^
            g_tables[5][(unsigned char)(source5 >> 40)] ^
            g_tables[6][(unsigned char)(source6 >> 48)] ^
            g_tables[7][(unsigned char)(source7 >> 56)];
    }
}

void kalyna_fast_encipher_512(
    uint64_t* const* round_keys,
    const uint64_t in[KALYNA_FAST_NB],
    uint64_t out[KALYNA_FAST_NB])
{
    uint64_t current[KALYNA_FAST_NB];
    uint64_t next[KALYNA_FAST_NB];
    int round;
    int i;

    /* Kalyna adds the first and last round keys modulo 2^64 and XORs the ones
       between; that asymmetry is part of the cipher, not an accident. */
    for (i = 0; i < KALYNA_FAST_NB; ++i) {
        current[i] = in[i] + round_keys[0][i];
    }

    for (round = 1; round < KALYNA_FAST_NR; ++round) {
        encipher_round(current, next);
        for (i = 0; i < KALYNA_FAST_NB; ++i) {
            current[i] = next[i] ^ round_keys[round][i];
        }
    }

    encipher_round(current, next);
    for (i = 0; i < KALYNA_FAST_NB; ++i) {
        out[i] = next[i] + round_keys[KALYNA_FAST_NR][i];
    }

    memset(current, 0, sizeof(current));
    memset(next, 0, sizeof(next));
}

/* The published DSTU 7624:2014 vector for the 512-bit block, 512-bit key
   variant, taken from the reference's own test driver. */
static const uint64_t kVectorKey[KALYNA_FAST_NB] = {
    0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL, 0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL,
    0x2726252423222120ULL, 0x2f2e2d2c2b2a2928ULL, 0x3736353433323130ULL, 0x3f3e3d3c3b3a3938ULL
};

static const uint64_t kVectorPlaintext[KALYNA_FAST_NB] = {
    0x4746454443424140ULL, 0x4f4e4d4c4b4a4948ULL, 0x5756555453525150ULL, 0x5f5e5d5c5b5a5958ULL,
    0x6766656463626160ULL, 0x6f6e6d6c6b6a6968ULL, 0x7776757473727170ULL, 0x7f7e7d7c7b7a7978ULL
};

static const uint64_t kVectorCiphertext[KALYNA_FAST_NB] = {
    0x6a351c811be3264aULL, 0x1a239605cad61da6ULL, 0xa1f347aa5483ba67ULL, 0xb856eb20c3ee1d3eULL,
    0x66ab5b1717f4d095ULL, 0x6cc815bb34f1d62fULL, 0xb7fe6e85266a90cbULL, 0xd9d90d947264bcc5ULL
};

/* A counter run through a 64-bit mix, so the checked keys and blocks are
   spread over the input space without pulling in a random source at start-up
   and without freezing a table of magic numbers into this file. */
static uint64_t derive_word(uint64_t counter)
{
    counter += 0x9e3779b97f4a7c15ULL;
    counter = (counter ^ (counter >> 30)) * 0xbf58476d1ce4e5b9ULL;
    counter = (counter ^ (counter >> 27)) * 0x94d049bb133111ebULL;
    return counter ^ (counter >> 31);
}

static int verify_against_reference(void)
{
    kalyna_t* ctx;
    uint64_t key[KALYNA_FAST_NB];
    uint64_t plaintext[KALYNA_FAST_NB];
    uint64_t expected[KALYNA_FAST_NB];
    uint64_t actual[KALYNA_FAST_NB];
    uint64_t counter = 0;
    int trial;
    int i;
    int matched = 1;

    ctx = KalynaInit(512, 512);
    if (ctx == NULL) {
        return 0;
    }

    /* First the published vector: it anchors the tables to the standard, not
       merely to the reference's reading of it. */
    memcpy(key, kVectorKey, sizeof(key));
    KalynaKeyExpand(key, ctx);
    kalyna_fast_encipher_512(ctx->round_keys, kVectorPlaintext, actual);
    if (memcmp(actual, kVectorCiphertext, sizeof(actual)) != 0) {
        matched = 0;
    }

    /* Then the reference itself, over keys and blocks that exercise every
       table entry rather than the one path a single vector walks. */
    for (trial = 0; matched && trial < 64; ++trial) {
        for (i = 0; i < KALYNA_FAST_NB; ++i) {
            key[i] = derive_word(counter++);
            plaintext[i] = derive_word(counter++);
        }

        KalynaKeyExpand(key, ctx);
        KalynaEncipher((uint64_t*)plaintext, ctx, expected);
        kalyna_fast_encipher_512(ctx->round_keys, plaintext, actual);
        if (memcmp(actual, expected, sizeof(actual)) != 0) {
            matched = 0;
        }
    }

    memset(key, 0, sizeof(key));
    memset(plaintext, 0, sizeof(plaintext));
    memset(expected, 0, sizeof(expected));
    memset(actual, 0, sizeof(actual));
    KalynaDelete(ctx);
    return matched;
}

static void prepare_once(void)
{
    build_tables();
    g_usable = verify_against_reference();
    if (!g_usable) {
        memset(g_tables, 0, sizeof(g_tables));
    }
}

#if defined(_WIN32)
static INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK prepare_once_callback(PINIT_ONCE once, PVOID parameter, PVOID* context)
{
    (void)once;
    (void)parameter;
    (void)context;
    prepare_once();
    return TRUE;
}

int kalyna_fast_ready(void)
{
    if (!InitOnceExecuteOnce(&g_once, prepare_once_callback, NULL, NULL)) {
        return 0;
    }

    return g_usable;
}
#else
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

int kalyna_fast_ready(void)
{
    pthread_once(&g_once, prepare_once);
    return g_usable;
}
#endif
