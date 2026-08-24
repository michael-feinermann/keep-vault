/*
 * Native adapter for ChaCha20-Poly1305 (RFC 8439).
 *
 * The outermost layer of the v9 paranoia cascade, and the only one that is not
 * a block cipher in CTR mode. It authenticates as well as encrypts, so it does
 * not fit the shared CTR driver: it needs a nonce of its own width, produces a
 * tag, and on decryption either returns the plaintext or refuses.
 *
 * Poly1305 is additional to, not a replacement for, the container's existing
 * HMAC-SHA3-512 and Skein-MAC-1024. It authenticates the outermost ciphertext
 * as that layer sees it; the other two authenticate the container.
 *
 * Deliberately not parallelised. Poly1305 is a single pass over the ciphertext
 * with a carry chain, so splitting it means recombining polynomial evaluations,
 * and the wrong recombination produces a tag that is merely different rather
 * than obviously broken. The layer beneath it is already parallel, and this one
 * runs at the speed of one core over data that has been through five ciphers.
 */
#include "chacha.h"
#include "misc.h"
#include "poly1305.h"

#include "cryptopp_ctr_common.hpp"

#define CHACHAPOLY_KEY_BYTES 32
#define CHACHAPOLY_NONCE_BYTES 12
#define CHACHAPOLY_TAG_BYTES 16

/*
 * Raw ChaCha20, and Poly1305 over a whole stream.
 *
 * The cascade cannot use the AEAD above for its outer layer. The container
 * encrypts in 16 MiB chunks and authenticates the finished ciphertext, so an
 * AEAD applied per chunk would produce a tag per chunk that says nothing about
 * the order those chunks appear in — dropping or swapping two of them would
 * leave every tag valid. Poly1305 is therefore run once over the entire
 * ciphertext, beside the container's HMAC-SHA3-512 and Skein-MAC-1024, where it
 * covers ordering and length as well as content.
 *
 * That needs the two halves separately: ChaCha20 as a keystream generator the
 * chunk loop can position by block, and Poly1305 as something that can be fed
 * incrementally.
 */
/*
 * Encrypts or decrypts, starting at an explicit block counter.
 *
 * ChaChaTLS, not ChaCha: Crypto++ carries both Bernstein's original with its
 * 8-byte nonce and the IETF form from RFC 8439 with a 12-byte nonce and a
 * 32-bit block counter. The container uses the IETF form, and the two produce
 * different keystreams from the same inputs.
 *
 * The counter is what lets a chunk be processed on its own: the caller passes
 * the block index the chunk begins at, so the keystream lines up with the
 * position in the stream rather than restarting per call.
 */
/* One contiguous range, keyed at the block the range starts on. Internal:
   the exported name below spreads a request across workers. */
static int chacha20_range(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    std::uint32_t block_counter,
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length)
{
    if (key == nullptr || nonce == nullptr) {
        return 1;
    }

    if (length != 0 && (input == nullptr || output == nullptr)) {
        return 1;
    }

    try {
        // The initial block counter is not part of the IV. Crypto++ reads it
        // from an "InitialBlock" parameter at SetKey time and puts it in
        // state[12]; the 12-byte nonce goes to state[13..15], exactly as
        // RFC 8439 section 2.3 lays the state out. Building a 16-byte
        // counter||nonce IV instead — which is what an earlier version of this
        // function did — produces a different keystream that matches neither
        // the RFC nor this file's own AEAD.
        CryptoPP::ChaChaTLS::Encryption cipher;
        cipher.SetKeyWithIV(
            key,
            CHACHAPOLY_KEY_BYTES,
            nonce,
            CHACHAPOLY_NONCE_BYTES);
        cipher.SetKey(
            key,
            CHACHAPOLY_KEY_BYTES,
            CryptoPP::MakeParameters(
                "InitialBlock", static_cast<CryptoPP::word64>(block_counter))
                (CryptoPP::Name::IV(),
                 CryptoPP::ConstByteArrayParameter(nonce, CHACHAPOLY_NONCE_BYTES)));
        cipher.ProcessData(output, input, length);
        return 0;
    } catch (...) {
        return 5;
    }
}

/*
 * The same keystream, produced by several workers at once.
 *
 * ChaCha20 numbers its 64-byte blocks and derives each one from the counter
 * alone, so a worker that starts at block n needs nothing from the worker
 * before it: it keys its own cipher with InitialBlock = counter + n. Ranges
 * begin on block boundaries, which is what makes the output identical to the
 * serial path byte for byte. The block ciphers beside it split on exactly the
 * same reasoning.
 *
 * RFC 8439 gives the counter 32 bits. Past 2^32 blocks it would wrap and
 * repeat keystream, so a request that would reach the wrap is refused rather
 * than served quietly.
 */
extern "C" KEEPVAULT_EXPORT int chacha20_xcrypt(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    std::uint32_t block_counter,
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length)
{
    constexpr std::size_t kChaChaBlockBytes = 64;

    if (key == nullptr || nonce == nullptr) {
        return 1;
    }

    if (length != 0 && (input == nullptr || output == nullptr)) {
        return 1;
    }

    if (length == 0) {
        return 0;
    }

    if (length > SIZE_MAX - (kChaChaBlockBytes - 1)) {
        return 4;
    }

    const std::size_t total_blocks = (length + kChaChaBlockBytes - 1) / kChaChaBlockBytes;
    if (total_blocks > static_cast<std::size_t>(UINT32_MAX) - block_counter) {
        return 4;
    }

    const std::size_t chunk_blocks = keepvault::kChunkBytes / kChaChaBlockBytes;
    std::size_t thread_count = 1;
    if (length >= keepvault::kParallelThresholdBytes) {
        const unsigned hardware = std::thread::hardware_concurrency();
        thread_count = hardware == 0 ? 1 : static_cast<std::size_t>(hardware);
        const std::size_t chunks = (total_blocks + chunk_blocks - 1) / chunk_blocks;
        if (thread_count > chunks) {
            thread_count = chunks;
        }
        if (thread_count > keepvault::kMaxThreads) {
            thread_count = keepvault::kMaxThreads;
        }
        if (thread_count == 0) {
            thread_count = 1;
        }
    }

    if (thread_count <= 1) {
        return chacha20_range(key, nonce, block_counter, input, output, length);
    }

    std::atomic<std::size_t> next_chunk{0};
    std::atomic<int> failure{0};

    auto worker = [&]() noexcept {
        try {
            for (;;) {
                const std::size_t chunk = next_chunk.fetch_add(1, std::memory_order_relaxed);
                const std::size_t first_block = chunk * chunk_blocks;
                if (first_block >= total_blocks) {
                    return;
                }

                const std::size_t offset = first_block * kChaChaBlockBytes;
                const std::size_t span = chunk_blocks * kChaChaBlockBytes;
                const std::size_t remaining = length - offset;
                const std::size_t count = remaining < span ? remaining : span;
                const std::uint32_t counter =
                    block_counter + static_cast<std::uint32_t>(first_block);

                const int result = chacha20_range(
                    key, nonce, counter, input + offset, output + offset, count);
                if (result != 0) {
                    failure.store(result, std::memory_order_relaxed);
                    return;
                }
            }
        } catch (...) {
            failure.store(3, std::memory_order_relaxed);
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(thread_count - 1);
    try {
        for (std::size_t i = 1; i < thread_count; ++i) {
            threads.emplace_back(worker);
        }
    } catch (...) {
        /* Fewer threads than hoped is not an error; this one runs the rest. */
    }

    worker();

    for (std::thread& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    return failure.load(std::memory_order_relaxed);
}

/*
 * The same keystream from one thread, whatever the length.
 *
 * Exported for the test suite, which holds the worker-split path against it
 * over buffers far larger than a self-check can afford, across keys, nonces and
 * starting block counters. It is the identical range function the serial path
 * uses, so a difference can only come from the split itself.
 *
 * Nothing in the application calls this.
 */
extern "C" KEEPVAULT_EXPORT int chacha20_xcrypt_serial(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    std::uint32_t block_counter,
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length)
{
    constexpr std::size_t kChaChaBlockBytes = 64;

    if (length == 0) {
        return (key == nullptr || nonce == nullptr) ? 1 : 0;
    }

    if (length > SIZE_MAX - (kChaChaBlockBytes - 1)) {
        return 4;
    }

    /* The same refusal as the exported path: a comparison against a keystream
       the counter could not legitimately produce proves nothing. */
    const std::size_t total_blocks = (length + kChaChaBlockBytes - 1) / kChaChaBlockBytes;
    if (total_blocks > static_cast<std::size_t>(UINT32_MAX) - block_counter) {
        return 4;
    }

    return chacha20_range(key, nonce, block_counter, input, output, length);
}

/*
 * Poly1305 over a stream, in three calls.
 *
 * This is the RFC 8439 form, which takes the 32-byte one-time key r||s
 * directly, rather than Bernstein's original AES-keyed variant.
 *
 * The one-time key is the caller's to supply and must never be reused with a
 * different message: Poly1305 is a one-time authenticator, and two messages
 * under one key hand an attacker the ability to forge a third. The container
 * derives it per archive from the Argon2id output.
 */
extern "C" KEEPVAULT_EXPORT void* poly1305_create(const std::uint8_t key[32])
{
    if (key == nullptr) {
        return nullptr;
    }

    try {
        auto* mac = new CryptoPP::Poly1305TLS();
        mac->SetKey(key, 32);
        return mac;
    } catch (...) {
        return nullptr;
    }
}

extern "C" KEEPVAULT_EXPORT int poly1305_update(void* handle, const std::uint8_t* data, std::size_t length)
{
    if (handle == nullptr || (length != 0 && data == nullptr)) {
        return 1;
    }

    try {
        static_cast<CryptoPP::Poly1305TLS*>(handle)->Update(data, length);
        return 0;
    } catch (...) {
        return 5;
    }
}

extern "C" KEEPVAULT_EXPORT int poly1305_final(void* handle, std::uint8_t tag[CHACHAPOLY_TAG_BYTES])
{
    if (handle == nullptr || tag == nullptr) {
        return 1;
    }

    try {
        static_cast<CryptoPP::Poly1305TLS*>(handle)->Final(tag);
        return 0;
    } catch (...) {
        return 5;
    }
}

extern "C" KEEPVAULT_EXPORT void poly1305_destroy(void* handle)
{
    delete static_cast<CryptoPP::Poly1305TLS*>(handle);
}

/*
 * ChaCha20-Poly1305 (RFC 8439), with the cipher half spread across workers.
 *
 * Crypto++ has its own ChaCha20Poly1305, and this file used to call it. It runs
 * the whole request on one thread, which left the outermost layer of every
 * cascade at the speed of a single core over data five ciphers had already
 * touched - the slowest stage in the catalogue by a wide margin.
 *
 * The two halves of the construction do not have the same constraint. ChaCha20
 * numbers its blocks and derives each from the counter alone, so it splits
 * exactly as it does above. Poly1305 is a carry chain over the whole message
 * and stays on one thread; splitting it would mean recombining polynomial
 * evaluations, and the wrong recombination gives a tag that is merely different
 * rather than obviously broken. So the keystream is parallel, the tag is not,
 * and the AEAD runs at whatever Poly1305 alone can do.
 *
 * Assembling the construction here rather than calling the library's means this
 * file now owns the framing, so the framing is what the tests hold against the
 * implementation this replaced, across every length where the padding changes
 * shape and every associated-data length beside it.
 */

/*
 * RFC 8439 section 2.6: the one-time Poly1305 key is the first 32 bytes of the
 * ChaCha20 keystream for this key and nonce at block counter 0. The message
 * starts at block 1, which is exactly why the AEAD and the raw keystream export
 * differ by one block.
 */
static int derive_poly1305_key(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    std::uint8_t one_time_key[CHACHAPOLY_KEY_BYTES])
{
    std::uint8_t zeros[CHACHAPOLY_KEY_BYTES];
    std::memset(zeros, 0, sizeof(zeros));
    return chacha20_range(key, nonce, 0, zeros, one_time_key, CHACHAPOLY_KEY_BYTES);
}

/*
 * RFC 8439 section 2.8: the associated data zero-padded to a multiple of 16,
 * the ciphertext zero-padded the same way, then both lengths as 64-bit little
 * endian. The padding and the lengths are what stop a byte moving from one
 * field into the other without changing the tag.
 */
static void poly1305_pad_to_16(CryptoPP::Poly1305TLS& mac, std::size_t length)
{
    const std::size_t remainder = length % 16;
    if (remainder != 0) {
        std::uint8_t zeros[16];
        std::memset(zeros, 0, sizeof(zeros));
        mac.Update(zeros, 16 - remainder);
    }
}

static void poly1305_append_length(CryptoPP::Poly1305TLS& mac, std::size_t length)
{
    std::uint8_t encoded[8];
    const std::uint64_t value = static_cast<std::uint64_t>(length);
    for (int i = 0; i < 8; ++i) {
        encoded[i] = static_cast<std::uint8_t>(value >> (i * 8));
    }

    mac.Update(encoded, sizeof(encoded));
}

static int compute_tag(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* ciphertext,
    std::size_t length,
    std::uint8_t tag[CHACHAPOLY_TAG_BYTES])
{
    std::uint8_t one_time_key[CHACHAPOLY_KEY_BYTES];
    const int derived = derive_poly1305_key(key, nonce, one_time_key);
    if (derived != 0) {
        keepvault::secure_zero(one_time_key, sizeof(one_time_key));
        return derived;
    }

    try {
        CryptoPP::Poly1305TLS mac;
        mac.SetKey(one_time_key, sizeof(one_time_key));
        keepvault::secure_zero(one_time_key, sizeof(one_time_key));

        if (associated_length != 0) {
            mac.Update(associated_data, associated_length);
        }
        poly1305_pad_to_16(mac, associated_length);

        if (length != 0) {
            mac.Update(ciphertext, length);
        }
        poly1305_pad_to_16(mac, length);

        poly1305_append_length(mac, associated_length);
        poly1305_append_length(mac, length);

        mac.Final(tag);
        return 0;
    } catch (...) {
        keepvault::secure_zero(one_time_key, sizeof(one_time_key));
        return 5;
    }
}

static int validate_aead_arguments(
    const std::uint8_t* key,
    const std::uint8_t* nonce,
    const std::uint8_t* tag,
    const std::uint8_t* input,
    const std::uint8_t* output,
    std::size_t length,
    const std::uint8_t* associated_data,
    std::size_t associated_length)
{
    if (key == nullptr || nonce == nullptr || tag == nullptr) {
        return 1;
    }

    if (length != 0 && (input == nullptr || output == nullptr)) {
        return 1;
    }

    if (associated_length != 0 && associated_data == nullptr) {
        return 1;
    }

    return 0;
}

/*
 * Encrypts and authenticates.
 *
 * The tag is written separately rather than appended, so the caller decides
 * where it lives and the ciphertext keeps the length of the plaintext.
 *
 * The tag covers the ciphertext, so it is taken after encryption; input and
 * output may be the same buffer, which is how the container calls it.
 */
extern "C" KEEPVAULT_EXPORT int chacha20poly1305_encrypt(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* plaintext,
    std::uint8_t* ciphertext,
    std::size_t length,
    std::uint8_t tag[CHACHAPOLY_TAG_BYTES])
{
    const int invalid = validate_aead_arguments(
        key, nonce, tag, plaintext, ciphertext, length, associated_data, associated_length);
    if (invalid != 0) {
        return invalid;
    }

    const int encrypted = chacha20_xcrypt(key, nonce, 1, plaintext, ciphertext, length);
    if (encrypted != 0) {
        return encrypted;
    }

    return compute_tag(key, nonce, associated_data, associated_length, ciphertext, length, tag);
}

/*
 * Verifies, then decrypts.
 *
 * Returns 6 when the tag does not match, and in that case writes nothing at
 * all: the tag is checked before a single byte of plaintext is produced, so
 * there is no window in which unauthenticated plaintext exists in the caller's
 * buffer. The previous implementation decrypted first and relied on Crypto++
 * clearing the output afterwards.
 *
 * The comparison is constant time. A tag check that returns early on the first
 * wrong byte tells an attacker how much of a forged tag was right.
 *
 * Reading the ciphertext for the tag before overwriting it is also what makes
 * an in-place call safe, which is how the container decrypts.
 */
extern "C" KEEPVAULT_EXPORT int chacha20poly1305_decrypt(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* ciphertext,
    std::uint8_t* plaintext,
    std::size_t length,
    const std::uint8_t tag[CHACHAPOLY_TAG_BYTES])
{
    const int invalid = validate_aead_arguments(
        key, nonce, tag, ciphertext, plaintext, length, associated_data, associated_length);
    if (invalid != 0) {
        return invalid;
    }

    std::uint8_t expected[CHACHAPOLY_TAG_BYTES];
    const int tagged = compute_tag(
        key, nonce, associated_data, associated_length, ciphertext, length, expected);
    if (tagged != 0) {
        keepvault::secure_zero(expected, sizeof(expected));
        return tagged;
    }

    const bool authentic = CryptoPP::VerifyBufsEqual(expected, tag, CHACHAPOLY_TAG_BYTES);
    keepvault::secure_zero(expected, sizeof(expected));
    if (!authentic) {
        return 6;
    }

    return chacha20_xcrypt(key, nonce, 1, ciphertext, plaintext, length);
}
