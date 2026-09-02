/*
 * Native adapter for AES-256 in CTR mode.
 *
 * This adapter is the v12 production path used directly by
 * NativeAes.XCryptCtr256: by itself for the AES suite and as the innermost
 * stage of the paranoia, ChaCha-over-AES and mixed cascades. It is not a slow
 * fallback behind a separate platform implementation.
 *
 * Crypto++ runtime dispatch selects AES-NI/SIMD on Windows x64 and the ARM AES
 * crypto extensions on Apple silicon when the CPU exposes them. The build must
 * therefore keep the matching assembly/SIMD translation units and feature
 * detection enabled. Published KATs and an implementation outside this adapter
 * provide the independent correctness reference; this file must not describe
 * its own production block function as that independent reference.
 */
#include "rijndael.h"

#include "cryptopp_ctr_common.hpp"

#include <string>

#define AES_KEY_BYTES 32
#define AES_BLOCK_BYTES 16

static_assert(
    CryptoPP::Rijndael::BLOCKSIZE == AES_BLOCK_BYTES,
    "AES block size changed; the container's nonce layout depends on it.");

static_assert(
    AES_KEY_BYTES <= CryptoPP::Rijndael::MAX_KEYLENGTH,
    "AES-256 is outside the key range this build of Crypto++ accepts.");

/* Stable values consumed by the managed verification gate. Keep this export
   read-only: it reports the same AlgorithmProvider branch Rijndael uses for
   encryption and cannot be used to force a faster or slower implementation. */
enum aes_runtime_provider {
    AES_PROVIDER_UNKNOWN = 0,
    AES_PROVIDER_AESNI = 1,
    AES_PROVIDER_ARMV8 = 2,
    AES_PROVIDER_ARMV7 = 3,
    AES_PROVIDER_POWER8 = 4,
    AES_PROVIDER_SSE2 = 5,
    AES_PROVIDER_PORTABLE_CPP = 6
};

extern "C" KEEPVAULT_EXPORT int aes_get_runtime_provider()
{
    try {
        CryptoPP::Rijndael::Encryption cipher;
        const std::string provider = cipher.AlgorithmProvider();
        if (provider == "AESNI") {
            return AES_PROVIDER_AESNI;
        }
        if (provider == "ARMv8") {
            return AES_PROVIDER_ARMV8;
        }
        if (provider == "ARMv7") {
            return AES_PROVIDER_ARMV7;
        }
        if (provider == "Power8") {
            return AES_PROVIDER_POWER8;
        }
        if (provider == "SSE2") {
            return AES_PROVIDER_SSE2;
        }
        if (provider == "C++") {
            return AES_PROVIDER_PORTABLE_CPP;
        }
    } catch (...) {
        /* A read-only diagnostics export must never unwind through C ABI. */
    }

    return AES_PROVIDER_UNKNOWN;
}

extern "C" KEEPVAULT_EXPORT int aes_256_ctr_xcrypt(
    const std::uint8_t key[AES_KEY_BYTES],
    const std::uint8_t nonce[AES_BLOCK_BYTES],
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length)
{
    return keepvault::xcrypt_ctr<CryptoPP::Rijndael::Encryption>(
        key, AES_KEY_BYTES, nonce, input, output, length);
}

/*
 * One block, no counter, for published-vector checks and comparison with the
 * test suite's independent AES implementation.
 */
extern "C" KEEPVAULT_EXPORT int aes_encrypt_block(
    const std::uint8_t* key,
    std::size_t key_length,
    const std::uint8_t input[AES_BLOCK_BYTES],
    std::uint8_t output[AES_BLOCK_BYTES])
{
    if (key == nullptr || input == nullptr || output == nullptr) {
        return 1;
    }

    if (key_length != 16 && key_length != 24 && key_length != 32) {
        return 2;
    }

    CryptoPP::Rijndael::Encryption cipher;
    cipher.SetKey(key, key_length);
    cipher.ProcessBlock(input, output);
    return 0;
}
