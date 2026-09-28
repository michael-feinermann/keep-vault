// v13 Camellia-256 CTR: complete primitive, 128-bit big-endian counter.
#include "camellia_fixed_access.hpp"
#include "bounded_ctr_v13.hpp"
#include <mutex>
namespace {
using Cipher = CryptoPP::CamelliaFixedAccess;
static_assert(Cipher::BLOCKSIZE == 16, "CTR block contract");
bool self_test() noexcept {
    static const bool passed = []() noexcept {
        try {
            const std::uint8_t key[32] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
            const std::uint8_t input[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
            const std::uint8_t expected[16] = {0x9a,0xcc,0x23,0x7d,0xff,0x16,0xd7,0x6c,0x20,0xef,0x7c,0x91,0x9e,0x3a,0x75,0x09};
            std::uint8_t output[16]; Cipher cipher; cipher.SetKey(key,sizeof(key)); cipher.ProcessBlock(input,output);
            const bool equal = CryptoPP::VerifyBufsEqual(output,expected,sizeof(output));
            keepvault::secure_zero(output,sizeof(output)); return equal;
        } catch (...) { return false; }
    }();
    return passed;
}
}
extern "C" KEEPVAULT_EXPORT int keepvault_v13_camellia_256_ctr_xcrypt(
    const std::uint8_t* key, std::size_t key_length, const std::uint8_t* nonce, std::size_t nonce_length,
    const std::uint8_t* input, std::size_t length, std::uint8_t* output, std::size_t output_capacity,
    std::uint32_t workers) noexcept {
    if (!self_test()) return 5;
    return keepvault::bounded_ctr_v13<Cipher>(key,key_length,nonce,nonce_length,input,length,output,output_capacity,workers);
}
extern "C" KEEPVAULT_EXPORT int keepvault_test_v13_camellia_256_encrypt_block(
    const std::uint8_t* key, std::size_t key_length, const std::uint8_t* input, std::size_t input_length,
    std::uint8_t* output, std::size_t output_capacity) noexcept {
    if (key_length != 32 || input_length != 16 || output_capacity < 16
        || !keepvault::valid_memory_range(key,key_length) || !keepvault::valid_memory_range(input,input_length)
        || !keepvault::valid_memory_range(output,output_capacity)) return 1;
    if (!self_test()) return 5;
    try { Cipher cipher; cipher.SetKey(key,key_length); cipher.ProcessBlock(input,output); return 0; }
    catch (...) { return 3; }
}
