// v13 Serpent-256 CTR: complete primitive, 128-bit big-endian counter.
#include "serpent.h"
#include "bounded_ctr_v13.hpp"
#include <mutex>
namespace {
using Cipher = CryptoPP::Serpent::Encryption;
static_assert(Cipher::BLOCKSIZE == 16, "CTR block contract");
bool self_test() noexcept {
    static const bool passed = []() noexcept {
        try {
            const std::uint8_t key[32] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
            const std::uint8_t input[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
            const std::uint8_t expected[16] = {0xad,0x86,0xde,0x83,0x23,0x1c,0x32,0x03,0xa8,0x6a,0xe3,0x3b,0x72,0x1e,0xaa,0x9f};
            std::uint8_t output[16]; Cipher cipher; cipher.SetKey(key,sizeof(key)); cipher.ProcessBlock(input,output);
            const bool equal = CryptoPP::VerifyBufsEqual(output,expected,sizeof(output));
            keepvault::secure_zero(output,sizeof(output)); return equal;
        } catch (...) { return false; }
    }();
    return passed;
}
}
extern "C" KEEPVAULT_EXPORT int keepvault_v13_serpent_256_ctr_xcrypt(
    const std::uint8_t* key, std::size_t key_length, const std::uint8_t* nonce, std::size_t nonce_length,
    const std::uint8_t* input, std::size_t length, std::uint8_t* output, std::size_t output_capacity,
    std::uint32_t workers) noexcept {
    if (!self_test()) return 5;
    return keepvault::bounded_ctr_v13<Cipher>(key,key_length,nonce,nonce_length,input,length,output,output_capacity,workers);
}
extern "C" KEEPVAULT_EXPORT int keepvault_test_v13_serpent_256_encrypt_block(
    const std::uint8_t* key, std::size_t key_length, const std::uint8_t* input, std::size_t input_length,
    std::uint8_t* output, std::size_t output_capacity) noexcept {
    if (key_length != 32 || input_length != 16 || output_capacity < 16
        || !keepvault::valid_memory_range(key,key_length) || !keepvault::valid_memory_range(input,input_length)
        || !keepvault::valid_memory_range(output,output_capacity)) return 1;
    if (!self_test()) return 5;
    try { Cipher cipher; cipher.SetKey(key,key_length); cipher.ProcessBlock(input,output); return 0; }
    catch (...) { return 3; }
}
