// Explicit v13 CTR buffer contract shared by the new 128-bit block ciphers.
#ifndef KEEPVAULT_BOUNDED_CTR_V13_HPP
#define KEEPVAULT_BOUNDED_CTR_V13_HPP
#include "cryptopp_ctr_common.hpp"
namespace keepvault {
inline bool valid_memory_range(const void* p, std::size_t length) noexcept {
    return length == 0 || (p != nullptr && reinterpret_cast<std::uintptr_t>(p) <= UINTPTR_MAX - length);
}
inline bool memory_ranges_overlap(const void* a, std::size_t al, const void* b, std::size_t bl) noexcept {
    return al && bl && reinterpret_cast<std::uintptr_t>(a) < reinterpret_cast<std::uintptr_t>(b) + bl
        && reinterpret_cast<std::uintptr_t>(b) < reinterpret_cast<std::uintptr_t>(a) + al;
}
template<class Cipher>
int bounded_ctr_v13(const std::uint8_t* key, std::size_t key_length,
    const std::uint8_t* nonce, std::size_t nonce_length,
    const std::uint8_t* input, std::size_t length,
    std::uint8_t* output, std::size_t output_capacity, std::uint32_t workers) noexcept {
    if (key_length != 32 || nonce_length != 16 || length > 16u * 1024u * 1024u
        || output_capacity < length || workers == 0
        || !valid_memory_range(key,key_length) || !valid_memory_range(nonce,nonce_length)
        || !valid_memory_range(input,length) || !valid_memory_range(output,output_capacity)
        || (input != output && memory_ranges_overlap(input,length,output,length))
        || memory_ranges_overlap(output,length,key,key_length) || memory_ranges_overlap(output,length,nonce,nonce_length)) return 1;
    if (length == 0) return 0; // Null data pointers are valid only for empty ranges.
    return xcrypt_ctr<Cipher>(key,key_length,nonce,input,output,length,workers);
}
} // namespace keepvault
#endif
