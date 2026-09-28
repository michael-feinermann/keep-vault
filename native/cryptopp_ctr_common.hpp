/*
 * Shared CTR driver for the Crypto++-backed block ciphers.
 *
 * The Kalyna and Threefish adapters have dedicated drivers. Crypto++-backed
 * AES, MARS, SHACAL-2, Camellia and Serpent share this implementation and the
 * registered, synchronously borrowed executor. Its behaviour matches the
 * adapters: same counter arithmetic, same claimed-chunk work queue, same
 * ciphertext regardless of how many threads run.
 */
#ifndef KEEPVAULT_CRYPTOPP_CTR_COMMON_HPP
#define KEEPVAULT_CRYPTOPP_CTR_COMMON_HPP

#include "modes.h"
#include "borrowed_executor_v13.h"
#include "adaptive_work_v13.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#define KEEPVAULT_EXPORT __declspec(dllexport)
#else
#define KEEPVAULT_EXPORT __attribute__((visibility("default")))
#endif

namespace keepvault {

/* Below this the thread hand-off costs more than it saves. */
constexpr std::size_t kParallelThresholdBytes = 1024u * 1024u;

/* Preferred claim size, reduced by the adaptive helper when the permitted
   worker count needs more independently executable block-aligned ranges. */
constexpr std::size_t kChunkBytes = 256u * 1024u;

/*
 * Every logical processor on the machine, hyperthreads included.
 *
 * std::thread::hardware_concurrency is not enough on Windows: what it reports
 * for a machine split into processor groups depends on the C++ runtime, and the
 * answer that matters here is the one the operating system gives for all groups
 * together.
 */
inline std::size_t logical_processor_count() noexcept
{
#if defined(_WIN32)
    const DWORD active = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (active > 0) {
        return static_cast<std::size_t>(active);
    }
#endif
    const unsigned hardware = std::thread::hardware_concurrency();
    return hardware == 0 ? 1 : static_cast<std::size_t>(hardware);
}

#if defined(_WIN32)
// Windows 11 / Server 2022 schedule across processor groups by default.
// Explicit pinning would narrow that affinity and ignore job restrictions.
// Keep the call site inert unless an older supported host is separately
// measured and an affinity-respecting compatibility strategy is justified.
inline void bind_worker_to_processor_group(std::size_t) noexcept {}
#endif

inline void secure_zero(void* pointer, std::size_t length) noexcept
{
    volatile unsigned char* target = static_cast<volatile unsigned char*>(pointer);
    while (length-- > 0) {
        *target++ = 0;
    }
}

struct ScopedWipe final {
    void* pointer;
    std::size_t length;
    ScopedWipe(void* target, std::size_t bytes) noexcept : pointer(target), length(bytes) {}
    ~ScopedWipe() noexcept { secure_zero(pointer, length); }
    ScopedWipe(const ScopedWipe&) = delete;
    ScopedWipe& operator=(const ScopedWipe&) = delete;
};

/*
 * Adds a block count to a big-endian counter that spans the whole nonce.
 *
 * The counter is the nonce, so it is as wide as the cipher's block. Carrying
 * across the entire width rather than a trailing field is what lets a worker
 * jump straight to the block it claimed without walking there.
 */
inline bool add_counter_blocks(
    std::uint8_t* counter,
    std::size_t counter_length,
    std::uint64_t blocks) noexcept
{
    std::size_t index = counter_length;
    std::uint64_t carry = blocks;
    while (index-- > 0 && carry != 0) {
        std::uint64_t sum = static_cast<std::uint64_t>(counter[index]) + (carry & 0xFFu);
        counter[index] = static_cast<std::uint8_t>(sum & 0xFFu);
        carry >>= 8;
        carry += sum >> 8;
    }

    return carry != 0;
}

/*
 * Encrypts or decrypts one range under an exclusively owned keyed cipher.
 *
 * CTR is its own inverse, so this one path serves both directions. Each worker
 * keys its own cipher instance once: Crypto++ block ciphers hold an expanded
 * schedule. Only the separately constructed CTR state changes between claims;
 * no instance is shared concurrently with another worker.
 */
template <typename Encryption>
inline int xcrypt_ctr_keyed_range(
    Encryption& cipher,
    const std::uint8_t* nonce,
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length,
    std::size_t first_block)
{
    constexpr std::size_t block_bytes = Encryption::BLOCKSIZE;

    std::uint8_t counter[block_bytes];
    const ScopedWipe wipe_counter(counter, sizeof(counter));
    std::memcpy(counter, nonce, block_bytes);
    if (add_counter_blocks(counter, block_bytes, static_cast<std::uint64_t>(first_block))) {
        return 4;
    }

    // Crypto++'s CTR policy feeds aligned runs to AdvancedProcessBlocks with
    // BT_InBlockIsCounter | BT_AllowParallel. That is the API through which
    // AES-NI/ARM-AES and the MARS/SHACAL SIMD implementations process several
    // blocks per call. Calling ProcessBlock here for every 16/32-byte block
    // was correct but silently reduced the production fast path to roughly a
    // tenth of its intended throughput.
    //
    // CTR_Mode_ExternalCipher preserves the same full-width big-endian counter
    // semantics (including carries above the low byte), supports partial tails
    // and in-place buffers, and uses the already-keyed cipher owned by this
    // range. The whole-request preflight above xcrypt_ctr_range remains the
    // authority that refuses exhaustion before any output is written.
    CryptoPP::CTR_Mode_ExternalCipher::Encryption ctr(cipher, counter);
    ctr.ProcessData(output, input, length);

    return 0;
}

template <typename Encryption>
inline int xcrypt_ctr_range(
    const std::uint8_t* key,
    std::size_t key_length,
    const std::uint8_t* nonce,
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length,
    std::size_t first_block)
{
    Encryption cipher;
    cipher.SetKey(key, key_length);
    return xcrypt_ctr_keyed_range(cipher, nonce, input, output, length, first_block);
}

/*
 * Drives a whole buffer, on one thread or several.
 *
 * Work is claimed in chunks rather than split once up front. Apple silicon
 * pairs fast performance cores with slower efficiency ones, and an even split
 * lets the slow half decide when the operation finishes; a claimed-chunk queue
 * lets each core take what it can carry. Because every chunk is keyed to its
 * absolute block index, the output does not depend on how the chunks were
 * distributed.
 */
template <typename Encryption>
inline int xcrypt_ctr(
    const std::uint8_t* key,
    std::size_t key_length,
    const std::uint8_t* nonce,
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length,
    std::uint32_t worker_budget = 0)
{
    constexpr std::size_t block_bytes = Encryption::BLOCKSIZE;

    if (key == nullptr || nonce == nullptr || input == nullptr || output == nullptr) {
        return 1;
    }

    if (length == 0) {
        return 0;
    }
    const auto input_address = reinterpret_cast<std::uintptr_t>(input);
    const auto output_address = reinterpret_cast<std::uintptr_t>(output);
    if (input_address > UINTPTR_MAX - length || output_address > UINTPTR_MAX - length
        || (input != output && input_address < output_address + length
            && output_address < input_address + length)) {
        return 1;
    }

    if (length > SIZE_MAX - (block_bytes - 1)) {
        return 4;
    }

    const std::size_t total_blocks = (length + block_bytes - 1) / block_bytes;

    // Refuse the whole request before writing a byte if its final block would
    // carry out of the block-wide big-endian counter. The old driver discarded
    // that carry and continued at zero, which can reuse keystream under the
    // same key on a nonce near its maximum value.
    std::uint8_t final_counter[block_bytes];
    std::memcpy(final_counter, nonce, block_bytes);
    const bool counter_overflow = add_counter_blocks(
        final_counter,
        block_bytes,
        static_cast<std::uint64_t>(total_blocks - 1));
    secure_zero(final_counter, sizeof(final_counter));
    if (counter_overflow) {
        return 4;
    }

    std::size_t thread_count = 1;
    if (length >= kParallelThresholdBytes) {
        thread_count = worker_budget == 0 ? logical_processor_count() : worker_budget;
        if (thread_count > total_blocks) thread_count = total_blocks;
        if (thread_count == 0) {
            thread_count = 1;
        }
    }

    const std::size_t chunk_blocks = keepvault_v13_claim_blocks(total_blocks, kChunkBytes / block_bytes, thread_count);

    if (thread_count <= 1) {
        // The parallel path below catches inside its workers, so without this
        // an allocation failure on a small buffer would unwind out through the
        // extern "C" boundary and terminate the process, while the same failure
        // on a large one returned an error the caller could report.
        try {
            return xcrypt_ctr_range<Encryption>(
                key, key_length, nonce, input, output, length, 0);
        } catch (...) {
            return 3;
        }
    }

    std::atomic<std::size_t> next_chunk{0};
    std::atomic<int> failure{0};

    auto worker = [&](std::size_t worker_index) noexcept {
#if defined(_WIN32)
        // Spawned workers may be spread across processor groups. Index zero is
        // the caller itself; changing its affinity here would permanently pin
        // an application or thread-pool thread after this function returned.
        if (worker_index != 0) {
            bind_worker_to_processor_group(worker_index);
        }
#else
        (void)worker_index;
#endif
        try {
            // Exclusive operation-local schedule, wiped by the cipher's
            // SecBlock destructor on normal return and exception unwind.
            // CTR state is constructed anew with an absolute counter per
            // claim and is never retained by the persistent executor.
            Encryption cipher;
            cipher.SetKey(key, key_length);
            for (;;) {
                if (failure.load(std::memory_order_relaxed) != 0) return;
                const std::size_t chunk = next_chunk.fetch_add(1, std::memory_order_relaxed);
                const std::size_t first_block = chunk * chunk_blocks;
                if (first_block >= total_blocks) {
                    return;
                }

                const std::size_t offset = first_block * block_bytes;
                const std::size_t span = chunk_blocks * block_bytes;
                const std::size_t remaining = length - offset;
                const std::size_t count = remaining < span ? remaining : span;

                const int result = xcrypt_ctr_keyed_range(
                    cipher, nonce, input + offset, output + offset, count, first_block);
                if (result != 0) {
                    failure.store(result, std::memory_order_relaxed);
                    return;
                }
            }
        } catch (...) {
            // A worker that threw must not unwind out of a thread, and it must
            // not leave the caller believing the buffer was processed.
            failure.store(3, std::memory_order_relaxed);
        }
    };

    const int borrowed = execute_borrowed(thread_count, worker);
    if (borrowed != -1) return borrowed == 0 ? failure.load(std::memory_order_relaxed) : 3;

    std::vector<std::thread> threads;
    try {
        threads.reserve(thread_count - 1);
        for (std::size_t i = 1; i < thread_count; ++i) {
            threads.emplace_back(worker, i);
        }
    } catch (...) {
        // Fewer threads than hoped is not an error; this one runs the rest.
        // Nothing is stored here on purpose: the threads that did start are
        // already running, and clearing the flag would discard a failure one of
        // them had just recorded.
    }

    // The calling thread keeps the group it already has and takes index 0.
    worker(0);

    for (std::thread& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    return failure.load(std::memory_order_relaxed);
}

}  // namespace keepvault

#endif
