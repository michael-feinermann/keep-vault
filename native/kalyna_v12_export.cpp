/*
 * Keep Vault v12 Kalyna-512/512 CTR adapter.
 *
 * The block primitive is Crypto++ 8.9.0's independently licensed Kalyna
 * implementation. CTR blocks are independent, so workers claim disjoint
 * ranges while preserving byte-for-byte output ordering. This adapter exports
 * only the current format-specific symbols.
 */

#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <new>

#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <pthread/qos.h>
#endif

#include "kalyna.h"

#define KEEPVAULT_EXPORT __attribute__((visibility("default")))

namespace {

constexpr std::size_t BlockBytes = 64;
constexpr std::size_t MaximumThreads = 64;
constexpr std::size_t ParallelThresholdBytes = 1024 * 1024;
constexpr std::size_t MinimumBytesPerThread = 256 * 1024;
constexpr std::size_t ChunkBlocks = 4096;

void secure_zero(void* pointer, std::size_t length) noexcept
{
    auto* bytes = static_cast<volatile std::uint8_t*>(pointer);
    while (length-- != 0) {
        *bytes++ = 0;
    }
}

class scoped_wipe final {
public:
    scoped_wipe(void* pointer, std::size_t length) noexcept
        : pointer_(pointer), length_(length)
    {
    }

    scoped_wipe(const scoped_wipe&) = delete;
    scoped_wipe& operator=(const scoped_wipe&) = delete;

    ~scoped_wipe()
    {
        secure_zero(pointer_, length_);
    }

private:
    void* pointer_;
    std::size_t length_;
};

struct copied_material final {
    std::array<std::uint8_t, BlockBytes> key{};
    std::array<std::uint8_t, BlockBytes> nonce{};

    ~copied_material()
    {
        secure_zero(key.data(), key.size());
        secure_zero(nonce.data(), nonce.size());
    }
};

bool increment_counter(std::uint8_t counter[BlockBytes]) noexcept
{
    for (std::size_t index = BlockBytes; index-- != 0;) {
        counter[index]++;
        if (counter[index] != 0) {
            return false;
        }
    }

    return true;
}

bool add_counter_blocks(std::uint8_t counter[BlockBytes], std::uint64_t blocks) noexcept
{
    std::uint64_t carry = blocks;
    for (std::size_t index = BlockBytes; index-- != 0 && carry != 0;) {
        const std::uint64_t sum = static_cast<std::uint64_t>(counter[index]) + (carry & 0xffU);
        counter[index] = static_cast<std::uint8_t>(sum);
        carry = (carry >> 8U) + (sum >> 8U);
    }

    return carry != 0;
}

bool counter_range_overflows(
    const std::array<std::uint8_t, BlockBytes>& nonce,
    std::size_t total_blocks) noexcept
{
    if (total_blocks == 0) {
        return false;
    }

    if (total_blocks - 1 > std::numeric_limits<std::uint64_t>::max()) {
        return true;
    }

    std::array<std::uint8_t, BlockBytes> final_counter = nonce;
    scoped_wipe wipe(final_counter.data(), final_counter.size());
    return add_counter_blocks(final_counter.data(), static_cast<std::uint64_t>(total_blocks - 1));
}

bool ranges_overlap(
    const std::uint8_t* left,
    const std::uint8_t* right,
    std::size_t length) noexcept
{
    if (length == 0 || left == right) {
        return false;
    }

    const auto left_value = reinterpret_cast<std::uintptr_t>(left);
    const auto right_value = reinterpret_cast<std::uintptr_t>(right);
    return left_value < right_value
        ? right_value - left_value < length
        : left_value - right_value < length;
}

bool fixed_equal(
    const std::uint8_t* left,
    const std::uint8_t* right,
    std::size_t length) noexcept
{
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < length; ++index) {
        difference |= static_cast<std::uint8_t>(left[index] ^ right[index]);
    }
    return difference == 0;
}

std::once_flag self_test_once;
std::atomic<int> self_test_status{0};

bool ensure_self_test() noexcept
{
    std::call_once(self_test_once, [] {
        std::array<std::uint8_t, BlockBytes> key{};
        std::array<std::uint8_t, BlockBytes> plaintext{};
        std::array<std::uint8_t, BlockBytes> output{};
        scoped_wipe wipe_key(key.data(), key.size());
        scoped_wipe wipe_plaintext(plaintext.data(), plaintext.size());
        scoped_wipe wipe_output(output.data(), output.size());
        static constexpr std::array<std::uint8_t, BlockBytes> expected = {
            0x4a, 0x26, 0xe3, 0x1b, 0x81, 0x1c, 0x35, 0x6a,
            0xa6, 0x1d, 0xd6, 0xca, 0x05, 0x96, 0x23, 0x1a,
            0x67, 0xba, 0x83, 0x54, 0xaa, 0x47, 0xf3, 0xa1,
            0x3e, 0x1d, 0xee, 0xc3, 0x20, 0xeb, 0x56, 0xb8,
            0x95, 0xd0, 0xf4, 0x17, 0x17, 0x5b, 0xab, 0x66,
            0x2f, 0xd6, 0xf1, 0x34, 0xbb, 0x15, 0xc8, 0x6c,
            0xcb, 0x90, 0x6a, 0x26, 0x85, 0x6e, 0xfe, 0xb7,
            0xc5, 0xbc, 0x64, 0x72, 0x94, 0x0d, 0xd9, 0xd9,
        };

        for (std::size_t index = 0; index < BlockBytes; ++index) {
            key[index] = static_cast<std::uint8_t>(index);
            plaintext[index] = static_cast<std::uint8_t>(index + 0x40U);
        }

        try {
            CryptoPP::Kalyna512::Encryption cipher;
            cipher.SetKey(key.data(), key.size());
            cipher.ProcessBlock(plaintext.data(), output.data());
            self_test_status.store(
                fixed_equal(expected.data(), output.data(), output.size()) ? 1 : -1,
                std::memory_order_release);
        }
        catch (...) {
            self_test_status.store(-1, std::memory_order_release);
        }
    });

    return self_test_status.load(std::memory_order_acquire) == 1;
}

int process_range(
    CryptoPP::Kalyna512::Encryption& cipher,
    const std::array<std::uint8_t, BlockBytes>& nonce,
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length,
    std::size_t start_block,
    std::size_t block_count)
{
    if (block_count == 0) {
        return 0;
    }

    if (start_block > std::numeric_limits<std::uint64_t>::max()) {
        return 4;
    }

    std::array<std::uint8_t, BlockBytes> counter = nonce;
    std::array<std::uint8_t, BlockBytes> stream{};
    scoped_wipe wipe_counter(counter.data(), counter.size());
    scoped_wipe wipe_stream(stream.data(), stream.size());
    if (add_counter_blocks(counter.data(), static_cast<std::uint64_t>(start_block))) {
        return 4;
    }

    const std::size_t end_block = start_block + block_count;
    if (end_block < start_block) {
        return 4;
    }

    for (std::size_t block_index = start_block; block_index < end_block; ++block_index) {
        const std::size_t offset = block_index * BlockBytes;
        const std::size_t remaining = length - offset;
        const std::size_t block_length = remaining < BlockBytes ? remaining : BlockBytes;
        cipher.ProcessBlock(counter.data(), stream.data());
        for (std::size_t index = 0; index < block_length; ++index) {
            output[offset + index] = static_cast<std::uint8_t>(input[offset + index] ^ stream[index]);
        }

        if (block_index + 1 < end_block && increment_counter(counter.data())) {
            return 4;
        }
    }

    return 0;
}

struct shared_state final {
    const copied_material& material;
    const std::uint8_t* input;
    std::uint8_t* output;
    std::size_t length;
    std::size_t total_blocks;
    std::atomic<std::size_t> next_chunk{0};
    std::atomic<std::size_t> ready{0};
    std::atomic<std::size_t> finished{0};
    std::atomic<bool> start{false};
    std::atomic<bool> cancel{false};
};

struct worker_job final {
    shared_state* shared = nullptr;
    int result = 0;
};

class worker_completion final {
public:
    explicit worker_completion(shared_state& shared) noexcept
        : shared_(shared)
    {
    }

    worker_completion(const worker_completion&) = delete;
    worker_completion& operator=(const worker_completion&) = delete;

    ~worker_completion()
    {
        // Release publishes every preceding job/result write. The parent
        // waits for this counter before it can destroy stack-backed worker
        // state, even if pthread_join itself unexpectedly fails.
        shared_.finished.fetch_add(1, std::memory_order_release);
    }

private:
    shared_state& shared_;
};

void* worker_entry(void* parameter) noexcept
{
    auto& job = *static_cast<worker_job*>(parameter);
    shared_state& shared = *job.shared;
    worker_completion completion(shared);
#if defined(__APPLE__)
    (void)pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0);
#endif

    bool announced_ready = false;
    try {
        CryptoPP::Kalyna512::Encryption cipher;
        cipher.SetKey(shared.material.key.data(), shared.material.key.size());
        shared.ready.fetch_add(1, std::memory_order_release);
        announced_ready = true;

        while (!shared.start.load(std::memory_order_acquire)
            && !shared.cancel.load(std::memory_order_acquire)) {
            (void)sched_yield();
        }
        if (shared.cancel.load(std::memory_order_acquire)) {
            return nullptr;
        }

        for (;;) {
            if (shared.cancel.load(std::memory_order_acquire)) {
                break;
            }
            const std::size_t chunk = shared.next_chunk.fetch_add(1, std::memory_order_relaxed);
            if (chunk > std::numeric_limits<std::size_t>::max() / ChunkBlocks) {
                job.result = 4;
                shared.cancel.store(true, std::memory_order_release);
                break;
            }
            const std::size_t start_block = chunk * ChunkBlocks;
            if (start_block >= shared.total_blocks) {
                break;
            }
            const std::size_t remaining = shared.total_blocks - start_block;
            const std::size_t block_count = remaining < ChunkBlocks ? remaining : ChunkBlocks;
            job.result = process_range(
                cipher,
                shared.material.nonce,
                shared.input,
                shared.output,
                shared.length,
                start_block,
                block_count);
            if (job.result != 0) {
                shared.cancel.store(true, std::memory_order_release);
                break;
            }
        }
    }
    catch (...) {
        job.result = 2;
        shared.cancel.store(true, std::memory_order_release);
        if (!announced_ready) {
            shared.ready.fetch_add(1, std::memory_order_release);
        }
    }

    return nullptr;
}

std::size_t configured_thread_limit() noexcept
{
    const char* configured = std::getenv("KALYNA_V12_CTR_THREADS");
    if (configured != nullptr && configured[0] != '\0') {
        errno = 0;
        char* end = nullptr;
        const unsigned long parsed = std::strtoul(configured, &end, 10);
        if (errno == 0 && end != configured && *end == '\0' && parsed > 0) {
            return parsed > MaximumThreads ? MaximumThreads : static_cast<std::size_t>(parsed);
        }
    }

    long processors = sysconf(_SC_NPROCESSORS_ONLN);
    if (processors <= 0) {
        processors = 1;
    }
    return static_cast<unsigned long>(processors) > MaximumThreads
        ? MaximumThreads
        : static_cast<std::size_t>(processors);
}

std::size_t choose_thread_count(
    std::size_t length,
    std::size_t total_blocks,
    bool force_scalar) noexcept
{
    if (force_scalar || length < ParallelThresholdBytes || total_blocks < 2) {
        return 1;
    }

    std::size_t threads = configured_thread_limit();
    std::size_t useful_threads = length / MinimumBytesPerThread;
    if (useful_threads == 0) {
        useful_threads = 1;
    }
    if (threads > useful_threads) {
        threads = useful_threads;
    }
    if (threads > total_blocks) {
        threads = total_blocks;
    }
    return threads == 0 ? 1 : threads;
}

int xcrypt(
    const std::uint8_t* key,
    const std::uint8_t* nonce,
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length,
    bool force_scalar,
    bool force_join_failure) noexcept
{
    if (key == nullptr || nonce == nullptr
        || (length != 0 && (input == nullptr || output == nullptr))) {
        return 1;
    }
    if (ranges_overlap(input, output, length)) {
        return 1;
    }
    if (!ensure_self_test()) {
        return 5;
    }
    if (length == 0) {
        return 0;
    }
    if (length > std::numeric_limits<std::size_t>::max() - (BlockBytes - 1)) {
        return 4;
    }

    copied_material material;
    std::memcpy(material.key.data(), key, material.key.size());
    std::memcpy(material.nonce.data(), nonce, material.nonce.size());
    const std::size_t total_blocks = (length + BlockBytes - 1) / BlockBytes;
    if (total_blocks == 0) {
        return 0;
    }
    if (counter_range_overflows(material.nonce, total_blocks)) {
        return 4;
    }

    try {
        const std::size_t thread_count = force_join_failure
            ? (total_blocks < 2 ? 1 : 2)
            : choose_thread_count(length, total_blocks, force_scalar);
        if (thread_count == 1) {
            CryptoPP::Kalyna512::Encryption cipher;
            cipher.SetKey(material.key.data(), material.key.size());
            return process_range(cipher, material.nonce, input, output, length, 0, total_blocks);
        }

        std::array<pthread_t, MaximumThreads> handles{};
        std::array<bool, MaximumThreads> started{};
        std::array<worker_job, MaximumThreads> jobs{};
        scoped_wipe wipe_handles(handles.data(), sizeof(handles));
        scoped_wipe wipe_started(started.data(), sizeof(started));
        scoped_wipe wipe_jobs(jobs.data(), sizeof(jobs));
        shared_state shared{material, input, output, length, total_blocks};

        std::size_t created = 0;
        for (; created < thread_count; ++created) {
            jobs[created].shared = &shared;
            if (pthread_create(&handles[created], nullptr, worker_entry, &jobs[created]) != 0) {
                shared.cancel.store(true, std::memory_order_release);
                shared.start.store(true, std::memory_order_release);
                break;
            }
            started[created] = true;
        }

        if (created == thread_count) {
            while (shared.ready.load(std::memory_order_acquire) < thread_count
                && !shared.cancel.load(std::memory_order_acquire)) {
                (void)sched_yield();
            }
            shared.start.store(true, std::memory_order_release);
        }

        // Joining is normally the completion proof. Waiting on an independent
        // release/acquire counter first also makes the exceptional join-error
        // path memory-safe: no worker can still reference shared, jobs,
        // material or the caller's buffers when this function returns.
        while (shared.finished.load(std::memory_order_acquire) < created) {
            (void)sched_yield();
        }

        int result = created == thread_count ? 0 : 3;
        for (std::size_t index = 0; index < created; ++index) {
            int join_result = 0;
            if (started[index]) {
                if (force_join_failure && index == 0) {
                    join_result = EINVAL;
                    // The completion counter proves the thread has exited, so
                    // detaching is now sufficient to release its pthread
                    // bookkeeping without exposing stack state to a live
                    // worker. This branch is used only by the exported KAT.
                    (void)pthread_detach(handles[index]);
                }
                else {
                    join_result = pthread_join(handles[index], nullptr);
                    if (join_result != 0) {
                        (void)pthread_detach(handles[index]);
                    }
                }
            }
            if (join_result != 0 && result == 0) {
                result = 3;
            }
            if (jobs[index].result != 0 && result == 0) {
                result = jobs[index].result;
            }
        }
        return result;
    }
    catch (...) {
        return 2;
    }
}

} // namespace

extern "C" KEEPVAULT_EXPORT int keepvault_v12_kalyna_512_512_ctr_xcrypt(
    const std::uint8_t key[BlockBytes],
    const std::uint8_t nonce[BlockBytes],
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length) noexcept
{
    return xcrypt(key, nonce, input, output, length, false, false);
}

extern "C" KEEPVAULT_EXPORT int keepvault_v12_kalyna_512_512_ctr_xcrypt_scalar(
    const std::uint8_t key[BlockBytes],
    const std::uint8_t nonce[BlockBytes],
    const std::uint8_t* input,
    std::uint8_t* output,
    std::size_t length) noexcept
{
    return xcrypt(key, nonce, input, output, length, true, false);
}

extern "C" KEEPVAULT_EXPORT int keepvault_v12_kalyna_join_failure_kat(void) noexcept
{
    constexpr std::size_t TestBytes = 2 * MinimumBytesPerThread;
    std::array<std::uint8_t, BlockBytes> key{};
    std::array<std::uint8_t, BlockBytes> nonce{};
    std::unique_ptr<std::uint8_t[]> input(new (std::nothrow) std::uint8_t[TestBytes]);
    std::unique_ptr<std::uint8_t[]> parallel(new (std::nothrow) std::uint8_t[TestBytes]);
    std::unique_ptr<std::uint8_t[]> scalar(new (std::nothrow) std::uint8_t[TestBytes]);
    if (!input || !parallel || !scalar) {
        return 6;
    }

    scoped_wipe wipe_key(key.data(), key.size());
    scoped_wipe wipe_nonce(nonce.data(), nonce.size());
    scoped_wipe wipe_input(input.get(), TestBytes);
    scoped_wipe wipe_parallel(parallel.get(), TestBytes);
    scoped_wipe wipe_scalar(scalar.get(), TestBytes);
    for (std::size_t index = 0; index < BlockBytes; ++index) {
        key[index] = static_cast<std::uint8_t>(index * 3U + 1U);
        nonce[index] = static_cast<std::uint8_t>(index * 5U + 7U);
    }
    for (std::size_t index = 0; index < TestBytes; ++index) {
        input[index] = static_cast<std::uint8_t>(index * 11U + 13U);
    }

    const int injected = xcrypt(
        key.data(), nonce.data(), input.get(), parallel.get(), TestBytes, false, true);
    const int reference = xcrypt(
        key.data(), nonce.data(), input.get(), scalar.get(), TestBytes, true, false);
    if (injected != 3 || reference != 0) {
        return 7;
    }
    return fixed_equal(parallel.get(), scalar.get(), TestBytes) ? 0 : 8;
}
