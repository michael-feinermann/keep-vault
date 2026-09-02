/*
 * Native adapter for ChaCha20-Poly1305 (RFC 8439).
 *
 * The outermost layer of the v12 paranoia and mixed cascades, and the only one
 * that is not a block cipher in CTR mode. It authenticates as well as encrypts, so it does
 * not fit the shared CTR driver: it needs a nonce of its own width, produces a
 * tag, and on decryption either returns the plaintext or refuses.
 *
 * Poly1305 is additional to, not a replacement for, the container's existing
 * HMAC-SHA3-512 and Skein-MAC-1024. It authenticates the outermost ciphertext
 * as that layer sees it; the other two authenticate the container.
 *
 * The ChaCha20 keystream and the Poly1305 polynomial are both split across
 * independent block-aligned workers. Poly1305 segment results are combined in
 * message order in GF(2^130-5), then s is added exactly once. The old scalar
 * Crypto++ path remains exported only as an independent differential oracle.
 */
#include "chacha.h"
#include "misc.h"
#include "poly1305.h"

#include "cryptopp_ctr_common.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <memory>
#include <new>
#include <thread>
#include <vector>

#if defined(__APPLE__)
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define CHACHAPOLY_KEY_BYTES 32
#define CHACHAPOLY_NONCE_BYTES 12
#define CHACHAPOLY_TAG_BYTES 16

#if defined(__APPLE__)
/*
 * Descriptor-only snapshot support for macOS.
 *
 * A named APFS clone still has a same-UID mutation window between creation and
 * unlink. POSIX shared memory gives us a kernel object in a non-enumerable
 * namespace instead: its 96-bit random name exists only long enough to open a
 * distinct read-only descriptor, then shm_unlink removes the name before the
 * object is sized or receives a byte of source data.
 *
 * The production ABI deliberately uses fixed-width integers:
 *
 *   int32 status keepvault_macos_snapshot_create_v1(
 *       int32 source_fd, uint64 maximum_bytes,
 *       int32 *snapshot_read_fd, uint64 *mapping_address,
 *       uint64 *logical_size, int32 *os_error)
 *
 * On success snapshot_read_fd owns an O_RDONLY, FD_CLOEXEC descriptor whose
 * link count is zero plus a complete PROT_READ mapping. Darwin POSIX-SHM
 * descriptors reject read(2)/pread(2), so managed consumers read the mapping;
 * the descriptor exists only to retain and independently attest the object.
 * On every failure the FD remains -1 and the address/length remain zero.
 * os_error is populated only for a failed system call. The test export adds a
 * synchronous callback after the copy and one deterministic ENOSPC injection
 * bit; production never calls that export.
 */
namespace {

constexpr std::int32_t kSnapshotSuccess = 0;
constexpr std::int32_t kSnapshotInvalidArgument = 1;
constexpr std::int32_t kSnapshotInvalidSource = 2;
constexpr std::int32_t kSnapshotSourceChanged = 3;
constexpr std::int32_t kSnapshotSystemError = 4;
constexpr std::int32_t kSnapshotTooLarge = 5;
constexpr std::int32_t kSnapshotInternalError = 6;
constexpr std::uint32_t kSnapshotTestInjectEnospc = 1u;
constexpr std::uint32_t kSnapshotTestForceSingleWorker = 1u << 1;
constexpr std::uint32_t kSnapshotTestRequireParallelWorkers = 1u << 2;
constexpr std::size_t kSnapshotRandomBytes = 12;  // 96 bits.
constexpr std::size_t kSnapshotCopyBufferBytes = 256u * 1024u;
constexpr std::size_t kSnapshotMaximumWorkers = 64;
constexpr std::size_t kSnapshotMaximumMappedBytes =
    kSnapshotMaximumWorkers * kSnapshotCopyBufferBytes;

using snapshot_test_hook = void (*)(void* context);

class snapshot_fd final {
public:
    snapshot_fd() noexcept = default;
    explicit snapshot_fd(int descriptor) noexcept : descriptor_(descriptor) {}
    snapshot_fd(const snapshot_fd&) = delete;
    snapshot_fd& operator=(const snapshot_fd&) = delete;

    ~snapshot_fd()
    {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
    }

    int get() const noexcept { return descriptor_; }

    int release() noexcept
    {
        const int result = descriptor_;
        descriptor_ = -1;
        return result;
    }

    void reset(int descriptor = -1) noexcept
    {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
        descriptor_ = descriptor;
    }

private:
    int descriptor_ = -1;
};

class snapshot_writer final {
public:
    explicit snapshot_writer(int descriptor) noexcept : descriptor_(descriptor) {}
    snapshot_writer(const snapshot_writer&) = delete;
    snapshot_writer& operator=(const snapshot_writer&) = delete;

    ~snapshot_writer()
    {
        if (descriptor_ >= 0) {
            if (!preserve_contents_) {
                (void)::ftruncate(descriptor_, 0);
            }
            (void)::close(descriptor_);
        }
    }

    int get() const noexcept { return descriptor_; }
    int close_preserving() noexcept
    {
        preserve_contents_ = true;
        const int descriptor = descriptor_;
        descriptor_ = -1;
        return ::close(descriptor);
    }

private:
    int descriptor_;
    bool preserve_contents_ = false;
};

struct snapshot_sensitive_buffers final {
    std::array<std::uint8_t, kSnapshotRandomBytes> random{};
    std::array<char, 31> name{};

    ~snapshot_sensitive_buffers()
    {
        keepvault::secure_zero(random.data(), random.size());
        keepvault::secure_zero(name.data(), name.size());
    }
};

static bool snapshot_source_stable(const struct stat& before, const struct stat& after) noexcept
{
    return before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_nlink == after.st_nlink
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_size == after.st_size
        && before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec
        && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec
        && before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec
        && before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
}

static void snapshot_encode_name(snapshot_sensitive_buffers& buffers) noexcept
{
    constexpr char hex[] = "0123456789abcdef";
    constexpr char prefix[] = "/kv12-";
    static_assert(sizeof(prefix) - 1 + (kSnapshotRandomBytes * 2) + 1
        == std::tuple_size<decltype(buffers.name)>::value);

    std::memcpy(buffers.name.data(), prefix, sizeof(prefix) - 1);
    std::size_t output = sizeof(prefix) - 1;
    for (std::uint8_t value : buffers.random) {
        buffers.name[output++] = hex[value >> 4];
        buffers.name[output++] = hex[value & 0x0Fu];
    }
    buffers.name[output] = '\0';
}

static std::int32_t snapshot_system_failure(int error, std::int32_t* os_error) noexcept
{
    *os_error = error == 0 ? EIO : error;
    return kSnapshotSystemError;
}

static bool snapshot_ranges_overlap(
    const void* left,
    std::size_t left_size,
    const void* right,
    std::size_t right_size) noexcept
{
    const std::uintptr_t left_address = reinterpret_cast<std::uintptr_t>(left);
    const std::uintptr_t right_address = reinterpret_cast<std::uintptr_t>(right);
    return left_address <= right_address
        ? right_address - left_address < left_size
        : left_address - right_address < right_size;
}

static std::int32_t create_anonymous_snapshot_impl(
    std::int32_t source_fd,
    std::uint64_t maximum_bytes,
    std::uint32_t test_flags,
    snapshot_test_hook after_copy_hook,
    void* hook_context,
    std::int32_t* snapshot_read_fd,
    std::uint64_t* mapping_address,
    std::uint64_t* logical_size,
    std::int32_t* os_error) noexcept
{
    if (snapshot_read_fd == nullptr || mapping_address == nullptr
        || logical_size == nullptr || os_error == nullptr
        || snapshot_ranges_overlap(
            snapshot_read_fd, sizeof(*snapshot_read_fd),
            mapping_address, sizeof(*mapping_address))
        || snapshot_ranges_overlap(
            snapshot_read_fd, sizeof(*snapshot_read_fd),
            logical_size, sizeof(*logical_size))
        || snapshot_ranges_overlap(
            snapshot_read_fd, sizeof(*snapshot_read_fd),
            os_error, sizeof(*os_error))
        || snapshot_ranges_overlap(
            mapping_address, sizeof(*mapping_address),
            logical_size, sizeof(*logical_size))
        || snapshot_ranges_overlap(
            mapping_address, sizeof(*mapping_address),
            os_error, sizeof(*os_error))
        || snapshot_ranges_overlap(
            logical_size, sizeof(*logical_size),
            os_error, sizeof(*os_error))) {
        return kSnapshotInvalidArgument;
    }

    *snapshot_read_fd = -1;
    *mapping_address = 0;
    *logical_size = 0;
    *os_error = 0;

    // Once all result ranges are known writable and disjoint, every remaining
    // failure obeys the ABI's clean-output invariant. In particular, invalid
    // test flags must not leave caller-owned garbage looking like a descriptor
    // or mapping that ought to be released.
    if (source_fd < 0
        || (test_flags & ~(kSnapshotTestInjectEnospc
            | kSnapshotTestForceSingleWorker
            | kSnapshotTestRequireParallelWorkers)) != 0
        || ((test_flags & kSnapshotTestForceSingleWorker) != 0
            && (test_flags & kSnapshotTestRequireParallelWorkers) != 0)
        || ((after_copy_hook == nullptr) != (hook_context == nullptr))) {
        return kSnapshotInvalidArgument;
    }

    const int source_flags = ::fcntl(source_fd, F_GETFL);
    if (source_flags < 0) {
        return snapshot_system_failure(errno, os_error);
    }
    if ((source_flags & O_ACCMODE) != O_RDONLY) {
        return kSnapshotInvalidSource;
    }

    struct stat source_before{};
    if (::fstat(source_fd, &source_before) != 0) {
        return snapshot_system_failure(errno, os_error);
    }
    if (!S_ISREG(source_before.st_mode) || source_before.st_size < 0) {
        return kSnapshotInvalidSource;
    }

    const std::uint64_t source_size = static_cast<std::uint64_t>(source_before.st_size);
    if (source_size > maximum_bytes) {
        return kSnapshotTooLarge;
    }

    snapshot_sensitive_buffers buffers;
    snapshot_fd reader;
    bool name_is_linked = false;

    int writer_descriptor = -1;
    for (unsigned attempt = 0; attempt < 64; ++attempt) {
        ::arc4random_buf(buffers.random.data(), buffers.random.size());
        snapshot_encode_name(buffers);
        writer_descriptor = ::shm_open(
            buffers.name.data(),
            O_CREAT | O_EXCL | O_RDWR,
            S_IRUSR | S_IWUSR);
        if (writer_descriptor >= 0) {
            name_is_linked = true;
            break;
        }
        if (errno != EEXIST) {
            return snapshot_system_failure(errno, os_error);
        }
    }
    if (writer_descriptor < 0) {
        return snapshot_system_failure(EEXIST, os_error);
    }
    snapshot_writer writer(writer_descriptor);

    auto unlink_name = [&]() noexcept -> bool {
        if (!name_is_linked) {
            return true;
        }
        if (::shm_unlink(buffers.name.data()) != 0) {
            return false;
        }
        name_is_linked = false;
        return true;
    };

    if (::fcntl(writer.get(), F_SETFD, FD_CLOEXEC) != 0) {
        const int error = errno;
        (void)unlink_name();
        return snapshot_system_failure(error, os_error);
    }

    struct stat writer_named{};
    if (::fstat(writer.get(), &writer_named) != 0) {
        const int error = errno;
        (void)unlink_name();
        return snapshot_system_failure(error, os_error);
    }
    if ((writer_named.st_mode & ACCESSPERMS) != (S_IRUSR | S_IWUSR)
        || writer_named.st_uid != ::geteuid()
        || writer_named.st_nlink != 0) {
        (void)unlink_name();
        return kSnapshotInternalError;
    }

    const int reader_descriptor = ::shm_open(buffers.name.data(), O_RDONLY, 0);
    if (reader_descriptor < 0) {
        const int error = errno;
        (void)unlink_name();
        return snapshot_system_failure(error, os_error);
    }
    reader.reset(reader_descriptor);
    if (::fcntl(reader.get(), F_SETFD, FD_CLOEXEC) != 0) {
        const int error = errno;
        (void)unlink_name();
        return snapshot_system_failure(error, os_error);
    }

    struct stat reader_named{};
    if (::fstat(reader.get(), &reader_named) != 0) {
        const int error = errno;
        (void)unlink_name();
        return snapshot_system_failure(error, os_error);
    }
    const int reader_flags = ::fcntl(reader.get(), F_GETFL);
    const int reader_descriptor_flags = ::fcntl(reader.get(), F_GETFD);
    if ((reader_named.st_mode & ACCESSPERMS) != (S_IRUSR | S_IWUSR)
        || reader_named.st_uid != ::geteuid() || reader_named.st_nlink != 0
        || reader_flags < 0 || (reader_flags & O_ACCMODE) != O_RDONLY
        || reader_descriptor_flags < 0 || (reader_descriptor_flags & FD_CLOEXEC) == 0) {
        (void)unlink_name();
        return kSnapshotInternalError;
    }

    // This is the last namespace operation. No source byte is copied while a
    // name exists, so even a same-UID process has nothing useful to discover.
    if (!unlink_name()) {
        return snapshot_system_failure(errno, os_error);
    }

    // Darwin reports st_nlink == 0 for POSIX-SHM descriptors even before
    // shm_unlink, so prove namespace removal by attempting a fresh open.
    const int reopened = ::shm_open(buffers.name.data(), O_RDONLY, 0);
    if (reopened >= 0) {
        (void)::close(reopened);
        return kSnapshotInternalError;
    }
    if (errno != ENOENT) {
        return snapshot_system_failure(errno, os_error);
    }

    struct stat writer_anonymous{};
    struct stat reader_anonymous{};
    if (::fstat(writer.get(), &writer_anonymous) != 0
        || ::fstat(reader.get(), &reader_anonymous) != 0) {
        return snapshot_system_failure(errno, os_error);
    }
    if (writer_anonymous.st_nlink != 0 || reader_anonymous.st_nlink != 0) {
        return kSnapshotInternalError;
    }

    if (::ftruncate(writer.get(), source_before.st_size) != 0) {
        return snapshot_system_failure(errno, os_error);
    }

    // Darwin rounds a POSIX-SHM object's physical st_size up to the VM page
    // size. The fixed ABI therefore returns the verified logical byte length;
    // the managed mapped stream enforces that EOF.
    const long page_size = ::sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        return snapshot_system_failure(errno, os_error);
    }
    const std::uint64_t page = static_cast<std::uint64_t>(page_size);
    const std::uint64_t expected_physical_size = source_size == 0
        ? 0
        : ((source_size + page - 1) / page) * page;

    static_assert(
        kSnapshotMaximumMappedBytes == 16u * 1024u * 1024u,
        "The parallel snapshot writable-window budget changed unexpectedly.");
    const std::uint64_t chunk_count = source_size == 0
        ? 0
        : (source_size + kSnapshotCopyBufferBytes - 1) / kSnapshotCopyBufferBytes;
    std::size_t worker_count = 1;
    if (chunk_count != 0
        && (test_flags & kSnapshotTestForceSingleWorker) == 0) {
        const long online_processors = ::sysconf(_SC_NPROCESSORS_ONLN);
        const std::size_t available_processors = online_processors > 0
            ? static_cast<std::size_t>(online_processors)
            : 1;
        worker_count = std::min<std::size_t>(
            kSnapshotMaximumWorkers,
            std::min<std::size_t>(
                available_processors,
                static_cast<std::size_t>(chunk_count)));
        if (worker_count == 0) {
            worker_count = 1;
        }
    }
    if ((test_flags & kSnapshotTestRequireParallelWorkers) != 0
        && worker_count < 2) {
        return kSnapshotInternalError;
    }

    std::atomic<std::uint64_t> next_chunk{0};
    std::atomic<std::int32_t> copy_failure{kSnapshotSuccess};
    std::atomic<int> copy_error{0};
    auto fail_copy = [&](std::int32_t status, int error) noexcept {
        std::int32_t expected = kSnapshotSuccess;
        if (copy_failure.compare_exchange_strong(
                expected,
                status,
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            copy_error.store(error, std::memory_order_relaxed);
        }
    };

    // Each worker maps a disjoint 256 KiB window of the anonymous object and
    // pread() writes the held source descriptor directly into that window. No
    // second plaintext/ciphertext heap copy exists, and at most 64 windows
    // (16 MiB total) can be writable at once. A failure makes the writer RAII
    // object truncate the anonymous object after all workers have joined.
    auto copy_worker = [&]() noexcept {
        while (copy_failure.load(std::memory_order_relaxed) == kSnapshotSuccess) {
            const std::uint64_t chunk = next_chunk.fetch_add(1, std::memory_order_relaxed);
            if (chunk >= chunk_count) {
                return;
            }
            const std::uint64_t offset = chunk * kSnapshotCopyBufferBytes;
            const std::size_t requested = static_cast<std::size_t>(
                std::min<std::uint64_t>(
                    kSnapshotCopyBufferBytes,
                    source_size - offset));
            if ((test_flags & kSnapshotTestInjectEnospc) != 0 && offset != 0) {
                fail_copy(kSnapshotSystemError, ENOSPC);
                return;
            }

            void* writable_mapping = ::mmap(
                nullptr,
                requested,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                writer.get(),
                static_cast<off_t>(offset));
            if (writable_mapping == MAP_FAILED) {
                fail_copy(kSnapshotSystemError, errno);
                return;
            }

            std::size_t filled = 0;
            while (filled < requested) {
                ssize_t bytes_read;
                do {
                    bytes_read = ::pread(
                        source_fd,
                        static_cast<std::uint8_t*>(writable_mapping) + filled,
                        requested - filled,
                        static_cast<off_t>(offset + filled));
                } while (bytes_read < 0 && errno == EINTR);
                if (bytes_read < 0) {
                    const int error = errno;
                    keepvault::secure_zero(writable_mapping, requested);
                    (void)::munmap(writable_mapping, requested);
                    fail_copy(kSnapshotSystemError, error);
                    return;
                }
                if (bytes_read == 0) {
                    keepvault::secure_zero(writable_mapping, requested);
                    (void)::munmap(writable_mapping, requested);
                    fail_copy(kSnapshotSourceChanged, 0);
                    return;
                }
                filled += static_cast<std::size_t>(bytes_read);
            }

            if (::munmap(writable_mapping, requested) != 0) {
                const int error = errno;
                keepvault::secure_zero(writable_mapping, requested);
                (void)::munmap(writable_mapping, requested);
                fail_copy(kSnapshotSystemError, error);
                return;
            }
        }
    };

    std::vector<std::thread> copy_threads;
    try {
        copy_threads.reserve(worker_count > 0 ? worker_count - 1 : 0);
        for (std::size_t worker = 1; worker < worker_count; ++worker) {
            copy_threads.emplace_back(copy_worker);
        }
    } catch (...) {
        fail_copy(kSnapshotSystemError, EAGAIN);
    }

    if (copy_failure.load(std::memory_order_relaxed) == kSnapshotSuccess) {
        copy_worker();
    }
    for (std::thread& thread : copy_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    const std::int32_t copy_status = copy_failure.load(std::memory_order_relaxed);
    if (copy_status == kSnapshotSystemError) {
        return snapshot_system_failure(
            copy_error.load(std::memory_order_relaxed),
            os_error);
    }
    if (copy_status != kSnapshotSuccess) {
        return copy_status;
    }

    const std::uint64_t offset = source_size;

    if (after_copy_hook != nullptr) {
        after_copy_hook(hook_context);
    }

    struct stat source_after{};
    if (::fstat(source_fd, &source_after) != 0) {
        return snapshot_system_failure(errno, os_error);
    }
    if (offset != source_size || !snapshot_source_stable(source_before, source_after)) {
        return kSnapshotSourceChanged;
    }

    struct stat snapshot_after{};
    if (::fstat(reader.get(), &snapshot_after) != 0) {
        return snapshot_system_failure(errno, os_error);
    }
    if (snapshot_after.st_nlink != 0
        || snapshot_after.st_size < 0
        || static_cast<std::uint64_t>(snapshot_after.st_size) != expected_physical_size
        || (snapshot_after.st_mode & ACCESSPERMS) != (S_IRUSR | S_IWUSR)) {
        return kSnapshotInternalError;
    }

    if (writer.close_preserving() != 0) {
        return snapshot_system_failure(errno, os_error);
    }

    struct stat read_only_after_writer_close{};
    if (::fstat(reader.get(), &read_only_after_writer_close) != 0
        || read_only_after_writer_close.st_nlink != 0
        || read_only_after_writer_close.st_size < 0
        || static_cast<std::uint64_t>(read_only_after_writer_close.st_size)
            != expected_physical_size) {
        return kSnapshotInternalError;
    }

    void* read_only_mapping = nullptr;
    if (source_size != 0) {
        if (source_size > SIZE_MAX) {
            return kSnapshotTooLarge;
        }
        read_only_mapping = ::mmap(
            nullptr,
            static_cast<std::size_t>(source_size),
            PROT_READ,
            MAP_SHARED,
            reader.get(),
            0);
        if (read_only_mapping == MAP_FAILED) {
            return snapshot_system_failure(errno, os_error);
        }
    }

    *snapshot_read_fd = reader.release();
    *mapping_address = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(read_only_mapping));
    *logical_size = source_size;
    return kSnapshotSuccess;
}

}  // namespace

extern "C" KEEPVAULT_EXPORT std::int32_t keepvault_macos_snapshot_create_v1(
    std::int32_t source_fd,
    std::uint64_t maximum_bytes,
    std::int32_t* snapshot_read_fd,
    std::uint64_t* mapping_address,
    std::uint64_t* logical_size,
    std::int32_t* os_error) noexcept
{
    return create_anonymous_snapshot_impl(
        source_fd,
        maximum_bytes,
        0,
        nullptr,
        nullptr,
        snapshot_read_fd,
        mapping_address,
        logical_size,
        os_error);
}

extern "C" KEEPVAULT_EXPORT std::int32_t keepvault_macos_snapshot_create_test_v1(
    std::int32_t source_fd,
    std::uint64_t maximum_bytes,
    std::uint32_t test_flags,
    snapshot_test_hook after_copy_hook,
    void* hook_context,
    std::int32_t* snapshot_read_fd,
    std::uint64_t* mapping_address,
    std::uint64_t* logical_size,
    std::int32_t* os_error) noexcept
{
    return create_anonymous_snapshot_impl(
        source_fd,
        maximum_bytes,
        test_flags,
        after_copy_hook,
        hook_context,
        snapshot_read_fd,
        mapping_address,
        logical_size,
        os_error);
}

extern "C" KEEPVAULT_EXPORT std::int32_t keepvault_macos_snapshot_release_v1(
    std::uint64_t mapping_address,
    std::uint64_t logical_size,
    std::int32_t* os_error) noexcept
{
    if (os_error == nullptr
        || ((mapping_address == 0) != (logical_size == 0))
        || logical_size > SIZE_MAX) {
        return kSnapshotInvalidArgument;
    }
    *os_error = 0;
    if (logical_size == 0) {
        return kSnapshotSuccess;
    }
    void* mapping = reinterpret_cast<void*>(
        static_cast<std::uintptr_t>(mapping_address));
    if (::munmap(mapping, static_cast<std::size_t>(logical_size)) != 0) {
        return snapshot_system_failure(errno, os_error);
    }
    return kSnapshotSuccess;
}
#endif

/* Raw ChaCha20 plus an explicitly retained scalar Poly1305 stream API. */
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

static int chacha20_validate_counter_range(
    std::uint32_t block_counter,
    std::size_t length) noexcept
{
    constexpr std::size_t kChaChaBlockBytes = 64;
    if (length > SIZE_MAX - (kChaChaBlockBytes - 1)) {
        return 4;
    }

    const std::size_t total_blocks =
        (length + kChaChaBlockBytes - 1) / kChaChaBlockBytes;
    const std::uint64_t available_blocks =
        static_cast<std::uint64_t>(UINT32_MAX) - block_counter + 1u;
    return static_cast<std::uint64_t>(total_blocks) > available_blocks ? 4 : 0;
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

    const int range_status = chacha20_validate_counter_range(block_counter, length);
    if (range_status != 0) {
        return range_status;
    }
    const std::size_t total_blocks = (length + kChaChaBlockBytes - 1) / kChaChaBlockBytes;

    const std::size_t chunk_blocks = keepvault::kChunkBytes / kChaChaBlockBytes;
    std::size_t thread_count = 1;
    if (length >= keepvault::kParallelThresholdBytes) {
        // The same count the block ciphers use: every logical processor on the
        // machine, asked of the operating system rather than of the C++
        // runtime. hardware_concurrency reports one processor group on a
        // machine Windows has split into several, which is half a dual-socket
        // server.
        thread_count = keepvault::logical_processor_count();
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

    auto worker = [&](std::size_t worker_index) noexcept {
#if defined(_WIN32)
        // Spawned workers may be spread across processor groups. Index zero is
        // the caller itself; changing its affinity here would permanently pin
        // an application or thread-pool thread after this function returned.
        if (worker_index != 0) {
            keepvault::bind_worker_to_processor_group(worker_index);
        }
#else
        (void)worker_index;
#endif
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
    try {
        threads.reserve(thread_count - 1);
        for (std::size_t i = 1; i < thread_count; ++i) {
            threads.emplace_back(worker, i);
        }
    } catch (...) {
        /* Fewer threads than hoped is not an error; this one runs the rest. */
    }

    /* The calling thread keeps the group it already has and takes index 0. */
    worker(0);

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
    if (length == 0) {
        return (key == nullptr || nonce == nullptr) ? 1 : 0;
    }

    /* The same refusal as the exported path: a comparison against a keystream
       the counter could not legitimately produce proves nothing. */
    const int range_status = chacha20_validate_counter_range(block_counter, length);
    if (range_status != 0) {
        return range_status;
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
 * Parallel Poly1305 for the RFC 8439 AEAD framing.
 *
 * The field is represented as five base-2^26 limbs. Every worker evaluates one
 * contiguous sequence of complete 16-byte Poly1305 blocks with h=0 and without
 * adding s. If R contains n_r blocks, then concatenation is exactly
 *
 *     H(L || R) = H(L) * r^n_r + H(R) mod (2^130 - 5).
 *
 * Segment boundaries are therefore block boundaries by construction. RFC 8439
 * pads AAD and ciphertext to complete blocks and appends one complete length
 * block, so the production path never has to give an interior segment the
 * semantics of a partial final block. The 128-bit s half is added once, after
 * the ordered join.
 */
namespace {

constexpr std::size_t kPoly1305BlockBytes = 16;
constexpr std::size_t kPoly1305MaxThreads = 64;
constexpr std::size_t kPoly1305ParallelThresholdBytes = 1024u * 1024u;
constexpr std::uint64_t kPoly1305LimbMask = (std::uint64_t{1} << 26) - 1;

// The 5x5 limb product yields 25 partial products in total, five per
// accumulator. Every limb entering a multiplication is below 2^26, so a single
// product stays below 2^52 and the four that carry the reduction factor 5 stay
// below 5*2^52 each. The widest accumulator, d0, therefore stays below
// 21*2^52 < 2^57, and the worst case with all five limbs at 2^26-1 was measured
// at exactly 57 bits. uint64_t leaves seven bits of headroom, which is the same
// bound poly1305-donna-32 relies on. Keeping the adapter free of the
// compiler-specific __int128 also makes the Windows native build take the same
// arithmetic path as the macOS one, bit for bit.
using poly1305_wide = std::uint64_t;

struct poly1305_field {
    std::uint64_t limb[5];
};

struct poly1305_segment {
    poly1305_field hash;
    std::size_t first_block;
    std::size_t block_count;
};

struct poly1305_plan {
    std::size_t aad_blocks;
    std::size_t ciphertext_blocks;
    std::size_t total_blocks;
    std::size_t thread_count;
};

static std::uint32_t poly1305_load32_le(const std::uint8_t* input) noexcept
{
    return static_cast<std::uint32_t>(input[0])
        | (static_cast<std::uint32_t>(input[1]) << 8)
        | (static_cast<std::uint32_t>(input[2]) << 16)
        | (static_cast<std::uint32_t>(input[3]) << 24);
}

static void poly1305_store32_le(std::uint8_t* output, std::uint32_t value) noexcept
{
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8);
    output[2] = static_cast<std::uint8_t>(value >> 16);
    output[3] = static_cast<std::uint8_t>(value >> 24);
}

static void poly1305_store64_le(std::uint8_t* output, std::uint64_t value) noexcept
{
    for (unsigned index = 0; index < 8; ++index) {
        output[index] = static_cast<std::uint8_t>(value >> (index * 8));
    }
}

static void poly1305_reduce(poly1305_field& value) noexcept
{
    /* Three fixed passes cover an addition and the carry folded from limb 4. */
    for (unsigned pass = 0; pass < 3; ++pass) {
        std::uint64_t carry = value.limb[0] >> 26;
        value.limb[0] &= kPoly1305LimbMask;
        value.limb[1] += carry;
        carry = value.limb[1] >> 26;
        value.limb[1] &= kPoly1305LimbMask;
        value.limb[2] += carry;
        carry = value.limb[2] >> 26;
        value.limb[2] &= kPoly1305LimbMask;
        value.limb[3] += carry;
        carry = value.limb[3] >> 26;
        value.limb[3] &= kPoly1305LimbMask;
        value.limb[4] += carry;
        carry = value.limb[4] >> 26;
        value.limb[4] &= kPoly1305LimbMask;
        value.limb[0] += carry * 5;
    }
}

static poly1305_field poly1305_multiply(
    const poly1305_field& left,
    const poly1305_field& right) noexcept
{
    const poly1305_wide d0 =
        poly1305_wide(left.limb[0]) * right.limb[0]
        + poly1305_wide(left.limb[1]) * right.limb[4] * 5
        + poly1305_wide(left.limb[2]) * right.limb[3] * 5
        + poly1305_wide(left.limb[3]) * right.limb[2] * 5
        + poly1305_wide(left.limb[4]) * right.limb[1] * 5;
    poly1305_wide d1 =
        poly1305_wide(left.limb[0]) * right.limb[1]
        + poly1305_wide(left.limb[1]) * right.limb[0]
        + poly1305_wide(left.limb[2]) * right.limb[4] * 5
        + poly1305_wide(left.limb[3]) * right.limb[3] * 5
        + poly1305_wide(left.limb[4]) * right.limb[2] * 5;
    poly1305_wide d2 =
        poly1305_wide(left.limb[0]) * right.limb[2]
        + poly1305_wide(left.limb[1]) * right.limb[1]
        + poly1305_wide(left.limb[2]) * right.limb[0]
        + poly1305_wide(left.limb[3]) * right.limb[4] * 5
        + poly1305_wide(left.limb[4]) * right.limb[3] * 5;
    poly1305_wide d3 =
        poly1305_wide(left.limb[0]) * right.limb[3]
        + poly1305_wide(left.limb[1]) * right.limb[2]
        + poly1305_wide(left.limb[2]) * right.limb[1]
        + poly1305_wide(left.limb[3]) * right.limb[0]
        + poly1305_wide(left.limb[4]) * right.limb[4] * 5;
    poly1305_wide d4 =
        poly1305_wide(left.limb[0]) * right.limb[4]
        + poly1305_wide(left.limb[1]) * right.limb[3]
        + poly1305_wide(left.limb[2]) * right.limb[2]
        + poly1305_wide(left.limb[3]) * right.limb[1]
        + poly1305_wide(left.limb[4]) * right.limb[0];

    poly1305_field result{};
    result.limb[0] = static_cast<std::uint64_t>(d0) & kPoly1305LimbMask;
    d1 += d0 >> 26;
    result.limb[1] = static_cast<std::uint64_t>(d1) & kPoly1305LimbMask;
    d2 += d1 >> 26;
    result.limb[2] = static_cast<std::uint64_t>(d2) & kPoly1305LimbMask;
    d3 += d2 >> 26;
    result.limb[3] = static_cast<std::uint64_t>(d3) & kPoly1305LimbMask;
    d4 += d3 >> 26;
    result.limb[4] = static_cast<std::uint64_t>(d4) & kPoly1305LimbMask;
    result.limb[0] += static_cast<std::uint64_t>(d4 >> 26) * 5;
    poly1305_reduce(result);
    return result;
}

static void poly1305_add(poly1305_field& left, const poly1305_field& right) noexcept
{
    for (unsigned index = 0; index < 5; ++index) {
        left.limb[index] += right.limb[index];
    }
    poly1305_reduce(left);
}

static poly1305_field poly1305_power(poly1305_field base, std::size_t exponent) noexcept
{
    poly1305_field result{{1, 0, 0, 0, 0}};
    while (exponent != 0) {
        if ((exponent & 1u) != 0) {
            result = poly1305_multiply(result, base);
        }
        exponent >>= 1;
        if (exponent != 0) {
            base = poly1305_multiply(base, base);
        }
    }
    keepvault::secure_zero(&base, sizeof(base));
    return result;
}

static poly1305_field poly1305_clamped_r(const std::uint8_t key[32]) noexcept
{
    return poly1305_field{{
        poly1305_load32_le(key + 0) & 0x3ffffffu,
        (poly1305_load32_le(key + 3) >> 2) & 0x3ffff03u,
        (poly1305_load32_le(key + 6) >> 4) & 0x3ffc0ffu,
        (poly1305_load32_le(key + 9) >> 6) & 0x3f03fffu,
        (poly1305_load32_le(key + 12) >> 8) & 0x00fffffu,
    }};
}

static poly1305_field poly1305_full_block(const std::uint8_t block[16]) noexcept
{
    return poly1305_field{{
        poly1305_load32_le(block + 0) & 0x3ffffffu,
        (poly1305_load32_le(block + 3) >> 2) & 0x3ffffffu,
        (poly1305_load32_le(block + 6) >> 4) & 0x3ffffffu,
        (poly1305_load32_le(block + 9) >> 6) & 0x3ffffffu,
        (poly1305_load32_le(block + 12) >> 8) | (std::uint64_t{1} << 24),
    }};
}

static int poly1305_make_plan(
    std::size_t associated_length,
    std::size_t ciphertext_length,
    std::uint32_t requested_workers,
    poly1305_plan& plan) noexcept
{
    if (associated_length > SIZE_MAX - (kPoly1305BlockBytes - 1)
        || ciphertext_length > SIZE_MAX - (kPoly1305BlockBytes - 1)) {
        return 4;
    }
    if (requested_workers > kPoly1305MaxThreads) {
        return 1;
    }

    plan.aad_blocks = (associated_length + kPoly1305BlockBytes - 1)
        / kPoly1305BlockBytes;
    plan.ciphertext_blocks = (ciphertext_length + kPoly1305BlockBytes - 1)
        / kPoly1305BlockBytes;
    if (plan.aad_blocks > SIZE_MAX - plan.ciphertext_blocks - 1) {
        return 4;
    }
    plan.total_blocks = plan.aad_blocks + plan.ciphertext_blocks + 1;

    std::size_t workers = requested_workers;
    if (workers == 0) {
        workers = plan.total_blocks >= kPoly1305ParallelThresholdBytes / kPoly1305BlockBytes
            ? keepvault::logical_processor_count()
            : 1;
    }
    if (workers > kPoly1305MaxThreads) {
        workers = kPoly1305MaxThreads;
    }
    if (workers > plan.total_blocks) {
        workers = plan.total_blocks;
    }
    plan.thread_count = workers == 0 ? 1 : workers;
    return 0;
}

static void poly1305_load_framed_block(
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* ciphertext,
    std::size_t ciphertext_length,
    const poly1305_plan& plan,
    std::size_t block_index,
    std::uint8_t block[16]) noexcept
{
    std::memset(block, 0, kPoly1305BlockBytes);
    if (block_index < plan.aad_blocks) {
        const std::size_t offset = block_index * kPoly1305BlockBytes;
        const std::size_t remaining = associated_length - offset;
        const std::size_t take = remaining < kPoly1305BlockBytes
            ? remaining
            : kPoly1305BlockBytes;
        if (take != 0) {
            std::memcpy(block, associated_data + offset, take);
        }
        return;
    }

    block_index -= plan.aad_blocks;
    if (block_index < plan.ciphertext_blocks) {
        const std::size_t offset = block_index * kPoly1305BlockBytes;
        const std::size_t remaining = ciphertext_length - offset;
        const std::size_t take = remaining < kPoly1305BlockBytes
            ? remaining
            : kPoly1305BlockBytes;
        if (take != 0) {
            std::memcpy(block, ciphertext + offset, take);
        }
        return;
    }

    poly1305_store64_le(block, static_cast<std::uint64_t>(associated_length));
    poly1305_store64_le(block + 8, static_cast<std::uint64_t>(ciphertext_length));
}

static void poly1305_evaluate_segment(
    poly1305_segment& segment,
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* ciphertext,
    std::size_t ciphertext_length,
    const poly1305_plan& plan,
    const poly1305_field& r) noexcept
{
    poly1305_field accumulator{};
    std::uint8_t block[kPoly1305BlockBytes];
    for (std::size_t offset = 0; offset < segment.block_count; ++offset) {
        poly1305_load_framed_block(
            associated_data,
            associated_length,
            ciphertext,
            ciphertext_length,
            plan,
            segment.first_block + offset,
            block);
        poly1305_field message = poly1305_full_block(block);
        poly1305_add(accumulator, message);
        accumulator = poly1305_multiply(accumulator, r);
        keepvault::secure_zero(&message, sizeof(message));
    }
    segment.hash = accumulator;
    keepvault::secure_zero(block, sizeof(block));
    keepvault::secure_zero(&accumulator, sizeof(accumulator));
}

static void poly1305_finish(
    poly1305_field hash,
    const std::uint8_t s[16],
    std::uint8_t tag[16]) noexcept
{
    poly1305_reduce(hash);

    std::uint64_t g0 = hash.limb[0] + 5;
    std::uint64_t carry = g0 >> 26;
    g0 &= kPoly1305LimbMask;
    std::uint64_t g1 = hash.limb[1] + carry;
    carry = g1 >> 26;
    g1 &= kPoly1305LimbMask;
    std::uint64_t g2 = hash.limb[2] + carry;
    carry = g2 >> 26;
    g2 &= kPoly1305LimbMask;
    std::uint64_t g3 = hash.limb[3] + carry;
    carry = g3 >> 26;
    g3 &= kPoly1305LimbMask;
    std::uint64_t g4 = hash.limb[4] + carry - (std::uint64_t{1} << 26);

    std::uint64_t use_g = (g4 >> 63) - 1;
    std::uint64_t use_h = ~use_g;
    hash.limb[0] = (hash.limb[0] & use_h) | (g0 & use_g);
    hash.limb[1] = (hash.limb[1] & use_h) | (g1 & use_g);
    hash.limb[2] = (hash.limb[2] & use_h) | (g2 & use_g);
    hash.limb[3] = (hash.limb[3] & use_h) | (g3 & use_g);
    hash.limb[4] = (hash.limb[4] & use_h) | (g4 & use_g);

    std::uint64_t word =
        static_cast<std::uint64_t>(
            static_cast<std::uint32_t>(hash.limb[0] | (hash.limb[1] << 26)))
        + poly1305_load32_le(s);
    poly1305_store32_le(tag, static_cast<std::uint32_t>(word));
    word = static_cast<std::uint64_t>(
        static_cast<std::uint32_t>(hash.limb[1] >> 6 | (hash.limb[2] << 20)))
        + poly1305_load32_le(s + 4) + (word >> 32);
    poly1305_store32_le(tag + 4, static_cast<std::uint32_t>(word));
    word = static_cast<std::uint64_t>(
        static_cast<std::uint32_t>(hash.limb[2] >> 12 | (hash.limb[3] << 14)))
        + poly1305_load32_le(s + 8) + (word >> 32);
    poly1305_store32_le(tag + 8, static_cast<std::uint32_t>(word));
    word = static_cast<std::uint64_t>(
        static_cast<std::uint32_t>(hash.limb[3] >> 18 | (hash.limb[4] << 8)))
        + poly1305_load32_le(s + 12) + (word >> 32);
    poly1305_store32_le(tag + 12, static_cast<std::uint32_t>(word));

    keepvault::secure_zero(&hash, sizeof(hash));
    keepvault::secure_zero(&g0, sizeof(g0));
    keepvault::secure_zero(&g1, sizeof(g1));
    keepvault::secure_zero(&g2, sizeof(g2));
    keepvault::secure_zero(&g3, sizeof(g3));
    keepvault::secure_zero(&g4, sizeof(g4));
    keepvault::secure_zero(&carry, sizeof(carry));
    keepvault::secure_zero(&use_g, sizeof(use_g));
    keepvault::secure_zero(&use_h, sizeof(use_h));
    keepvault::secure_zero(&word, sizeof(word));
}

static int poly1305_compute_parallel(
    const std::uint8_t one_time_key[32],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* ciphertext,
    std::size_t ciphertext_length,
    const poly1305_plan& plan,
    std::uint8_t tag[16]) noexcept
{
    std::array<poly1305_segment, kPoly1305MaxThreads> segments{};
    const std::size_t base = plan.total_blocks / plan.thread_count;
    const std::size_t extra = plan.total_blocks % plan.thread_count;
    std::size_t first = 0;
    for (std::size_t index = 0; index < plan.thread_count; ++index) {
        segments[index].first_block = first;
        segments[index].block_count = base + (index < extra ? 1 : 0);
        first += segments[index].block_count;
    }

    poly1305_field r = poly1305_clamped_r(one_time_key);
    std::array<std::thread, kPoly1305MaxThreads - 1> threads;
    std::size_t started = 0;
    std::size_t first_unstarted = 1;
    for (; first_unstarted < plan.thread_count; ++first_unstarted) {
        try {
            const std::size_t segment_index = first_unstarted;
            threads[started] = std::thread([&, segment_index]() noexcept {
                poly1305_evaluate_segment(
                    segments[segment_index],
                    associated_data,
                    associated_length,
                    ciphertext,
                    ciphertext_length,
                    plan,
                    r);
            });
            ++started;
        } catch (...) {
            break;
        }
    }

    /* A thread creation failure is a performance event, not a crypto failure. */
    for (std::size_t index = first_unstarted; index < plan.thread_count; ++index) {
        poly1305_evaluate_segment(
            segments[index],
            associated_data,
            associated_length,
            ciphertext,
            ciphertext_length,
            plan,
            r);
    }
    poly1305_evaluate_segment(
        segments[0],
        associated_data,
        associated_length,
        ciphertext,
        ciphertext_length,
        plan,
        r);

    for (std::size_t index = 0; index < started; ++index) {
        if (threads[index].joinable()) {
            threads[index].join();
        }
    }

    poly1305_field combined = segments[0].hash;
    for (std::size_t index = 1; index < plan.thread_count; ++index) {
        poly1305_field power = poly1305_power(r, segments[index].block_count);
        combined = poly1305_multiply(combined, power);
        poly1305_add(combined, segments[index].hash);
        keepvault::secure_zero(&power, sizeof(power));
    }
    poly1305_finish(combined, one_time_key + 16, tag);

    keepvault::secure_zero(&combined, sizeof(combined));
    keepvault::secure_zero(&r, sizeof(r));
    keepvault::secure_zero(segments.data(), sizeof(segments));
    return 0;
}

}  // namespace

/*
 * ChaCha20-Poly1305 (RFC 8439), with both halves spread across workers.
 *
 * Crypto++ has its own ChaCha20Poly1305, and this file used to call it. It runs
 * the whole request on one thread, which left the outermost layer of every
 * cascade at the speed of a single core over data five ciphers had already
 * touched - the slowest stage in the catalogue by a wide margin.
 *
 * ChaCha20 numbers its blocks and derives each from the counter alone, so it
 * splits exactly as it does above. Poly1305 workers evaluate contiguous
 * 16-byte block ranges from h=0, and their 130-bit results are joined in order
 * with H(L || R) = H(L) * r^blocks(R) + H(R). Only the final joined value is
 * reduced to 128 bits and offset by s.
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
    const int result = chacha20_range(
        key, nonce, 0, zeros, one_time_key, CHACHAPOLY_KEY_BYTES);
    keepvault::secure_zero(zeros, sizeof(zeros));
    if (result != 0) {
        keepvault::secure_zero(one_time_key, CHACHAPOLY_KEY_BYTES);
    }
    return result;
}

/*
 * RFC 8439 section 2.8: the associated data zero-padded to a multiple of 16,
 * the ciphertext zero-padded the same way, then both lengths as 64-bit little
 * endian. The padding and the lengths are what stop a byte moving from one
 * field into the other without changing the tag.
 */
static void poly1305_serial_pad_to_16(CryptoPP::Poly1305TLS& mac, std::size_t length)
{
    const std::size_t remainder = length % 16;
    if (remainder != 0) {
        std::uint8_t zeros[16];
        std::memset(zeros, 0, sizeof(zeros));
        mac.Update(zeros, 16 - remainder);
        keepvault::secure_zero(zeros, sizeof(zeros));
    }
}

static void poly1305_serial_append_length(CryptoPP::Poly1305TLS& mac, std::size_t length)
{
    std::uint8_t encoded[8];
    const std::uint64_t value = static_cast<std::uint64_t>(length);
    for (int i = 0; i < 8; ++i) {
        encoded[i] = static_cast<std::uint8_t>(value >> (i * 8));
    }

    mac.Update(encoded, sizeof(encoded));
    keepvault::secure_zero(encoded, sizeof(encoded));
}

static int compute_tag_serial(
    const std::uint8_t one_time_key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* ciphertext,
    std::size_t length,
    std::uint8_t tag[CHACHAPOLY_TAG_BYTES])
{
    try {
        CryptoPP::Poly1305TLS mac;
        mac.SetKey(one_time_key, CHACHAPOLY_KEY_BYTES);

        if (associated_length != 0) {
            mac.Update(associated_data, associated_length);
        }
        poly1305_serial_pad_to_16(mac, associated_length);

        if (length != 0) {
            mac.Update(ciphertext, length);
        }
        poly1305_serial_pad_to_16(mac, length);

        poly1305_serial_append_length(mac, associated_length);
        poly1305_serial_append_length(mac, length);

        mac.Final(tag);
        return 0;
    } catch (...) {
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

static int validate_auth_arguments(
    const std::uint8_t* key,
    const std::uint8_t* nonce,
    const std::uint8_t* tag,
    const std::uint8_t* ciphertext,
    std::size_t length,
    const std::uint8_t* associated_data,
    std::size_t associated_length)
{
    if (key == nullptr || nonce == nullptr || tag == nullptr) {
        return 1;
    }
    if (length != 0 && ciphertext == nullptr) {
        return 1;
    }
    if (associated_length != 0 && associated_data == nullptr) {
        return 1;
    }
    return 0;
}

static int chacha20poly1305_encrypt_impl(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* plaintext,
    std::uint8_t* ciphertext,
    std::size_t length,
    std::uint8_t tag[CHACHAPOLY_TAG_BYTES],
    std::uint32_t requested_poly1305_workers,
    bool serial_reference)
{
    const int invalid = validate_aead_arguments(
        key, nonce, tag, plaintext, ciphertext, length, associated_data, associated_length);
    if (invalid != 0) {
        return invalid;
    }

    const int chacha_range_status = chacha20_validate_counter_range(1, length);
    if (chacha_range_status != 0) {
        return chacha_range_status;
    }

    poly1305_plan plan{};
    const int planned = poly1305_make_plan(
        associated_length,
        length,
        serial_reference ? 1u : requested_poly1305_workers,
        plan);
    if (planned != 0) {
        return planned;
    }

    /* Both xcrypt entry points validate counter exhaustion before writing. */
    std::uint8_t one_time_key[CHACHAPOLY_KEY_BYTES]{};
    const int derived = derive_poly1305_key(key, nonce, one_time_key);
    if (derived != 0) {
        keepvault::secure_zero(one_time_key, sizeof(one_time_key));
        return derived;
    }

    const int encrypted = serial_reference
        ? chacha20_xcrypt_serial(key, nonce, 1, plaintext, ciphertext, length)
        : chacha20_xcrypt(key, nonce, 1, plaintext, ciphertext, length);
    if (encrypted != 0) {
        keepvault::secure_zero(one_time_key, sizeof(one_time_key));
        return encrypted;
    }

    const int tagged = serial_reference
        ? compute_tag_serial(
            one_time_key,
            associated_data,
            associated_length,
            ciphertext,
            length,
            tag)
        : poly1305_compute_parallel(
            one_time_key,
            associated_data,
            associated_length,
            ciphertext,
            length,
            plan,
            tag);
    keepvault::secure_zero(one_time_key, sizeof(one_time_key));
    return tagged;
}

static int chacha20poly1305_decrypt_impl(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* ciphertext,
    std::uint8_t* plaintext,
    std::size_t length,
    const std::uint8_t tag[CHACHAPOLY_TAG_BYTES],
    std::uint32_t requested_poly1305_workers,
    bool serial_reference)
{
    const int invalid = validate_aead_arguments(
        key, nonce, tag, ciphertext, plaintext, length, associated_data, associated_length);
    if (invalid != 0) {
        return invalid;
    }

    const int chacha_range_status = chacha20_validate_counter_range(1, length);
    if (chacha_range_status != 0) {
        return chacha_range_status;
    }

    poly1305_plan plan{};
    const int planned = poly1305_make_plan(
        associated_length,
        length,
        serial_reference ? 1u : requested_poly1305_workers,
        plan);
    if (planned != 0) {
        return planned;
    }

    std::uint8_t one_time_key[CHACHAPOLY_KEY_BYTES]{};
    const int derived = derive_poly1305_key(key, nonce, one_time_key);
    if (derived != 0) {
        keepvault::secure_zero(one_time_key, sizeof(one_time_key));
        return derived;
    }

    std::uint8_t expected[CHACHAPOLY_TAG_BYTES]{};
    const int tagged = serial_reference
        ? compute_tag_serial(
            one_time_key,
            associated_data,
            associated_length,
            ciphertext,
            length,
            expected)
        : poly1305_compute_parallel(
            one_time_key,
            associated_data,
            associated_length,
            ciphertext,
            length,
            plan,
            expected);
    keepvault::secure_zero(one_time_key, sizeof(one_time_key));
    if (tagged != 0) {
        keepvault::secure_zero(expected, sizeof(expected));
        return tagged;
    }

    const bool authentic = CryptoPP::VerifyBufsEqual(expected, tag, CHACHAPOLY_TAG_BYTES);
    keepvault::secure_zero(expected, sizeof(expected));
    if (!authentic) {
        return 6;
    }

    /* No plaintext byte is produced before the constant-time tag check above. */
    return serial_reference
        ? chacha20_xcrypt_serial(key, nonce, 1, ciphertext, plaintext, length)
        : chacha20_xcrypt(key, nonce, 1, ciphertext, plaintext, length);
}

static int chacha20poly1305_auth_impl(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* ciphertext,
    std::size_t length,
    std::uint8_t tag[CHACHAPOLY_TAG_BYTES],
    std::uint32_t requested_poly1305_workers,
    bool serial_reference)
{
    const int invalid = validate_auth_arguments(
        key, nonce, tag, ciphertext, length, associated_data, associated_length);
    if (invalid != 0) {
        return invalid;
    }

    poly1305_plan plan{};
    const int planned = poly1305_make_plan(
        associated_length,
        length,
        serial_reference ? 1u : requested_poly1305_workers,
        plan);
    if (planned != 0) {
        return planned;
    }

    std::uint8_t one_time_key[CHACHAPOLY_KEY_BYTES]{};
    const int derived = derive_poly1305_key(key, nonce, one_time_key);
    if (derived != 0) {
        keepvault::secure_zero(one_time_key, sizeof(one_time_key));
        return derived;
    }

    const int tagged = serial_reference
        ? compute_tag_serial(
            one_time_key,
            associated_data,
            associated_length,
            ciphertext,
            length,
            tag)
        : poly1305_compute_parallel(
            one_time_key,
            associated_data,
            associated_length,
            ciphertext,
            length,
            plan,
            tag);
    keepvault::secure_zero(one_time_key, sizeof(one_time_key));
    return tagged;
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
    return chacha20poly1305_encrypt_impl(
        key,
        nonce,
        associated_data,
        associated_length,
        plaintext,
        ciphertext,
        length,
        tag,
        0,
        false);
}

/* Explicit fixed-worker and serial exports are v12 differential-test seams. */
extern "C" KEEPVAULT_EXPORT int chacha20poly1305_encrypt_with_workers(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* plaintext,
    std::uint8_t* ciphertext,
    std::size_t length,
    std::uint8_t tag[CHACHAPOLY_TAG_BYTES],
    std::uint32_t poly1305_workers)
{
    return chacha20poly1305_encrypt_impl(
        key,
        nonce,
        associated_data,
        associated_length,
        plaintext,
        ciphertext,
        length,
        tag,
        poly1305_workers,
        false);
}

extern "C" KEEPVAULT_EXPORT int chacha20poly1305_encrypt_serial(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* plaintext,
    std::uint8_t* ciphertext,
    std::size_t length,
    std::uint8_t tag[CHACHAPOLY_TAG_BYTES])
{
    return chacha20poly1305_encrypt_impl(
        key,
        nonce,
        associated_data,
        associated_length,
        plaintext,
        ciphertext,
        length,
        tag,
        1,
        true);
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
    return chacha20poly1305_decrypt_impl(
        key,
        nonce,
        associated_data,
        associated_length,
        ciphertext,
        plaintext,
        length,
        tag,
        0,
        false);
}

extern "C" KEEPVAULT_EXPORT int chacha20poly1305_decrypt_with_workers(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* ciphertext,
    std::uint8_t* plaintext,
    std::size_t length,
    const std::uint8_t tag[CHACHAPOLY_TAG_BYTES],
    std::uint32_t poly1305_workers)
{
    return chacha20poly1305_decrypt_impl(
        key,
        nonce,
        associated_data,
        associated_length,
        ciphertext,
        plaintext,
        length,
        tag,
        poly1305_workers,
        false);
}

extern "C" KEEPVAULT_EXPORT int chacha20poly1305_decrypt_serial(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* ciphertext,
    std::uint8_t* plaintext,
    std::size_t length,
    const std::uint8_t tag[CHACHAPOLY_TAG_BYTES])
{
    return chacha20poly1305_decrypt_impl(
        key,
        nonce,
        associated_data,
        associated_length,
        ciphertext,
        plaintext,
        length,
        tag,
        1,
        true);
}

extern "C" KEEPVAULT_EXPORT int chacha20poly1305_auth_with_workers(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* ciphertext,
    std::size_t length,
    std::uint8_t tag[CHACHAPOLY_TAG_BYTES],
    std::uint32_t poly1305_workers)
{
    return chacha20poly1305_auth_impl(
        key,
        nonce,
        associated_data,
        associated_length,
        ciphertext,
        length,
        tag,
        poly1305_workers,
        false);
}

extern "C" KEEPVAULT_EXPORT int chacha20poly1305_auth_serial(
    const std::uint8_t key[CHACHAPOLY_KEY_BYTES],
    const std::uint8_t nonce[CHACHAPOLY_NONCE_BYTES],
    const std::uint8_t* associated_data,
    std::size_t associated_length,
    const std::uint8_t* ciphertext,
    std::size_t length,
    std::uint8_t tag[CHACHAPOLY_TAG_BYTES])
{
    return chacha20poly1305_auth_impl(
        key,
        nonce,
        associated_data,
        associated_length,
        ciphertext,
        length,
        tag,
        1,
        true);
}
