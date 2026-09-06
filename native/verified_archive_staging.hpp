#ifndef KEEPVAULT_VERIFIED_ARCHIVE_STAGING_HPP
#define KEEPVAULT_VERIFIED_ARCHIVE_STAGING_HPP

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

namespace keepvault {

// Private in-process staging of an integrity-checked regular ZPAQ stream.
// This is an internal v12 pipe envelope, not an on-disk container format.
// No named IPC object, pathname reopening, or device/inode claim is involved.
class VerifiedArchiveStaging final {
public:
    static std::unique_ptr<VerifiedArchiveStaging> Read(
        FILE* input, std::uint64_t maximum_bytes)
    {
        std::array<unsigned char, 16> header{};
        static constexpr unsigned char magic[8] = {'K','V','1','2','V','M',0,0};
        if (input == nullptr || std::fread(header.data(), 1, header.size(), input) != header.size()
            || std::memcmp(header.data(), magic, sizeof(magic)) != 0)
            throw std::runtime_error("invalid v12 verified-staging envelope");
        std::uint64_t length = 0;
        for (std::size_t i = 8; i < header.size(); ++i)
            length = (length << 8) | header[i];
        if (length == 0 || length > maximum_bytes
            || length > std::numeric_limits<std::size_t>::max())
            throw std::runtime_error("v12 verified-staging length exceeds its bound");

        auto result = std::unique_ptr<VerifiedArchiveStaging>(
            new VerifiedArchiveStaging(static_cast<std::size_t>(length)));
        constexpr std::size_t window = 1024 * 1024;
        while (result->written_ < result->size_) {
            const std::size_t remaining = result->size_ - result->written_;
            const std::size_t count = remaining < window ? remaining : window;
            const std::size_t read = std::fread(
                result->bytes_ + result->written_, 1, count, input);
            result->written_ += read;
            if (read != count)
                throw std::runtime_error("truncated v12 verified-staging payload");
        }
        if (std::fgetc(input) != EOF || std::ferror(input))
            throw std::runtime_error("trailing or unreadable v12 verified-staging payload");

        // Reduce maximum protection as well as current protection. The parser
        // must not be able to regain write access through mprotect afterwards.
        if (mach_vm_protect(mach_task_self(),
                reinterpret_cast<mach_vm_address_t>(result->bytes_),
                result->size_, TRUE, VM_PROT_READ) != KERN_SUCCESS)
            throw std::runtime_error("cannot seal v12 verified-staging memory");
        result->sealed_ = true;
        return result;
    }

    ~VerifiedArchiveStaging() noexcept
    {
        if (bytes_ != nullptr) {
            if (!sealed_) {
                volatile unsigned char* clear = bytes_;
                for (std::size_t i = 0; i < written_; ++i) clear[i] = 0;
            }
            (void)munmap(bytes_, size_);
        }
    }
    VerifiedArchiveStaging(const VerifiedArchiveStaging&) = delete;
    VerifiedArchiveStaging& operator=(const VerifiedArchiveStaging&) = delete;
    const unsigned char* data() const noexcept { return bytes_; }
    std::size_t size() const noexcept { return size_; }

private:
    explicit VerifiedArchiveStaging(std::size_t size) : size_(size)
    {
        void* memory = mmap(nullptr, size, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON, -1, 0);
        if (memory == MAP_FAILED)
            throw std::runtime_error("cannot allocate bounded v12 verified-staging memory");
        bytes_ = static_cast<unsigned char*>(memory);
    }
    unsigned char* bytes_ = nullptr;
    std::size_t size_ = 0;
    std::size_t written_ = 0;
    bool sealed_ = false;
};
}
#endif
