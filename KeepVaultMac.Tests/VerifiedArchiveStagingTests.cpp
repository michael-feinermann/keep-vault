#include "../native/verified_archive_staging.hpp"
#include <cerrno>
#include <vector>
#include <sys/mount.h>
#include <cstddef>

// Independent SDK checks for the signer's descriptor-bound volume-policy ABI.
static_assert(sizeof(struct statfs) == 2168, "Darwin statfs64 size");
static_assert(offsetof(struct statfs, f_flags) == 64, "Darwin statfs64 flags offset");
static_assert(MNT_IGNORE_OWNERSHIP == 0x00200000, "Darwin ownership flag");

static std::vector<unsigned char> envelope(std::size_t payload) {
    std::vector<unsigned char> bytes(16 + payload);
    const unsigned char magic[8] = {0x4b,0x56,0x31,0x32,0x56,0x4d,0,0};
    std::memcpy(bytes.data(), magic, 8);
    std::uint64_t size = payload;
    for (int i = 15; i >= 8; --i) { bytes[i] = static_cast<unsigned char>(size); size >>= 8; }
    for (std::size_t i = 16; i < bytes.size(); ++i) bytes[i] = static_cast<unsigned char>(i * 37);
    return bytes;
}

static bool check(std::vector<unsigned char> bytes, std::uint64_t maximum, bool valid) {
    FILE* stream = tmpfile();
    if (!stream) return false;
    if (std::fwrite(bytes.data(), 1, bytes.size(), stream) != bytes.size()) { fclose(stream); return false; }
    rewind(stream);
    bool passed = false;
    try {
        auto staging = keepvault::VerifiedArchiveStaging::Read(stream, maximum);
        passed = valid && staging->size() == bytes.size() - 16
            && std::memcmp(staging->data(), bytes.data() + 16, staging->size()) == 0;
        // Neither libc nor Mach may restore write access after sealing.
        errno = 0;
        passed = passed && mprotect(const_cast<unsigned char*>(staging->data()),
            staging->size(), PROT_READ | PROT_WRITE) != 0;
        passed = passed && mach_vm_protect(mach_task_self(),
            reinterpret_cast<mach_vm_address_t>(staging->data()), staging->size(),
            FALSE, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS;
    }
    catch (const std::runtime_error&) { passed = !valid; }
    if (fclose(stream) != 0) passed = false;
    return passed;
}

int main() {
    unsigned checks = 0;
    auto require = [&](std::vector<unsigned char> bytes, std::uint64_t maximum, bool valid) {
        ++checks;
        if (!check(std::move(bytes), maximum, valid)) {
            std::fprintf(stderr, "verified staging check %u failed\n", checks);
            std::exit(1);
        }
    };
    for (std::size_t size : {1u, 4095u, 4096u, 4097u, 1024u * 1024u + 17u})
        require(envelope(size), size, true);
    require(envelope(0), 4096, false);
    require(envelope(4097), 4096, false);
    auto invalid = envelope(16);
    invalid[0] ^= 1; require(invalid, 4096, false);
    invalid = envelope(16); invalid.resize(15); require(invalid, 4096, false);
    invalid = envelope(16); invalid.pop_back(); require(invalid, 4096, false);
    invalid = envelope(16); invalid.push_back(0); require(invalid, 4096, false);
    invalid = envelope(16);
    std::memset(invalid.data() + 8, 0xff, 8); require(invalid, 512ULL * 1024 * 1024 * 1024, false);
    for (int i = 0; i < 32; ++i) require(envelope(1), 1, true);
    std::printf("verified_staging_vm=pass checks=%u\n", checks);
    return 0;
}
