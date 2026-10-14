// Standalone test target. Public deterministic data, no production secrets.
#include "../verified_archive_reader.hpp"
#include <array>
#include <cerrno>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {
struct Rng {
    std::uint64_t value;
    std::uint64_t next() {
        value += UINT64_C(0x9e3779b97f4a7c15);
        std::uint64_t z = value;
        z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
        return z ^ (z >> 31);
    }
};
using File = std::unique_ptr<FILE, int(*)(FILE*)>;
File temporary() {
    FILE* file = std::tmpfile();
    if (!file) throw std::runtime_error("fixture tmpfile failed");
    return File(file, &std::fclose);
}
void require(bool valid, const char* message) { if (!valid) throw std::logic_error(message); }
void write_all(FILE* file, const void* data, std::size_t size) {
    require(std::fwrite(data, 1, size, file) == size, "fixture write failed");
}
void be64(unsigned char* target, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) target[i] = static_cast<unsigned char>(value >> (56 - 8 * i));
}
std::uint64_t load(const unsigned char* source, unsigned bytes) {
    std::uint64_t result = 0;
    for (unsigned i = 0; i < bytes; ++i) result = (result << 8) | source[i];
    return result;
}
unsigned char oracle(std::uint64_t position, std::uint64_t case_seed) {
    Rng generator{position ^ case_seed};
    return static_cast<unsigned char>(generator.next());
}
void guards(const std::vector<unsigned char>& bytes, std::size_t payload) {
    for (unsigned i = 0; i < 64; ++i)
        require(bytes[i] == 0xa7 && bytes[64 + payload + i] == 0xa7, "output canary overwritten");
}
}

int main(int argc, char** argv) {
    std::uint64_t seed = UINT64_C(0x4b5631335241465a);
    if (argc > 2) { std::fprintf(stderr, "usage: verified_read_at_fuzz [seed]\n"); return 2; }
    if (argc == 2) {
        char* end = nullptr; errno = 0;
        seed = std::strtoull(argv[1], &end, 0);
        if (errno || !end || *end) return 2;
    }
    std::size_t accepted = 0, rejected = 0, response_bytes = 0, maximum = 0, transactions = 0;
    for (unsigned index = 0; index < 10000; ++index) {
        const unsigned mode = index % 12;
        Rng random{seed ^ (UINT64_C(0xd1342543de82ef95) * (index + 1))};
        const std::uint64_t case_seed = random.next();
        std::uint64_t length = 1 + (random.next() & UINT64_C(0x7ffffffffffffffe));
        std::size_t count = 1 + random.next() % 4096;
        if (index % 1000 == 0) count = (1u << 20) + 1 + random.next() % 127;
        length = std::max(length, std::uint64_t(count));
        std::uint64_t offset = random.next() % (length - count + 1);
        std::vector<unsigned char> output(count + 128, 0xa7);
        try {
            File responses = temporary(), requests = temporary();
            std::array<unsigned char, 16> header{{'K','V','1','3','R','A',0,0}};
            be64(header.data() + 8, length);
            std::size_t header_bytes = header.size();
            if (mode == 3) header[random.next() % 8] ^= static_cast<unsigned char>(1u << (random.next() % 8));
            if (mode == 4) header_bytes = random.next() % 16;
            if (mode == 5) be64(header.data() + 8, 0);
            if (mode == 6) be64(header.data() + 8, random.next() | UINT64_C(0x8000000000000000));
            write_all(responses.get(), header.data(), header_bytes);
            std::vector<unsigned char> bytes(count);
            for (std::size_t i = 0; i < count; ++i) bytes[i] = oracle(offset + i, case_seed);
            std::size_t supplied = mode == 4 ? 0 : count;
            if (mode == 9) supplied = random.next() % count;
            write_all(responses.get(), bytes.data(), supplied);
            std::rewind(responses.get());
            bool failed = false;
            try {
                keepvault::VerifiedArchiveReader reader(responses.get(), requests.get());
                require(reader.size() == length, "archive length changed");
                if (mode == 7) reader.read_at(length + 1, output.data() + 64, 1);
                else if (mode == 8) reader.read_at(length, output.data() + 64, 1 + random.next() % 4096);
                else if (mode == 10) reader.read_at(UINT64_MAX, output.data() + 64, SIZE_MAX);
                else if (mode == 11) reader.read_at(length, output.data() + 64, 0);
                else reader.read_at(offset, output.data() + 64, count);
            }
            catch (const std::runtime_error&) { failed = true; }
            const bool expected_failure = mode >= 3 && mode <= 10;
            require(failed == expected_failure, "accept/reject oracle disagrees");
            guards(output, count);
            std::rewind(requests.get());
            if (!failed && mode != 11) {
                require(std::equal(bytes.begin(), bytes.end(), output.begin() + 64), "valid response differs from offset oracle");
                std::size_t remaining = count;
                std::uint64_t requested_offset = offset;
                while (remaining) {
                    std::array<unsigned char, 12> request{};
                    require(std::fread(request.data(), 1, request.size(), requests.get()) == request.size(), "request frame truncated");
                    const std::size_t chunk = std::min(remaining, std::size_t(1u << 20));
                    require(load(request.data(), 8) == requested_offset && load(request.data() + 8, 4) == chunk,
                        "request framing disagrees with independent BE64/BE32 oracle");
                    remaining -= chunk; requested_offset += chunk; ++transactions;
                }
                require(std::fgetc(requests.get()) == EOF, "extra request bytes");
                ++accepted;
            }
            else if (mode != 9) {
                require(std::fgetc(requests.get()) == EOF, "invalid or empty request produced bytes");
                require(std::all_of(output.begin(), output.end(), [](unsigned char b){ return b == 0xa7; }), "pre-admission failure changed output");
                if (failed) ++rejected; else ++accepted;
            }
            else {
                // Truncated transport may fill a prefix, but may neither report
                // success nor write beyond the caller's explicitly sized region.
                for (std::size_t i = 0; i < supplied; ++i) require(output[64 + i] == bytes[i], "partial transport prefix differs");
                for (std::size_t i = supplied; i < count; ++i) require(output[64 + i] == 0xa7, "truncated transport wrote missing bytes");
                ++rejected;
            }
            response_bytes += supplied + header_bytes;
            maximum = std::max(maximum, supplied + header_bytes);
        }
        catch (const std::exception& failure) {
            std::fprintf(stderr, "read_at_fuzz=FAIL seed=0x%016" PRIx64 " case=%u mode=%u offset=%" PRIu64 " count=%zu length=%" PRIu64 " error=%s\n",
                seed, index, mode, offset, count, length, failure.what());
            return 1;
        }
    }
    std::printf("read_at_fuzz=PASS seed=0x%016" PRIx64 " cases=10000 accepted=%zu rejected=%zu response_bytes_total=%zu maximum_case_bytes=%zu request_transactions=%zu canaries=PASS oracle=independent-offset-pattern-and-BE-framing\n",
        seed, accepted, rejected, response_bytes, maximum, transactions);
    return 0;
}
