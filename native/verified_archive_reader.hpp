#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <mutex>
#include <stdexcept>

namespace keepvault {

// The parser receives no source file descriptor. Each bounded response comes
// from the parent's authenticated read-at interface. All parallel parser
// readers serialize complete request/response transactions through this object.
class VerifiedArchiveReader final {
    FILE* input_;
    FILE* requests_;
    std::uint64_t length_;
    std::mutex gate_;
    static constexpr std::size_t window_ = 1u << 20;

    static void exact(FILE* stream, void* output, std::size_t count) {
        auto* bytes = static_cast<unsigned char*>(output);
        while (count) {
            const auto n = std::fread(bytes, 1, count, stream);
            if (!n || std::ferror(stream))
                throw std::runtime_error("verified read-at response is incomplete");
            bytes += n;
            count -= n;
        }
    }

public:
    VerifiedArchiveReader(FILE* input, FILE* requests) : input_(input), requests_(requests), length_(0) {
        unsigned char header[16];
        exact(input_, header, sizeof(header));
        const unsigned char magic[8] = {'K','V','1','3','R','A',0,0};
        if (!std::equal(header, header + 8, magic))
            throw std::runtime_error("invalid verified read-at protocol");
        for (unsigned i = 8; i != 16; ++i) length_ = (length_ << 8) | header[i];
        if (!length_ || length_ > std::uint64_t(std::numeric_limits<std::int64_t>::max()))
            throw std::runtime_error("invalid verified read-at length");
    }

    std::uint64_t size() const noexcept { return length_; }

    void read_at(std::uint64_t offset, void* output, std::size_t count) {
        std::lock_guard<std::mutex> lock(gate_);
        if (offset > length_ || count > length_ - offset)
            throw std::runtime_error("verified read-at request exceeds archive");
        auto* bytes = static_cast<unsigned char*>(output);
        while (count) {
            const auto n = std::min(count, window_);
            unsigned char request[12];
            for (unsigned i = 0; i != 8; ++i) request[i] = static_cast<unsigned char>(offset >> (56 - i * 8));
            for (unsigned i = 0; i != 4; ++i) request[8+i] = static_cast<unsigned char>(n >> (24 - i * 8));
            if (std::fwrite(request, 1, sizeof(request), requests_) != sizeof(request)
                    || std::fflush(requests_) != 0)
                throw std::runtime_error("verified read-at request write failed");
            exact(input_, bytes, n);
            bytes += n;
            offset += n;
            count -= n;
        }
    }
};
}
