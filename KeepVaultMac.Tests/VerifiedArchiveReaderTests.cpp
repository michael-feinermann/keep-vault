#include "../native/verified_archive_reader.hpp"
#include <cassert>
#include <cstring>
#include <vector>

static FILE* input(std::uint64_t length, const char* magic = "KV13RA\0\0", std::size_t payload = 0) {
    FILE* f = tmpfile(); assert(f);
    unsigned char header[16]; memcpy(header, magic, 8);
    for (unsigned i=0;i<8;++i) header[8+i]=static_cast<unsigned char>(length>>(56-8*i));
    assert(fwrite(header,1,16,f)==16);
    for (std::size_t i=0;i<payload;++i) assert(fputc(int(i%251),f)!=EOF);
    rewind(f); return f;
}
int main() {
    unsigned checks=0;
    for (std::uint64_t n : {0ull, 0x8000000000000000ull, 0xffffffffffffffffull}) {
        FILE* f=input(n); FILE* o=tmpfile(); bool failed=false;
        try {keepvault::VerifiedArchiveReader r(f,o);} catch (const std::runtime_error&) {failed=true;}
        assert(failed); ++checks; fclose(f); fclose(o);
    }
    for (const char* magic : {"KV12VM\0\0", "KV13VM\0\0", "KV13RAxx"}) {
        FILE* f=input(1,magic); FILE* o=tmpfile(); bool failed=false;
        try {keepvault::VerifiedArchiveReader r(f,o);} catch (const std::runtime_error&) {failed=true;}
        assert(failed); ++checks; fclose(f); fclose(o);
    }
    constexpr std::size_t count=(1u<<20)+3;
    FILE* f=input(1ull<<42,"KV13RA\0\0",count); FILE* o=tmpfile();
    keepvault::VerifiedArchiveReader r(f,o); assert(r.size()==(1ull<<42)); ++checks;
    std::vector<unsigned char> bytes(count); r.read_at((1ull<<32)+17,bytes.data(),bytes.size());
    for (std::size_t i=0;i<count;++i) assert(bytes[i]==i%251);
    ++checks; assert(ftell(o)==24); ++checks;
    rewind(o); unsigned char request[24]; assert(fread(request,1,24,o)==24);
    assert(request[3]==1 && request[7]==17 && request[9]==0x10 && request[23]==3); ++checks;
    for (std::uint64_t off : {(1ull<<42), 0xffffffffffffffffull}) {
        bool failed=false;try {r.read_at(off,bytes.data(),1);}catch (const std::runtime_error&){failed=true;}
        assert(failed);++checks;
    }
    bool failed=false;try {r.read_at(0,bytes.data(),1);}catch (const std::runtime_error&){failed=true;}
    assert(failed);++checks;fclose(f);fclose(o);
    printf("verified_read_at_native=pass checks=%u\n",checks);
}
