// Keep Vault REV11: actual native model admission, lifetime and fault tests.
// clang++ -std=c++17 -O1 -DNOJIT -DBSD zpaq_model_budget.cpp libzpaq.cpp -o test
#include "../../external/zpaq/libzpaq.h"
#include <cstdio>
#include <cstddef>
#include <cstring>
#include <new>
#include <limits>

namespace {
struct Failure {};
struct Allocation { size_t bytes; alignas(std::max_align_t) unsigned char data[1]; };
constexpr size_t allocation_overhead=80; // native arm64 header16 +64 allocator margin
size_t live_bytes=0, peak_bytes=0, allocations=0;
size_t fail_after=std::numeric_limits<size_t>::max();
size_t reserved=0, reservation_base=0, max_reserved=0;
unsigned owners=0, acquire_calls=0, release_calls=0, deny_call=0;
bool coverage_failure=false, lifetime_failure=false;
uint64_t granted[256]={0};
void require(bool ok, const char* message) {
  if (!ok) {std::fprintf(stderr,"FAIL: %s\n",message); throw Failure();}
}
void check_coverage() {
  if (owners && live_bytes>reservation_base+reserved+owners*128) {
    if (!coverage_failure) std::fprintf(stderr,"coverage live=%zu base=%zu reserved=%zu owners=%u\n",live_bytes,reservation_base,reserved,owners);
    coverage_failure=true;
  }
  if (live_bytes>peak_bytes) peak_bytes=live_bytes;
}
void reset_tracking() {
  require(!owners && !reserved,"prior reservations survived");
  acquire_calls=release_calls=deny_call=0;
  coverage_failure=lifetime_failure=false;
  max_reserved=0; peak_bytes=live_bytes;
  fail_after=std::numeric_limits<size_t>::max();
}
struct Owner: libzpaq::MemoryReservation {
  size_t bytes, baseline;
  explicit Owner(size_t n):bytes(n),baseline(live_bytes) {
    if (!owners) reservation_base=live_bytes;
    ++owners; reserved+=bytes;
    if (reserved>max_reserved) max_reserved=reserved;
  }
  ~Owner() override {
    // The reservation object itself is included in the baseline. Exception
    // tests throw a trivial object, so no exception-message allocation hides
    // buffers released too late.
    if (live_bytes>baseline) lifetime_failure=true;
    reserved-=bytes; --owners; ++release_calls;
  }
};
libzpaq::MemoryReservation* acquire(uint64_t bytes) {
  ++acquire_calls;
  if (acquire_calls<=256) granted[acquire_calls-1]=bytes;
  if (acquire_calls==deny_call) throw Failure();
  return new Owner(size_t(bytes));
}
struct FixedBuffer: libzpaq::Reader,libzpaq::Writer {
  unsigned char* bytes;
  size_t length=0, position=0, capacity;
  explicit FixedBuffer(size_t n):bytes(new unsigned char[n]),capacity(n) {}
  ~FixedBuffer() {delete[] bytes;}
  void put(int c) override {
    if (length==capacity) throw Failure();
    bytes[length++]=static_cast<unsigned char>(c);
  }
  void write(const char* p,int n) override {
    if (n<0 || size_t(n)>capacity-length) throw Failure();
    std::memcpy(bytes+length,p,n); length+=n;
  }
  int get() override {return position<length ? bytes[position++] : -1;}
  int read(char* p,int n) override {
    size_t count=std::min(size_t(n),length-position);
    std::memcpy(p,bytes+position,count); position+=count; return int(count);
  }
};
void fill(libzpaq::StringBuffer& in,size_t n) {
  for (size_t i=0;i<n;++i) in.put(int((i*71+i/17)%223)); // no E8/E9 transform
}
void finish_checks(size_t baseline) {
  require(!owners && !reserved,"reservation leaked");
  require(!lifetime_failure,"reservation released before model buffers");
  require(!coverage_failure,"allocation exceeded concrete admitted bytes");
  require(live_bytes==baseline,"model allocation leaked");
}
}

size_t keepvault_budget_allocation_overhead() noexcept {return allocation_overhead;}
void* keepvault_budget_malloc(size_t n) {
  if (allocations++==fail_after) return 0;
  if (n>SIZE_MAX-sizeof(Allocation)) return 0;
  Allocation* a=static_cast<Allocation*>(std::malloc(sizeof(Allocation)+n));
  if (!a) return 0;
  a->bytes=n; live_bytes+=n+allocation_overhead; check_coverage(); return a->data;
}
void keepvault_budget_free(void* p) noexcept {
  if (!p) return;
  Allocation* a=reinterpret_cast<Allocation*>(static_cast<unsigned char*>(p)-offsetof(Allocation,data));
  live_bytes-=a->bytes+allocation_overhead; std::free(a);
}
void* keepvault_budget_calloc(size_t n,size_t s) {
  if (s && n>SIZE_MAX/s) return 0;
  void* p=keepvault_budget_malloc(n*s); if (p) std::memset(p,0,n*s); return p;
}
void* keepvault_budget_realloc(void* p,size_t n) {
  if (!p) return keepvault_budget_malloc(n);
  Allocation* old=reinterpret_cast<Allocation*>(static_cast<unsigned char*>(p)-offsetof(Allocation,data));
  void* q=keepvault_budget_malloc(n);
  if (q) {std::memcpy(q,p,std::min(n,old->bytes)); keepvault_budget_free(p);}
  return q;
}
bool keepvault_budget_reserve_mapping(size_t) {return false;}
void keepvault_budget_release_mapping(size_t) {}
void* operator new(size_t n) {void* p=keepvault_budget_malloc(n); if (!p) throw std::bad_alloc(); return p;}
void* operator new[](size_t n) {return ::operator new(n);}
void operator delete(void* p) noexcept {keepvault_budget_free(p);}
void operator delete[](void* p) noexcept {keepvault_budget_free(p);}
namespace libzpaq { [[noreturn]] void error(const char*) {throw Failure();} }

int main() {
 try {
  libzpaq::setMemoryReservationFactory(acquire);
  for (const char* method: {"0","1","2","3","4","5","6","9"}) {
    libzpaq::StringBuffer in; fill(in,4096);
    FixedBuffer compressed(1<<20), recovered(1<<20);
    reset_tracking(); size_t baseline=live_bytes;
    libzpaq::compressBlock(&in,&compressed,method,"test",0,false);
    finish_checks(baseline);
    require(acquire_calls==2 && release_calls==2,"compression must own parse and runtime admissions");
    require(max_reserved<(128ull<<20),"tiny input unexpectedly admitted a blanket large model");
    const uint64_t encode_bytes=granted[1];
    reset_tracking(); baseline=live_bytes;
    libzpaq::decompress(&compressed,&recovered);
    finish_checks(baseline);
    require(recovered.length==4096,"roundtrip length differs");
    for (size_t i=0;i<recovered.length;++i)
      require(recovered.bytes[i]==(i*71+i/17)%223,"roundtrip content differs");
    require(acquire_calls==2,"decode must own fixed parser and actual runtime model");
    std::printf("PASS method %s: encoder=%llu decoder=%llu bytes\n",method,
      static_cast<unsigned long long>(encode_bytes),static_cast<unsigned long long>(granted[1]));
  }
  {
    libzpaq::StringBuffer in; fill(in,1024); FixedBuffer out(1<<20);
    reset_tracking(); size_t baseline=live_bytes; deny_call=2;
    bool failed=false; try {libzpaq::compressBlock(&in,&out,"5",0,0,false);} catch (...) {failed=true;}
    require(failed && out.length==0,"denied model emitted archive bytes");
    finish_checks(baseline);
    std::puts("PASS denied model: no output and no surviving lease");
  }
  {
    libzpaq::StringBuffer in; fill(in,1024); FixedBuffer out(1<<20), recovered(1<<20);
    for (int i=0;i<3;++i) libzpaq::compressBlock(&in,&out,"2",0,0,false);
    reset_tracking(); size_t baseline=live_bytes;
    libzpaq::decompress(&out,&recovered);
    finish_checks(baseline);
    require(acquire_calls==4 && release_calls==4,"multi-block model owners accumulated");
    require(recovered.length==3072,"multi-block roundtrip length differs");
    reset_tracking(); out.position=0; baseline=live_bytes;
    { libzpaq::Decompresser d; d.setInput(&out);
      while (d.findBlock()) while (d.findFilename()) {d.readComment(); d.readSegmentEnd();} }
    finish_checks(baseline);
    require(acquire_calls==1,"header listing reserved an unused runtime model");
    std::puts("PASS multiple blocks and header-only scan: actual model lifetime");
  }
  for (const char* method: {"2","5"}) {
    libzpaq::StringBuffer in; fill(in,1024); FixedBuffer out(1<<20);
    reset_tracking(); size_t start_alloc=allocations;
    libzpaq::compressBlock(&in,&out,method,0,0,false);
    const size_t count=allocations-start_alloc;
    for (size_t fault=0;fault<count;++fault) {
      out.length=0; reset_tracking(); size_t baseline=live_bytes;
      fail_after=allocations+fault;
      try {libzpaq::compressBlock(&in,&out,method,0,0,false);} catch (...) {}
      fail_after=std::numeric_limits<size_t>::max(); finish_checks(baseline);
    }
    std::printf("PASS method %s allocation fault sweep: %zu allocation sites\n",method,count);
  }
  {
    libzpaq::StringBuffer in; fill(in,1024); FixedBuffer out(1<<20), recovered(1<<20);
    libzpaq::compressBlock(&in,&out,"3",0,0,false);
    reset_tracking(); size_t baseline=live_bytes; deny_call=2;
    bool failed=false; try {libzpaq::decompress(&out,&recovered);} catch (...) {failed=true;}
    require(failed && recovered.length==0,"denied decoder model emitted plaintext");
    finish_checks(baseline);
    reset_tracking(); out.position=0; size_t start_alloc=allocations;
    libzpaq::decompress(&out,&recovered);
    const size_t count=allocations-start_alloc;
    for (size_t fault=0;fault<count;++fault) {
      out.position=0; recovered.length=0; reset_tracking(); baseline=live_bytes;
      fail_after=allocations+fault;
      try {libzpaq::decompress(&out,&recovered);} catch (...) {}
      fail_after=std::numeric_limits<size_t>::max(); finish_checks(baseline);
    }
    std::printf("PASS decoder denial and allocation fault sweep: %zu allocation sites\n",count);
  }
  libzpaq::setMemoryReservationFactory(0);
  std::puts("PASS zpaq-model-budget"); return 0;
 } catch (...) {std::fprintf(stderr,"FAILED zpaq-model-budget\n"); return 1;}
}
