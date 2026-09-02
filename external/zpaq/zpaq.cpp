// zpaq.cpp - Journaling incremental deduplicating archiver

#define ZPAQ_VERSION "7.15"
/*
  This software is provided as-is, with no warranty.
  I, Matt Mahoney, release this software into
  the public domain.   This applies worldwide.
  In some countries this may not be legally possible; if so:
  I grant anyone the right to use this software for any purpose,
  without any conditions, unless such conditions are required by law.

zpaq is a journaling (append-only) archiver for incremental backups.
Files are added only when the last-modified date has changed. Both the old
and new versions are saved. You can extract from old versions of the
archive by specifying a date or version number. zpaq supports 5
compression levels, deduplication, AES-256 encryption, and multi-threading
using an open, self-describing format for backward and forward
compatibility in Windows and Linux. See zpaq.pod for usage.

TO COMPILE:

This program needs libzpaq from http://mattmahoney.net/zpaq/
Recommended compile for Windows with MinGW:

  g++ -O3 zpaq.cpp libzpaq.cpp -o zpaq

With Visual C++:

  cl /O2 /EHsc zpaq.cpp libzpaq.cpp advapi32.lib

For Linux:

  g++ -O3 -Dunix zpaq.cpp libzpaq.cpp -pthread -o zpaq

For BSD or OS/X

  g++ -O3 -Dunix -DBSD zpaq.cpp libzpaq.cpp -pthread -o zpaq

Possible options:

  -DDEBUG    Enable run time checks and help screen for undocumented options.
  -DNOJIT    Don't assume x86 with SSE2 for libzpaq. Slower (disables JIT).
  -Dunix     Not Windows. Sometimes automatic in Linux. Needed for Mac OS/X.
  -DBSD      For BSD or OS/X.
  -DPTHREAD  Use Pthreads instead of Windows threads. Requires pthreadGC2.dll
             or pthreadVC2.dll from http://sourceware.org/pthreads-win32/
  -Dunixtest To make -Dunix work in Windows with MinGW.
  -fopenmp   Parallel divsufsort (faster, implies -pthread, broken in MinGW).
  -pthread   Required in Linux, implied by -fopenmp.
  -O3 or /O2 Optimize (faster).
  -o         Name of output executable.
  /EHsc      Enable exception handing in VC++ (required).
  advapi32.lib  Required for libzpaq in VC++.

*/
#define _FILE_OFFSET_BITS 64  // In Linux make sizeof(off_t) == 8
#ifndef UNICODE
#define UNICODE  // For Windows
#endif
#include "libzpaq.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>
#include <stdarg.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <exception>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>
#include <fcntl.h>
#if defined(__APPLE__) && defined(__MACH__)
#include <CoreFoundation/CoreFoundation.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <spawn.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#endif
#ifdef _WIN32
#include <io.h>
#endif

#ifndef DEBUG
#define NDEBUG 1
#endif
#include <assert.h>

static bool g_pipe_archive=false;          // --pipe: archive "-" is stdin/stdout
static bool g_verified_archive_stdin=false; // --verified-stdin: authenticated regular archive on stdin
static std::atomic<int> g_keepvault_test_creation_read_error(0);
static std::atomic<int> g_keepvault_test_close_error(0);
static std::atomic<int> g_keepvault_test_output_open_error(0);
// Keep Vault v12 wraps every independently compressed streaming block in a
// bounded frame. The frame boundary is what lets extraction verify and
// decompress different blocks in parallel without buffering the whole archive
// or guessing where a compressed block ends. Older unframed pipe streams are
// deliberately not accepted by the v12 application.
static const char KEEPVAULT_PIPE_MAGIC[8]={'K','V','P','1','2','Z','P','1'};
static const unsigned char KEEPVAULT_ZPAQ_BLOCK_MAGIC[16]={
  0x37,0x6b,0x53,0x74,0xa0,0x31,0x83,0xd3,
  0x8c,0xb2,0x28,0xb0,0xd3,0x7a,0x50,0x51};
static const uint64_t KEEPVAULT_PIPE_MAX_COMPRESSED=24ull<<20;
static const uint64_t KEEPVAULT_PIPE_MAX_UNCOMPRESSED=32ull<<20;
static const double KEEPVAULT_PIPE_MAX_MODEL_MEMORY=128.0*1024.0*1024.0;
static const uint64_t KEEPVAULT_MAX_EXTRACTED_BYTES=500ull<<30;
static const uint64_t KEEPVAULT_MAX_SINGLE_FILE_BYTES=500ull<<30;
static const uint64_t KEEPVAULT_MAX_EXTRACTED_FILES=500000ull;
// The v12 scheduler admits reservations against a logical 6 GiB shared
// processing budget. It never allocates this amount as one object.
static const uint64_t KEEPVAULT_NATIVE_PROCESSING_BUDGET=6ull<<30;
// A regular v12 archive may be as large as 512 GiB. Verified stdin is staged
// into one unlinked, descriptor-bound POSIX-SHM object and read with pread(2),
// so this limit never implies a same-sized address-space mapping or allocation.
static const uint64_t KEEPVAULT_MAX_VERIFIED_ARCHIVE_BYTES=512ull<<30;
static const size_t KEEPVAULT_VERIFIED_STAGING_WINDOW=size_t(32)<<20;
static const uint64_t KEEPVAULT_COMPRESSION_JOB_RESERVATION=384ull<<20;
static const uint64_t KEEPVAULT_REGULAR_JOB_RESERVATION=592ull<<20;
static const uint64_t KEEPVAULT_PIPE_PENDING_COMPRESSED_BUDGET=512ull<<20;
static const uint64_t KEEPVAULT_REGULAR_MAX_UNCOMPRESSED=64ull<<20;
static const double KEEPVAULT_REGULAR_MAX_MODEL_MEMORY=512.0*1024.0*1024.0;
static const size_t KEEPVAULT_MAX_ARCHIVE_MEMBER_NAME_BYTES=32767;
static const size_t KEEPVAULT_MAX_ARCHIVE_COMMENT_BYTES=1024;
static const uint64_t MAX_ARCHIVE_FRAGMENTS=uint64_t(1)<<26;
static const uint64_t MAX_INDEX_BLOCK_BYTES=uint64_t(512)<<20;

static int zpaq_printf(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  const int result=vfprintf(g_pipe_archive ? stderr : stdout, fmt, args);
  va_end(args);
  return result;
}

#define printf zpaq_printf

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#ifndef unix
#define unix 1
#endif
#endif
#ifdef unix
#define PTHREAD 1
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include <dirent.h>
#include <utime.h>
#include <errno.h>
static int g_verified_archive_fd=-1;
static int64_t g_verified_archive_size=0;
static std::string g_keepvault_verified_shm_name;
static int g_keepvault_output_root_fd=-1;
static uint64_t g_keepvault_expected_root_device=0;
static uint64_t g_keepvault_expected_root_inode=0;
static bool g_keepvault_has_expected_root_device=false;
static bool g_keepvault_has_expected_root_inode=false;
#ifdef BSD
#include <sys/sysctl.h>
#endif

#else  // Assume Windows
#include <windows.h>
#include <io.h>
#endif

// For testing -Dunix in Windows
#ifdef unixtest
#define lstat(a,b) stat(a,b)
#define mkdir(a,b) mkdir(a)
#ifndef fseeko
#define fseeko(a,b,c) fseeko64(a,b,c)
#endif
#ifndef ftello
#define ftello(a) ftello64(a)
#endif
#endif

using std::string;
using std::vector;
using std::map;
using std::min;
using std::max;
using libzpaq::StringBuffer;

// Handle errors in libzpaq and elsewhere
void libzpaq::error(const char* msg) {
  if (strstr(msg, "ut of memory")) throw std::bad_alloc();
  throw std::runtime_error(msg);
}
using libzpaq::error;

// Portable thread types and functions for Windows and Linux. Use like this:
//
// // Create mutex for locking thread-unsafe code
// Mutex mutex;            // shared by all threads
// init_mutex(mutex);      // initialize in unlocked state
// Semaphore sem(n);       // n >= 0 is initial state
//
// // Declare a thread function
// ThreadReturn thread(void *arg) {  // arg points to in/out parameters
//   lock(mutex);          // wait if another thread has it first
//   release(mutex);       // allow another waiting thread to continue
//   sem.wait();           // wait until n>0, then --n
//   sem.signal();         // ++n to allow waiting threads to continue
//   return 0;             // must return 0 to exit thread
// }
//
// // Start a thread
// ThreadID tid;
// run(tid, thread, &arg); // runs in parallel
// join(tid);              // wait for thread to return
// destroy_mutex(mutex);   // deallocate resources used by mutex
// sem.destroy();          // deallocate resources used by semaphore

#ifdef PTHREAD
#include <pthread.h>
typedef void* ThreadReturn;                                // job return type
typedef pthread_t ThreadID;                                // job ID type
static std::atomic<int> g_keepvault_test_pthread_create_error(0);
static std::atomic<int> g_keepvault_test_pthread_join_error(0);

static void keepvault_fatal_thread_error(const char* operation, int code) {
  fprintf(stderr, "zpaq fatal: %s failed: %s (%d)\n",
      operation, strerror(code), code);
  fflush(stderr);
  _Exit(2);
}

void run(ThreadID& tid, ThreadReturn(*f)(void*), void* arg) {// start job
  int injected=g_keepvault_test_pthread_create_error.exchange(0);
  const int result=injected ? injected : pthread_create(&tid, NULL, f, arg);
  // A partially started pool cannot be unwound through the legacy queue
  // safely because existing workers may already be blocked on its semaphores.
  // Terminate the child process immediately rather than hanging or allowing
  // those workers to outlive their job object.
  if (result) keepvault_fatal_thread_error("pthread_create", result);
}
void join(ThreadID tid) {                                  // wait for job
  int result=pthread_join(tid, NULL);
  const int injected=g_keepvault_test_pthread_join_error.exchange(0);
  if (!result && injected) result=injected;
  if (result) keepvault_fatal_thread_error("pthread_join", result);
}
typedef pthread_mutex_t Mutex;                             // mutex type
void init_mutex(Mutex& m) {pthread_mutex_init(&m, 0);}     // init mutex
void lock(Mutex& m) {pthread_mutex_lock(&m);}              // wait for mutex
void release(Mutex& m) {pthread_mutex_unlock(&m);}         // release mutex
void destroy_mutex(Mutex& m) {pthread_mutex_destroy(&m);}  // destroy mutex

class Semaphore {
public:
  Semaphore() {sem=-1;}
  void init(int n) {
    assert(n>=0);
    assert(sem==-1);
    int r=pthread_cond_init(&cv, 0);
    if (r) keepvault_fatal_thread_error("pthread_cond_init", r);
    r=pthread_mutex_init(&mutex, 0);
    if (r) keepvault_fatal_thread_error("pthread_mutex_init", r);
    sem=n;
  }
  void destroy() {
    assert(sem>=0);
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cv);
  }
  int wait() {
    assert(sem>=0);
    int r=pthread_mutex_lock(&mutex);
    if (r) keepvault_fatal_thread_error("pthread_mutex_lock", r);
    // POSIX permits spurious condition-variable wakeups. Consuming a token
    // after one would underflow the semaphore and can deadlock the pipeline.
    while (sem==0 && r==0) r=pthread_cond_wait(&cv, &mutex);
    if (r) {
      pthread_mutex_unlock(&mutex);
      keepvault_fatal_thread_error("pthread_cond_wait", r);
    }
    --sem;
    r=pthread_mutex_unlock(&mutex);
    if (r) keepvault_fatal_thread_error("pthread_mutex_unlock", r);
    return 0;
  }
  void signal() {
    assert(sem>=0);
    int r=pthread_mutex_lock(&mutex);
    if (r) keepvault_fatal_thread_error("pthread_mutex_lock", r);
    ++sem;
    r=pthread_cond_signal(&cv);
    if (r) keepvault_fatal_thread_error("pthread_cond_signal", r);
    r=pthread_mutex_unlock(&mutex);
    if (r) keepvault_fatal_thread_error("pthread_mutex_unlock", r);
  }
  void test_spurious_signal_without_token() {
    int r=pthread_mutex_lock(&mutex);
    if (r) keepvault_fatal_thread_error("pthread_mutex_lock", r);
    r=pthread_cond_signal(&cv);
    if (r) keepvault_fatal_thread_error("pthread_cond_signal", r);
    r=pthread_mutex_unlock(&mutex);
    if (r) keepvault_fatal_thread_error("pthread_mutex_unlock", r);
  }
private:
  pthread_cond_t cv;  // to signal FINISHED
  pthread_mutex_t mutex; // protects cv
  int sem;  // semaphore count
};

struct KeepVaultSemaphoreSelfTestState {
  Semaphore semaphore;
  std::atomic<bool> completed;
  KeepVaultSemaphoreSelfTestState(): completed(false) {}
};

static ThreadReturn keepvault_semaphore_self_test_waiter(void* argument) {
  KeepVaultSemaphoreSelfTestState& state=
      *static_cast<KeepVaultSemaphoreSelfTestState*>(argument);
  state.semaphore.wait();
  state.completed.store(true);
  return 0;
}

static ThreadReturn keepvault_thread_self_test_noop(void*) { return 0; }

static int keepvault_semaphore_spurious_wakeup_self_test() {
  KeepVaultSemaphoreSelfTestState state;
  state.semaphore.init(0);
  ThreadID waiter;
  run(waiter, keepvault_semaphore_self_test_waiter, &state);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  state.semaphore.test_spurious_signal_without_token();
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  if (state.completed.load()) {
    fprintf(stderr, "spurious semaphore wakeup consumed a nonexistent token\n");
    _Exit(2);
  }
  state.semaphore.signal();
  join(waiter);
  if (!state.completed.load()) {
    fprintf(stderr, "semaphore waiter did not consume a real token\n");
    _Exit(2);
  }
  state.semaphore.destroy();
  fprintf(stderr, "semaphore_spurious_wakeup=blocked\n");
  return 0;
}

#else  // Windows
typedef DWORD ThreadReturn;
typedef HANDLE ThreadID;
void run(ThreadID& tid, ThreadReturn(*f)(void*), void* arg) {
  tid=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)f, arg, 0, NULL);
  if (tid==NULL) error("CreateThread failed");
}
void join(ThreadID& tid) {
  if (tid==NULL) throw std::runtime_error("invalid thread handle");
  const DWORD wait_result=WaitForSingleObject(tid, INFINITE);
  const BOOL close_result=CloseHandle(tid);
  tid=NULL;
  if (wait_result!=WAIT_OBJECT_0 || !close_result)
    error("thread join failed");
}
typedef HANDLE Mutex;
void init_mutex(Mutex& m) {m=CreateMutex(NULL, FALSE, NULL);}
void lock(Mutex& m) {WaitForSingleObject(m, INFINITE);}
void release(Mutex& m) {ReleaseMutex(m);}
void destroy_mutex(Mutex& m) {CloseHandle(m);}

class Semaphore {
public:
  enum {MAXCOUNT=2000000000};
  Semaphore(): h(NULL) {}
  void init(int n) {assert(!h); h=CreateSemaphore(NULL, n, MAXCOUNT, NULL);}
  void destroy() {assert(h); CloseHandle(h);}
  int wait() {assert(h); return WaitForSingleObject(h, INFINITE);}
  void signal() {assert(h); ReleaseSemaphore(h, 1, NULL);}
private:
  HANDLE h;  // Windows semaphore
};

#endif

// Global variables
int64_t global_start=0;  // set to mtime() at start of main()

// In Windows, convert 16-bit wide string to UTF-8 and \ to /
#ifndef unix
string wtou(const wchar_t* s) {
  assert(sizeof(wchar_t)==2);  // Not true in Linux
  assert((wchar_t)(-1)==65535);
  string r;
  if (!s) return r;
  for (; *s; ++s) {
    if (*s=='\\') r+='/';
    else if (*s<128) r+=*s;
    else if (*s<2048) r+=192+*s/64, r+=128+*s%64;
    else r+=224+*s/4096, r+=128+*s/64%64, r+=128+*s%64;
  }
  return r;
}

// In Windows, convert UTF-8 string to wide string ignoring
// invalid UTF-8 or >64K. Convert "/" to slash (default "\").
std::wstring utow(const char* ss, char slash='\\') {
  assert(sizeof(wchar_t)==2);
  assert((wchar_t)(-1)==65535);
  std::wstring r;
  if (!ss) return r;
  const unsigned char* s=(const unsigned char*)ss;
  for (; s && *s; ++s) {
    if (s[0]=='/') r+=slash;
    else if (s[0]<128) r+=s[0];
    else if (s[0]>=192 && s[0]<224 && s[1]>=128 && s[1]<192)
      r+=(s[0]-192)*64+s[1]-128, ++s;
    else if (s[0]>=224 && s[0]<240 && s[1]>=128 && s[1]<192
             && s[2]>=128 && s[2]<192)
      r+=(s[0]-224)*4096+(s[1]-128)*64+s[2]-128, s+=2;
  }
  return r;
}
#endif

// Print a UTF-8 string to f (stdout, stderr) so it displays properly
void printUTF8(const char* s, FILE* f=stdout) {
  assert(f);
  assert(s);
  if (g_pipe_archive && f==stdout) f=stderr;
#ifdef unix
  fprintf(f, "%s", s);
#else
  const HANDLE h=(HANDLE)_get_osfhandle(_fileno(f));
  DWORD ft=GetFileType(h);
  if (ft==FILE_TYPE_CHAR) {
    fflush(f);
    std::wstring w=utow(s, '/');  // Windows console: convert to UTF-16
    DWORD n=0;
    WriteConsole(h, w.c_str(), w.size(), &n, 0);
  }
  else  // stdout redirected to file
    fprintf(f, "%s", s);
#endif
}

// Return relative time in milliseconds
int64_t mtime() {
#ifdef unix
  timeval tv;
  gettimeofday(&tv, 0);
  return tv.tv_sec*1000LL+tv.tv_usec/1000;
#else
  return int64_t(GetTickCount64());
#endif
}

// Convert 64 bit decimal YYYYMMDDHHMMSS to "YYYY-MM-DD HH:MM:SS"
// where -1 = unknown date, 0 = deleted.
string dateToString(int64_t date) {
  if (date<=0) return "                   ";
  string s="0000-00-00 00:00:00";
  static const int t[]={18,17,15,14,12,11,9,8,6,5,3,2,1,0};
  for (int i=0; i<14; ++i) s[t[i]]+=int(date%10), date/=10;
  return s;
}

// Convert attributes to a readable format
string attrToString(int64_t attrib) {
  string r="     ";
  if ((attrib&255)=='u') {
    r[0]="0pc3d5b7 9lBsDEF"[(attrib>>20)&15];
    for (int i=0; i<4; ++i)
      r[4-i]=(attrib>>(8+3*i))%8+'0';
  }
  else if ((attrib&255)=='w') {
    for (int i=0, j=0; i<32; ++i) {
      if ((attrib>>(i+8))&1) {
        char c="RHS DAdFTprCoIEivs89012345678901"[i];
        if (j<5) r[j]=c;
        else r+=c;
        ++j;
      }
    }
  }
  return r;
}

// Convert seconds since 0000 1/1/1970 to 64 bit decimal YYYYMMDDHHMMSS
// Valid from 1970 to 2099.
int64_t decimal_time(time_t tt) {
  if (tt==-1) tt=0;
  int64_t t=(sizeof(tt)==4) ? unsigned(tt) : tt;
  const int second=t%60;
  const int minute=t/60%60;
  const int hour=t/3600%24;
  t/=86400;  // days since Jan 1 1970
  const int term=t/1461;  // 4 year terms since 1970
  t%=1461;
  t+=(t>=59);  // insert Feb 29 on non leap years
  t+=(t>=425);
  t+=(t>=1157);
  const int year=term*4+t/366+1970;  // actual year
  t%=366;
  t+=(t>=60)*2;  // make Feb. 31 days
  t+=(t>=123);   // insert Apr 31
  t+=(t>=185);   // insert June 31
  t+=(t>=278);   // insert Sept 31
  t+=(t>=340);   // insert Nov 31
  const int month=t/31+1;
  const int day=t%31+1;
  return year*10000000000LL+month*100000000+day*1000000
         +hour*10000+minute*100+second;
}

// Convert decimal date to time_t - inverse of decimal_time()
time_t unix_time(int64_t date) {
  if (date<=0) return -1;
  static const int days[12]={0,31,59,90,120,151,181,212,243,273,304,334};
  const int year=date/10000000000LL%10000;
  const int month=(date/100000000%100-1)%12;
  const int day=date/1000000%100;
  const int hour=date/10000%100;
  const int min=date/100%100;
  const int sec=date%100;
  return (day-1+days[month]+(year%4==0 && month>1)+((year-1970)*1461+1)/4)
    *86400+hour*3600+min*60+sec;
}

/////////////////////////////// File //////////////////////////////////

// Windows/Linux compatible file type
#ifdef unix
typedef FILE* FP;
const FP FPNULL=NULL;
const char* const RB="rb";
const char* const WB="wb";
const char* const RBPLUS="rb+";
const char* const WBPLUS="wb+";

#else // Windows
typedef HANDLE FP;
const FP FPNULL=INVALID_HANDLE_VALUE;
typedef enum {RB, WB, RBPLUS, WBPLUS} MODE;  // fopen modes

// Open file. Only modes "rb", "wb", "rb+" and "wb+" are supported.
FP fopen(const char* filename, MODE mode) {
  assert(filename);
  DWORD access=0;
  if (mode!=WB) access=GENERIC_READ;
  if (mode!=RB) access|=GENERIC_WRITE;
  const DWORD disp=(mode==WB || mode==WBPLUS) ? CREATE_ALWAYS : OPEN_EXISTING;
  DWORD share=FILE_SHARE_READ;
  return CreateFile(utow(filename).c_str(), access, share,
                    NULL, disp, FILE_ATTRIBUTE_NORMAL, NULL);
}

// Close file
int fclose(FP fp) {
  return CloseHandle(fp) ? 0 : EOF;
}

// Read nobj objects of size size into ptr. Return number of objects read.
size_t fread(void* ptr, size_t size, size_t nobj, FP fp) {
  if (!ptr || fp==FPNULL || size==0 || nobj==0 || nobj>SIZE_MAX/size)
    return 0;
  const size_t total=size*nobj;
  size_t completed=0;
  unsigned char* out=(unsigned char*)ptr;
  while (completed<total) {
    const size_t remaining=total-completed;
    const DWORD chunk=remaining>MAXDWORD ? MAXDWORD : DWORD(remaining);
    DWORD transferred=0;
    if (!ReadFile(fp, out+completed, chunk, &transferred, NULL)) break;
    completed+=transferred;
    if (transferred<chunk) break;
  }
  return completed/size;
}

// Write nobj objects of size size from ptr to fp. Return number written.
size_t fwrite(const void* ptr, size_t size, size_t nobj, FP fp) {
  if (!ptr || fp==FPNULL || size==0 || nobj==0 || nobj>SIZE_MAX/size)
    return 0;
  const size_t total=size*nobj;
  size_t completed=0;
  const unsigned char* in=(const unsigned char*)ptr;
  while (completed<total) {
    const size_t remaining=total-completed;
    const DWORD chunk=remaining>MAXDWORD ? MAXDWORD : DWORD(remaining);
    DWORD transferred=0;
    if (!WriteFile(fp, in+completed, chunk, &transferred, NULL)) break;
    completed+=transferred;
    if (transferred<chunk) break;
  }
  return completed/size;
}

// Move file pointer by offset. origin is SEEK_SET (from start), SEEK_CUR,
// (from current position), or SEEK_END (from end).
int fseeko(FP fp, int64_t offset, int origin) {
  if (origin==SEEK_SET) origin=FILE_BEGIN;
  else if (origin==SEEK_CUR) origin=FILE_CURRENT;
  else if (origin==SEEK_END) origin=FILE_END;
  else return -1;
  LARGE_INTEGER distance;
  distance.QuadPart=offset;
  return SetFilePointerEx(fp, distance, NULL, origin) ? 0 : -1;
}

// Get file position
int64_t ftello(FP fp) {
  LARGE_INTEGER distance;
  LARGE_INTEGER position;
  distance.QuadPart=0;
  if (!SetFilePointerEx(fp, distance, &position, FILE_CURRENT))
    error("file position query failed");
  return position.QuadPart;
}

#endif

static size_t keepvault_read_creation_input(
    void* buffer, size_t size, FP input) {
  if (g_keepvault_test_creation_read_error.exchange(0)) {
    errno=EIO;
    error("creation input read failed");
  }
  const size_t count=fread(buffer, 1, size, input);
#ifdef unix
  if (count==0 && ferror(input)) error("creation input read failed");
#endif
  return count;
}

static int keepvault_checked_fclose(FP file) {
  const int actual=fclose(file);
  return g_keepvault_test_close_error.exchange(0) || actual!=0 ? EOF : 0;
}

// Return true if a file or directory (UTF-8 without trailing /) exists.
bool exists(string filename) {
  if (g_pipe_archive && filename=="-") return false;
  int len=filename.size();
  if (len<1) return false;
  if (filename[len-1]=='/') filename=filename.substr(0, len-1);
#ifdef unix
  struct stat sb;
  return !lstat(filename.c_str(), &sb);
#else
  return GetFileAttributes(utow(filename.c_str()).c_str())
         !=INVALID_FILE_ATTRIBUTES;
#endif
}

// Delete a file, return true if successful
bool delete_file(const char* filename) {
#ifdef unix
  return remove(filename)==0;
#else
  return DeleteFile(utow(filename).c_str());
#endif
}

#ifdef unix

// Print last error message
void printerr(const char* filename) {
  perror(filename);
}

#else

// Print last error message
void printerr(const char* filename) {
  fflush(stdout);
  int err=GetLastError();
  printUTF8(filename, stderr);
  if (err==ERROR_FILE_NOT_FOUND)
    fprintf(stderr, ": file not found\n");
  else if (err==ERROR_PATH_NOT_FOUND)
    fprintf(stderr, ": path not found\n");
  else if (err==ERROR_ACCESS_DENIED)
    fprintf(stderr, ": access denied\n");
  else if (err==ERROR_SHARING_VIOLATION)
    fprintf(stderr, ": sharing violation\n");
  else if (err==ERROR_BAD_PATHNAME)
    fprintf(stderr, ": bad pathname\n");
  else if (err==ERROR_INVALID_NAME)
    fprintf(stderr, ": invalid name\n");
  else if (err==ERROR_NETNAME_DELETED)
    fprintf(stderr, ": network name no longer available\n");
  else
    fprintf(stderr, ": Windows error %d\n", err);
}

#endif

// Close fp if open. Set date and attributes unless 0
void close(const char* filename, int64_t date, int64_t attr, FP fp=FPNULL) {
  assert(filename);
#ifdef unix
  if (fp!=FPNULL && keepvault_checked_fclose(fp)!=0)
    error("output close or flush failed");
  if (date>0) {
    struct utimbuf ub;
    ub.actime=time(NULL);
    ub.modtime=unix_time(date);
    utime(filename, &ub);
  }
  if ((attr&255)=='u')
    chmod(filename, attr>>8);
#else
  const bool ads=strstr(filename, ":$DATA")!=0;  // alternate data stream?
  if (date>0 && !ads) {
    if (fp==FPNULL)
      fp=CreateFile(utow(filename).c_str(),
                    FILE_WRITE_ATTRIBUTES,
                    FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fp!=FPNULL) {
      SYSTEMTIME st;
      st.wYear=date/10000000000LL%10000;
      st.wMonth=date/100000000%100;
      st.wDayOfWeek=0;  // ignored
      st.wDay=date/1000000%100;
      st.wHour=date/10000%100;
      st.wMinute=date/100%100;
      st.wSecond=date%100;
      st.wMilliseconds=0;
      FILETIME ft;
      SystemTimeToFileTime(&st, &ft);
      SetFileTime(fp, NULL, NULL, &ft);
    }
  }
  if (fp!=FPNULL) CloseHandle(fp);
  if ((attr&255)=='w' && !ads)
    SetFileAttributes(utow(filename).c_str(), attr>>8);
#endif
}

// Print file open error and throw exception
void ioerr(const char* msg) {
  printerr(msg);
  throw std::runtime_error(msg);
}

// Create directories as needed. For example if path="/tmp/foo/bar"
// then create directories /, /tmp, and /tmp/foo unless they exist.
// Set date and attributes if not 0.
void makepath(string path, int64_t date=0, int64_t attr=0) {
  for (unsigned i=0; i<path.size(); ++i) {
    if (path[i]=='\\' || path[i]=='/') {
      path[i]=0;
#ifdef unix
      mkdir(path.c_str(), 0777);
#else
      CreateDirectory(utow(path.c_str()).c_str(), 0);
#endif
      path[i]='/';
    }
  }

  // Set date and attributes
  string filename=path;
  if (filename!="" && filename[filename.size()-1]=='/')
    filename=filename.substr(0, filename.size()-1);  // remove trailing slash
  close(filename.c_str(), date, attr);
}

#ifndef unix

// Truncate filename to length. Return -1 if error, else 0.
int truncate(const char* filename, int64_t length) {
  std::wstring w=utow(filename);
  HANDLE out=CreateFile(w.c_str(), GENERIC_READ | GENERIC_WRITE,
                        0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (out!=INVALID_HANDLE_VALUE) {
    LARGE_INTEGER position;
    position.QuadPart=length;
    const bool truncated=SetFilePointerEx(out, position, NULL, FILE_BEGIN)
                         && SetEndOfFile(out);
    const bool closed=CloseHandle(out)!=FALSE;
    if (truncated && closed) return 0;
  }
  return -1;
}
#endif

/////////////////////////////// Archive ///////////////////////////////

// Convert non-negative decimal number x to string of at least n digits
string itos(int64_t x, int n=1) {
  assert(x>=0);
  assert(n>=0);
  string r;
  for (; x || n>0; x/=10, --n) r=string(1, '0'+x%10)+r;
  return r;
}

// Replace * and ? in fn with part or digits of part
string subpart(string fn, int part) {
  for (int j=fn.size()-1; j>=0; --j) {
    if (fn[j]=='?')
      fn[j]='0'+part%10, part/=10;
    else if (fn[j]=='*')
      fn=fn.substr(0, j)+itos(part)+fn.substr(j+1), part=0;
  }
  return fn;
}

// Base of InputArchive and OutputArchive
class ArchiveBase {
protected:
  libzpaq::AES_CTR* aes;  // NULL if not encrypted
  FP fp;          // currently open file or FPNULL
  bool stdio;     // true for archive "-" pipe mode
#ifdef unix
  bool bound_descriptor;  // read-only anonymous regular archive supplied on stdin
#endif
public:
  ArchiveBase(): aes(0), fp(FPNULL), stdio(false)
#ifdef unix
      , bound_descriptor(false)
#endif
      {}
  ~ArchiveBase() {
    if (aes) delete aes;
    if (fp!=FPNULL && !stdio) fclose(fp);
  }  
  bool isopen() {
    return fp!=FPNULL || stdio
#ifdef unix
        || bound_descriptor
#endif
        ;
  }
};

// An InputArchive supports encrypted reading
class InputArchive: public ArchiveBase, public libzpaq::Reader {
  vector<int64_t> sz;  // part sizes
  int64_t off;  // current offset
  string fn;  // filename, possibly multi-part with wildcards
public:

  // Open filename. If password then decrypt input.
  InputArchive(const char* filename, const char* password=0);

  // Read and return 1 byte or -1 (EOF)
  int get() {
    error("get() not implemented");
    return -1;
  }

  // Read up to len bytes into obuf at current offset. Return 0..len bytes
  // actually read. 0 indicates EOF.
  int read(char* obuf, int len) {
#ifdef unix
    if (bound_descriptor) {
      if (len<=0 || off>=g_verified_archive_size) return 0;
      if (off<0 || g_verified_archive_fd<0)
        error("verified archive descriptor identity is invalid");
      const size_t count=size_t(min<int64_t>(int64_t(len),
          g_verified_archive_size-off));
      size_t completed=0;
      while (completed<count) {
        const ssize_t result=pread(g_verified_archive_fd, obuf+completed,
            count-completed, off_t(off+int64_t(completed)));
        if (result<0 && errno==EINTR) continue;
        if (result<=0) error("cannot read bound verified archive staging object");
        completed+=size_t(result);
      }
      off+=int64_t(completed);
      return int(completed);
    }
#endif
    if (stdio) {
      const int nr=fread(obuf, 1, len, fp);
      if (nr>0) off+=nr;
      return nr;
    }
    int nr=fread(obuf, 1, len, fp);
    if (nr==0) {
      seek(0, SEEK_CUR);
      nr=fread(obuf, 1, len, fp);
    }
    if (nr==0) return 0;
    if (aes) aes->encrypt(obuf, nr, off);
    off+=nr;
    return nr;
  }

  // Like fseeko()
  void seek(int64_t p, int whence);

  // Like ftello()
  int64_t tell() {
    return off;
  }
};

// Like fseeko. If p is out of range then close file.
void InputArchive::seek(int64_t p, int whence) {
  if (!isopen()) return;

#ifdef unix
  if (bound_descriptor) {
    int64_t base=0;
    if (whence==SEEK_SET) base=0;
    else if (whence==SEEK_CUR) base=off;
    else if (whence==SEEK_END) base=g_verified_archive_size;
    else error("invalid verified archive seek");
    if ((p>0 && base>INT64_MAX-p) || (p<0 && base<INT64_MIN-p))
      error("verified archive seek overflow");
    const int64_t target=base+p;
    if (target<0 || target>g_verified_archive_size)
      error("verified archive seek is out of range");
    off=target;
    return;
  }
#endif

  if (stdio) {
    if (whence!=SEEK_CUR || p!=0)
      error("cannot seek on archive input pipe");
    return;
  }

  // Compute new offset
  if (whence==SEEK_SET) off=p;
  else if (whence==SEEK_CUR) off+=p;
  else if (whence==SEEK_END) {
    off=p;
    for (unsigned i=0; i<sz.size(); ++i) off+=sz[i];
  }

  // Optimization for single file to avoid close and reopen
  if (sz.size()==1) {
    fseeko(fp, off, SEEK_SET);
    return;
  }

  // Seek across multiple files
  assert(sz.size()>1);
  int64_t sum=0;
  unsigned i;
  for (i=0;; ++i) {
    sum+=sz[i];
    if (sum>off || i+1>=sz.size()) break;
  }
  const string next=subpart(fn, i+1);
  fclose(fp);
  fp=fopen(next.c_str(), RB);
  if (fp==FPNULL) ioerr(next.c_str());
  fseeko(fp, off-sum, SEEK_END);
}

// Open for input. Decrypt with password and using the salt in the
// first 32 bytes. If filename has wildcards then assume multi-part
// and read their concatenation.

InputArchive::InputArchive(const char* filename, const char* password):
    off(0), fn(filename) {
  assert(filename);

#ifdef unix
  if (g_verified_archive_stdin && !strcmp(filename, "-")) {
    if (password) error("verified stdin does not support zpaq -key");
    if (g_verified_archive_fd<0 || g_verified_archive_size<1)
      error("verified archive stdin was not staged");
    bound_descriptor=true;
    sz.push_back(g_verified_archive_size);
    return;
  }
#endif

  if (g_pipe_archive && !strcmp(filename, "-")) {
    if (password) error("archive pipe mode does not support zpaq -key");
    stdio=true;
#ifdef unix
    fp=stdin;
#else
    if (_setmode(_fileno(stdin), _O_BINARY)==-1)
      error("cannot set archive input pipe to binary mode");
    fp=GetStdHandle(STD_INPUT_HANDLE);
#endif
    return;
  }

  // Get file sizes
  const string part0=subpart(filename, 0);
  for (unsigned i=1; ; ++i) {
    const string parti=subpart(filename, i);
    if (i>1 && parti==part0) break;
    fp=fopen(parti.c_str(), RB);
    if (fp==FPNULL) break;
    fseeko(fp, 0, SEEK_END);
    sz.push_back(ftello(fp));
    fclose(fp);
  }

  // Open first part
  const string part1=subpart(filename, 1);
  fp=fopen(part1.c_str(), RB);
  if (!isopen()) ioerr(part1.c_str());
  assert(fp!=FPNULL);

  // Get encryption salt
  if (password) {
    char salt[32], key[32];
    if (fread(salt, 1, 32, fp)!=32) error("cannot read salt");
    libzpaq::stretchKey(key, password, salt);
    aes=new libzpaq::AES_CTR(key, 32, salt);
    off=32;
  }
}

// An Archive is a file supporting encryption
class OutputArchive: public ArchiveBase, public libzpaq::Writer {
  int64_t off;    // preceding multi-part bytes
  unsigned ptr;   // write pointer in buf: 0 <= ptr <= BUFSIZE
  enum {BUFSIZE=1<<16};
  vector<char> buf;  // heap-backed I/O buffer
public:

  // Open. If password then encrypt output.
  OutputArchive(const char* filename, const char* password=0,
                const char* salt_=0, int64_t off_=0);

  // Write pending output
  void flush() {
    assert(fp!=FPNULL || stdio);
    if (ptr==0) return;
    if (stdio) {
      if (aes) error("archive pipe mode does not support zpaq -key");
      if (fwrite(buf.data(), 1, ptr, fp)!=ptr)
        error("archive pipe write failed");
      off+=ptr;
      ptr=0;
      return;
    }
    if (aes) aes->encrypt(buf.data(), ptr, ftello(fp)+off);
    if (fwrite(buf.data(), 1, ptr, fp)!=ptr)
      error("archive write failed");
    ptr=0;
  }

  // Position the next read or write offset to p.
  void seek(int64_t p, int whence) {
    if (stdio) {
      const int64_t current=off+ptr;
      int64_t target=current;
      if (whence==SEEK_SET) target=p;
      else if (whence==SEEK_CUR) target=current+p;
      else if (whence==SEEK_END) target=current+p;
      if (target!=current) error("cannot seek on archive pipe");
    }
    else if (fp!=FPNULL) {
      flush();
      if (fseeko(fp, p, whence)!=0) error("archive seek failed");
    }
    else if (whence==SEEK_SET) off=p;
    else off+=p;  // assume at end
  }

  // Return current file offset.
  int64_t tell() const {
    if (stdio) return off+ptr;
    else if (fp!=FPNULL) return ftello(fp)+ptr;
    else return off;
  }

  // Write one byte
  void put(int c) {
    if (fp==FPNULL && !stdio) ++off;
    else {
      if (ptr>=buf.size()) flush();
      if (ptr>=buf.size()) error("archive output buffer overflow");
      buf.at(ptr++)=char(c);
    }
  }

  // Write buf[0..n-1]
  void write(const char* ibuf, int len) {
    if (fp==FPNULL && !stdio) off+=len;
    else while (len-->0) put(*ibuf++);
  }

  // Flush output and close
  void close() {
    if (stdio) {
      flush();
      fp=FPNULL;
      stdio=false;
    }
    else if (fp!=FPNULL) {
      flush();
      if (fclose(fp)!=0) error("archive close failed");
    }
    fp=FPNULL;
  }
};

// Create or update an existing archive or part. If filename is ""
// then keep track of position in off but do not write to disk. Otherwise
// open and encrypt with password if not 0. If the file exists then
// read the salt from the first 32 bytes and off_ must be 0. Otherwise
// encrypt assuming off_ previous bytes, of which the first 32 are salt_.
// If off_ is 0 then write salt_ to the first 32 bytes.

OutputArchive::OutputArchive(const char* filename, const char* password,
    const char* salt_, int64_t off_): off(off_), ptr(0), buf(BUFSIZE) {
  assert(filename);
  if (g_pipe_archive && !strcmp(filename, "-")) {
    if (password) error("archive pipe mode does not support zpaq -key");
    stdio=true;
#ifdef unix
    fp=stdout;
#else
    if (_setmode(_fileno(stdout), _O_BINARY)==-1)
      error("cannot set archive output pipe to binary mode");
    fp=GetStdHandle(STD_OUTPUT_HANDLE);
#endif
    return;
  }
  if (!*filename) return;

  // Open existing file
  char salt[32]={0};
  fp=fopen(filename, RBPLUS);
  if (isopen()) {
    if (off!=0) error("file exists and off > 0");
    if (password) {
      if (fread(salt, 1, 32, fp)!=32) error("cannot read salt");
      if (salt_ && memcmp(salt, salt_, 32)) error("salt mismatch");
    }
    seek(0, SEEK_END);
  }

  // Create new file
  else {
    fp=fopen(filename, WB);
    if (!isopen()) ioerr(filename);
    if (password) {
      if (!salt_) error("salt not specified");
      else memcpy(salt, salt_, 32);
      if (off==0 && fwrite(salt, 1, 32, fp)!=32) ioerr(filename);
    }
  }

  // Set up encryption
  if (password) {
    char key[32];
    libzpaq::stretchKey(key, password, salt);
    aes=new libzpaq::AES_CTR(key, 32, salt);
  }
}

///////////////////////// System info /////////////////////////////////

// Guess number of cores. In 32 bit mode, max is 2.
int numberOfProcessors() {
  int rc=0;  // result
#ifdef unix
#ifdef BSD  // BSD or Mac OS/X
  size_t rclen=sizeof(rc);
  int mib[2]={CTL_HW, HW_NCPU};
  if (sysctl(mib, 2, &rc, &rclen, 0, 0)!=0)
    perror("sysctl");

#else  // Linux
  // Count lines of the form "processor\t: %d\n" in /proc/cpuinfo
  // where %d is 0, 1, 2,..., rc-1
  FILE *in=fopen("/proc/cpuinfo", "r");
  if (!in) return 1;
  std::string s;
  int c;
  while ((c=getc(in))!=EOF) {
    if (c>='A' && c<='Z') c+='a'-'A';  // convert to lowercase
    if (c>' ') s+=c;  // remove white space
    if (c=='\n') {  // end of line?
      if (s.size()>10 && s.substr(0, 10)=="processor:") {
        c=atoi(s.c_str()+10);
        if (c==rc) ++rc;
      }
      s="";
    }
  }
  fclose(in);
#endif
#else

  // Count active processors across all Windows processor groups.
  const DWORD processor_count=GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
  if (processor_count>0 && processor_count<=INT_MAX)
    rc=int(processor_count);
#endif
  if (rc<1) rc=1;
  if (sizeof(char*)==4 && rc>2) rc=2;
  return rc;
}

////////////////////////////// misc ///////////////////////////////////

// Bounded libzpaq metadata writer. The target v12 reader supplies the
// schema-specific filename/comment limits before either string is materialized.
struct StringWriter: public libzpaq::Writer {
  string s;
  size_t limit;
  explicit StringWriter(size_t maximum=65535): limit(maximum) {
    if (maximum<1 || maximum>65535) error("invalid metadata string limit");
  }
  void put(int c) {
    if (s.size()>=limit) error("archive metadata string exceeds its v12 limit");
    s+=char(c);
  }
};

// In Windows convert upper case to lower case.
inline int tolowerW(int c) {
#ifndef unix
  if (c>='A' && c<='Z') return c-'A'+'a';
#endif
  return c;
}

#ifdef unix
// The parent chooses one cryptographically random POSIX-SHM name and binds that
// exact name into the Seatbelt profile and this parser option. Prefix grants
// are deliberately forbidden: a compromised parser must not be able to create
// durable shared-memory objects or exhaust the namespace.
static bool keepvault_valid_verified_shm_name(const char* name) {
  if (!name || strlen(name)!=30 || memcmp(name, "/kv12-", 6)!=0) return false;
  for (size_t i=6; i<30; ++i) {
    const unsigned char c=static_cast<unsigned char>(name[i]);
    if (!((c>='0' && c<='9') || (c>='a' && c<='f'))) return false;
  }
  return true;
}

static void keepvault_wipe_verified_shm_name() {
  if (!g_keepvault_verified_shm_name.empty()) {
    volatile char* wipe=&g_keepvault_verified_shm_name[0];
    for (size_t i=0; i<g_keepvault_verified_shm_name.size(); ++i) wipe[i]=0;
    g_keepvault_verified_shm_name.clear();
    g_keepvault_verified_shm_name.shrink_to_fit();
  }
}

static int keepvault_create_verified_shm(int& writer) {
  if (!keepvault_valid_verified_shm_name(g_keepvault_verified_shm_name.c_str()))
    error("missing bound verified archive staging identity");
  writer=-1;
  const char* name=g_keepvault_verified_shm_name.c_str();
  writer=shm_open(name, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
  if (writer<0) error("cannot create bound verified archive staging object");
  int reader=-1;
  struct stat writer_stat;
  struct stat reader_stat;
  const bool protected_writer=fcntl(writer, F_SETFD, FD_CLOEXEC)==0;
  const bool valid_writer=protected_writer && fstat(writer, &writer_stat)==0
      && S_ISREG(writer_stat.st_mode) && writer_stat.st_uid==geteuid()
      && (writer_stat.st_mode&0777)==0600 && writer_stat.st_nlink==1;
  if (valid_writer) reader=shm_open(name, O_RDONLY, 0);
  const bool protected_reader=reader>=0
      && fcntl(reader, F_SETFD, FD_CLOEXEC)==0;
  const bool same_object=protected_reader && fstat(reader, &reader_stat)==0
      && S_ISREG(reader_stat.st_mode) && reader_stat.st_uid==geteuid()
      && (reader_stat.st_mode&0777)==0600 && reader_stat.st_nlink==1
      && writer_stat.st_dev==reader_stat.st_dev
      && writer_stat.st_ino==reader_stat.st_ino;
  const bool unlinked=shm_unlink(name)==0;
  if (!same_object || !unlinked) {
    if (!unlinked) shm_unlink(name);
    if (reader>=0) ::close(reader);
    ::close(writer);
    writer=-1;
    error("cannot protect bound verified archive staging object");
  }
  keepvault_wipe_verified_shm_name();
  return reader;
}

static void stage_verified_archive_stdin() {
  int writer=-1;
  int reader=keepvault_create_verified_shm(writer);
  std::unique_ptr<unsigned char[]> buffer(
      new unsigned char[KEEPVAULT_VERIFIED_STAGING_WINDOW]);
  uint64_t total=0;
  try {
    while (true) {
      if (total==KEEPVAULT_MAX_VERIFIED_ARCHIVE_BYTES) {
        const int trailing=fgetc(stdin);
        if (trailing!=EOF)
          error("verified archive stdin exceeds the v12 size limit");
        if (ferror(stdin)) error("cannot read verified archive stdin");
        break;
      }
      const size_t request=size_t(min<uint64_t>(KEEPVAULT_VERIFIED_STAGING_WINDOW,
          KEEPVAULT_MAX_VERIFIED_ARCHIVE_BYTES-total));
      const size_t count=fread(buffer.get(), 1, request, stdin);
      if (count<request && ferror(stdin))
        error("cannot read verified archive stdin");
      if (count==0) break;
      const uint64_t next_size=total+uint64_t(count);
      if (next_size>uint64_t(INT64_MAX)
          || ftruncate(writer, off_t(next_size))!=0)
        error("cannot size verified archive staging object");
      size_t completed=0;
      while (completed<count) {
        const ssize_t result=pwrite(writer, buffer.get()+completed,
            count-completed, off_t(total+uint64_t(completed)));
        if (result<0 && errno==EINTR) continue;
        if (result<=0) error("cannot write verified archive staging object");
        completed+=size_t(result);
      }
      total=next_size;
      if (count<request) break;
    }
    if (total<1) error("verified archive stdin is empty");
    struct stat reader_status;
    if (fstat(reader, &reader_status)!=0 || !S_ISREG(reader_status.st_mode)
        || reader_status.st_uid!=geteuid() || reader_status.st_nlink!=0
        || uint64_t(reader_status.st_size)!=total)
      error("verified archive staging descriptor changed while in use");
    const int closing_writer=writer;
    writer=-1;
    if (::close(closing_writer)!=0)
      error("cannot close verified archive staging writer");
    if (g_verified_archive_fd>=0)
      error("verified archive staging descriptor is already installed");
    g_verified_archive_fd=reader;
    reader=-1;
    g_verified_archive_size=int64_t(total);
  }
  catch (...) {
    volatile unsigned char* wipe_buffer=buffer.get();
    for (size_t i=0; i<KEEPVAULT_VERIFIED_STAGING_WINDOW; ++i)
      wipe_buffer[i]=0;
    if (writer>=0) ftruncate(writer, 0);
    if (writer>=0) ::close(writer);
    if (reader>=0) ::close(reader);
    if (g_verified_archive_fd>=0) {
      ::close(g_verified_archive_fd);
      g_verified_archive_fd=-1;
      g_verified_archive_size=0;
    }
    throw;
  }
  volatile unsigned char* wipe_buffer=buffer.get();
  for (size_t i=0; i<KEEPVAULT_VERIFIED_STAGING_WINDOW; ++i)
    wipe_buffer[i]=0;
}
#endif

static int parse_keepvault_thread_count(const char* text) {
  errno=0;
  char* end=0;
  const long value=strtol(text, &end, 10);
  if (errno || !end || end==text || *end || value<1 || value>64)
    error("thread count must be an integer from 1 through 64");
  return int(value);
}

// Return true if strings a == b or a+"/" is a prefix of b
// or a ends in "/" and is a prefix of b.
// Match ? in a to any char in b.
// Match * in a to any string in b.
// In Windows, not case sensitive.
bool ispath(const char* a, const char* b) {
  for (; *a; ++a, ++b) {
    const int ca=tolowerW(*a);
    const int cb=tolowerW(*b);
    if (ca=='*') {
      while (true) {
        if (ispath(a+1, b)) return true;
        if (!*b) return false;
        ++b;
      }
    }
    else if (ca=='?') {
      if (*b==0) return false;
    }
    else if (ca==cb && ca=='/' && a[1]==0)
      return true;
    else if (ca!=cb)
      return false;
  }
  return *b==0 || *b=='/';
}

// Read 4 byte little-endian int and advance s
unsigned btoi(const char* &s) {
  s+=4;
  return (s[-4]&255)|((s[-3]&255)<<8)|((s[-2]&255)<<16)|((s[-1]&255)<<24);
}

// Read 8 byte little-endian int and advance s
int64_t btol(const char* &s) {
  uint64_t r=btoi(s);
  return r+(uint64_t(btoi(s))<<32);
}

/////////////////////////////// Jidac /////////////////////////////////

// A Jidac object represents an archive contents: a list of file
// fragments with hash, size, and archive offset, and a list of
// files with date, attributes, and list of fragment pointers.
// Methods add to, extract from, compare, and list the archive.

// enum for version
static const int64_t DEFAULT_VERSION=99999999999999LL; // unless -until

// fragment hash table entry
struct HT {
  unsigned char sha1[20];  // fragment hash
  int usize;      // uncompressed size, -1 if unknown, -2 if not init
  HT(const char* s=0, int u=-2) {
    if (s) memcpy(sha1, s, 20);
    else memset(sha1, 0, 20);
    usize=u;
  }
};

// filename entry
struct DT {
  int64_t date;          // decimal YYYYMMDDHHMMSS (UT) or 0 if deleted
  int64_t size;          // size or -1 if unknown
  int64_t attr;          // first 8 attribute bytes
  int64_t data;          // sort key or frags written. -1 = do not write
  vector<unsigned> ptr;  // fragment list
  DT(): date(0), size(0), attr(0), data(0) {}
};
typedef map<string, DT> DTMap;

// list of blocks to extract
struct Block {
  int64_t offset;       // location in archive
  int64_t usize;        // uncompressed size, -1 if unknown (streaming)
  int64_t bsize;        // compressed size
  vector<DTMap::iterator> files;  // list of files pointing here
  unsigned start;       // index in ht of first fragment
  unsigned size;        // number of fragments to decompress
  unsigned frags;       // number of fragments in block
  unsigned extracted;   // number of fragments decompressed OK
  enum {READY, WORKING, GOOD, BAD} state;
  Block(unsigned s, int64_t o): offset(o), usize(-1), bsize(0), start(s),
      size(0), frags(0), extracted(0), state(READY) {}
};

// Version info
struct VER {
  int64_t date;          // Date of C block, 0 if streaming
  int64_t lastdate;      // Latest date of any block
  int64_t offset;        // start of transaction C block
  int64_t data_offset;   // start of first D block
  int64_t csize;         // size of compressed data, -1 = no index
  int updates;           // file updates
  int deletes;           // file deletions
  unsigned firstFragment;// first fragment ID
  VER() {memset(this, 0, sizeof(*this));}
};

// Windows API functions not in Windows XP to be dynamically loaded
#ifndef unix
typedef HANDLE (WINAPI* FindFirstStreamW_t)
                   (LPCWSTR, STREAM_INFO_LEVELS, LPVOID, DWORD);
FindFirstStreamW_t findFirstStreamW=0;
typedef BOOL (WINAPI* FindNextStreamW_t)(HANDLE, LPVOID);
FindNextStreamW_t findNextStreamW=0;
#endif

class CompressJob;

// Do everything
class Jidac {
public:
  int doCommand(int argc, const char** argv);
  friend ThreadReturn decompressThread(void* arg);
  friend ThreadReturn testThread(void* arg);
  friend struct ExtractJob;
private:

  // Command line arguments
  char command;             // command 'a', 'x', or 'l'
  string archive;           // archive name
  vector<string> files;     // filename args
  int all;                  // -all option
  bool force;               // -force option
  int fragment;             // -fragment option
  const char* index;        // index option
  char password_string[32]; // hash of -key argument
  const char* password;     // points to password_string or NULL
  string method;            // default "1"
  bool noattributes;        // -noattributes option
  vector<string> notfiles;  // list of prefixes to exclude
  string nottype;           // -not =...
  vector<string> onlyfiles; // list of prefixes to include
  const char* repack;       // -repack output file
  char new_password_string[32]; // -repack hashed password
  const char* new_password; // points to new_password_string or NULL
  int summary;              // summary option if > 0, detailed if -1
  bool dotest;              // -test option
  int threads;              // default is number of cores
  uint64_t keepvault_max_extracted_bytes;
  uint64_t keepvault_max_single_file_bytes;
  uint64_t keepvault_max_extracted_files;
  vector<string> tofiles;   // -to option
  int64_t date;             // now as decimal YYYYMMDDHHMMSS (UT)
  int64_t version;          // version number or 14 digit date

  // Archive state
  int64_t dhsize;           // total size of D blocks according to H blocks
  int64_t dcsize;           // total size of D blocks according to C blocks
  vector<HT> ht;            // list of fragments
  DTMap dt;                 // set of files in archive
  DTMap edt;                // set of external files to add or compare
  vector<Block> block;      // list of data blocks to extract
  vector<VER> ver;          // version info

  // Commands
  int add();                // add, return 1 if error else 0
  int extract();            // extract, return 1 if error else 0
  int extract_pipe_streaming(bool list_only=false); // bounded parallel v12 pipe extraction/list
  int list();               // list, return 0
  void usage();             // help

  // Support functions
  string rename(string name);           // rename from -to
  int64_t read_archive(const char* arc, int *errors=0);  // read arc
  bool isselected(const char* filename, bool rn=false);// files, -only, -not
  void scandir(string filename);        // scan dirs to dt
  void addfile(string filename, int64_t edate, int64_t esize,
               int64_t eattr);          // add external file to dt
  void list_versions(int64_t csize);    // print ver. csize=archive size
  bool equal(DTMap::const_iterator p, const char* filename);
             // compare file contents with p
};

// Print help message
void Jidac::usage() {
  printf(
"Usage: zpaq command archive[.zpaq] files... -options...\n"
"Files... may be directory trees. Default is the whole archive.\n"
"Use * or \?\?\?\? in archive name for multi-part or \"\" for empty.\n"
"Commands:\n"
"   a  add         Append files to archive if dates have changed.\n"
"   x  extract     Extract most recent versions of files.\n"
"   l  list        List or compare external files to archive by dates.\n"
"Options:\n"
"  -all [N]        Extract/list versions in N [4] digit directories.\n"
"  -f -force       Add: append files if contents have changed.\n"
"                  Extract: overwrite existing output files.\n"
"                  List: compare file contents instead of dates.\n"
"  -index F        Extract: create index F for archive.\n"
"                  Add: create suffix for archive indexed by F, update F.\n"
"  -key X          Create or access encrypted archive with password X.\n"
"  -mN  -method N  Compress level N (0..5 = faster..better, default 1).\n"
"  -noattributes   Ignore/don't save file attributes or permissions.\n"
"  -not files...   Exclude. * and ? match any string or char.\n"
"       =[+-#^?]   List: exclude by comparison result.\n"
"  -only files...  Include only matches (default: *).\n"
"  -repack F [X]   Extract to new archive F with key X (default: none).\n"
"  -sN -summary N  List: show top N sorted by size. -1: show frag IDs.\n"
"                  Add/Extract: if N > 0 show brief progress.\n"
"  -test           Extract: verify but do not write files.\n"
"  -tN -threads N  Use N threads (default: 0 = %d cores).\n"
"  -to out...      Rename files... to out... or all to out/all.\n"
"  -until N        Roll back archive to N'th update or -N from end.\n"
"  -until %s  Set date, roll back (UT, default time: 235959).\n"
#ifndef NDEBUG
"Advanced options:\n"
"  -fragment N     Use 2^N KiB average fragment size (default: 6).\n"
"  -mNB -method NB Use 2^B MiB blocks (0..11, default: 04, 14, 26..56).\n"
"  -method {xs}B[,N2]...[{ciawmst}[N1[,N2]...]]...  Advanced:\n"
"  x=journaling (default). s=streaming (no dedupe).\n"
"    N2: 0=no pre/post. 1,2=packed,byte LZ77. 3=BWT. 4..7=0..3 with E8E9.\n"
"    N3=LZ77 min match. N4=longer match to try first (0=none). 2^N5=search\n"
"    depth. 2^N6=hash table size (N6=B+21: suffix array). N7=lookahead.\n"
"    Context modeling defaults shown below:\n"
"  c0,0,0: context model. N1: 0=ICM, 1..256=CM max count. 1000..1256 halves\n"
"    memory. N2: 1..255=offset mod N2, 1000..1255=offset from N2-1000 byte.\n"
"    N3...: order 0... context masks (0..255). 256..511=mask+byte LZ77\n"
"    parse state, >1000: gap of N3-1000 zeros.\n"
"  i: ISSE chain. N1=context order. N2...=order increment.\n"
"  a24,0,0: MATCH: N1=hash multiplier. N2=halve buffer. N3=halve hash tab.\n"
"  w1,65,26,223,20,0: Order 0..N1-1 word ISSE chain. A word is bytes\n"
"    N2..N2+N3-1 ANDed with N4, hash mulitpiler N5, memory halved by N6.\n"
"  m8,24: MIX all previous models, N1 context bits, learning rate N2.\n"
"  s8,32,255: SSE last model. N1 context bits, count range N2..N3.\n"
"  t8,24: MIX2 last 2 models, N1 context bits, learning rate N2.\n"
#endif
  , threads, dateToString(date).c_str());
  exit(1);
}

// return a/b such that there is exactly one "/" in between, and
// in Windows, any drive letter in b the : is removed and there
// is a "/" after.
string append_path(string a, string b) {
  int na=a.size();
  int nb=b.size();
#ifndef unix
  if (nb>1 && b[1]==':') {  // remove : from drive letter
    if (nb>2 && b[2]!='/') b[1]='/';
    else b=b[0]+b.substr(2), --nb;
  }
#endif
  if (nb>0 && b[0]=='/') b=b.substr(1);
  if (na>0 && a[na-1]=='/') a=a.substr(0, na-1);
  return a+"/"+b;
}

// Reject archive member names that could escape the extraction working directory
// or address Windows devices/alternate data streams. The application extracts into
// a dedicated empty directory, so dot components and ambiguous Win32 names are not
// needed for compatibility.
bool safe_archive_member_path(const string& name) {
  if (name.size()==0 || name.size()>KEEPVAULT_MAX_ARCHIVE_MEMBER_NAME_BYTES
      || name[0]=='/' || name[0]=='\\')
    return false;
  string component;
  for (unsigned i=0; i<=name.size(); ++i) {
    const char c=i<name.size() ? name[i] : '/';
    if (c=='/' || c=='\\') {
      if (component.size()==0) {
        const bool trailing_separator=i==name.size() && i>0
            && (name[i-1]=='/' || name[i-1]=='\\');
        if (!trailing_separator) return false;
      }
      else {
        if (component.size()>1020) return false;
        if (component=="." || component=="..") return false;
        if (component[component.size()-1]=='.'
            || component[component.size()-1]==' ') return false;
        string base=component;
        const unsigned dot=base.find('.');
        if (dot<base.size()) base=base.substr(0, dot);
        for (unsigned j=0; j<base.size(); ++j)
          base[j]=char(toupper((unsigned char)base[j]));
        if (base=="CON" || base=="PRN" || base=="AUX" || base=="NUL"
            || (base.size()==4 && (base.substr(0, 3)=="COM"
                                  || base.substr(0, 3)=="LPT")
                && base[3]>='1' && base[3]<='9')) return false;
      }
      component="";
    }
    else {
      if ((unsigned char)c<32) return false;
      if (c==':' || c=='<' || c=='>' || c=='"' || c=='|'
          || c=='?' || c=='*') return false;
      component+=c;
    }
  }
  return true;
}

static string keepvault_canonical_output_path(string name) {
  for (size_t i=0; i<name.size(); ++i)
    if (name[i]=='\\') name[i]='/';
  while (!name.empty() && name[name.size()-1]=='/') name.resize(name.size()-1);
  if (name.empty() || !safe_archive_member_path(name))
    error("unsafe archive member path");
  return name;
}

#ifdef unix
struct KeepVaultPathIdentity {
  dev_t device;
  ino_t inode;
  mode_t mode;
  nlink_t links;
};

static std::mutex g_keepvault_output_mutex;
static std::map<string, KeepVaultPathIdentity> g_keepvault_output_directories;
static std::map<string, KeepVaultPathIdentity> g_keepvault_output_files;

static KeepVaultPathIdentity keepvault_identity_from_stat(const struct stat& st) {
  KeepVaultPathIdentity identity={st.st_dev, st.st_ino, st.st_mode, st.st_nlink};
  return identity;
}

static int keepvault_close_owned_descriptor(int& owner) {
  if (owner<0) return 0;
  const int closing=owner;
  owner=-1;
  return ::close(closing);
}

static bool keepvault_same_object(
    const KeepVaultPathIdentity& left, const KeepVaultPathIdentity& right) {
  return left.device==right.device && left.inode==right.inode;
}

static void keepvault_require_root_identity_locked() {
  if (g_keepvault_output_root_fd<0)
    error("descriptor-bound extraction root is unavailable");
  struct stat st;
  if (fstat(g_keepvault_output_root_fd, &st)!=0 || !S_ISDIR(st.st_mode)
      || uint64_t(st.st_dev)!=g_keepvault_expected_root_device
      || uint64_t(st.st_ino)!=g_keepvault_expected_root_inode)
    error("descriptor-bound extraction root identity changed");
}

static void keepvault_initialize_output_root() {
  if (!g_keepvault_has_expected_root_device
      || !g_keepvault_has_expected_root_inode)
    error("v12 extraction requires the expected output-root device and inode");
  if (g_keepvault_output_root_fd>=0)
    error("v12 extraction root was initialized more than once");
  const int fd=open(".", O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if (fd<0) error("cannot open descriptor-bound extraction root");
  g_keepvault_output_root_fd=fd;
  try {
    std::lock_guard<std::mutex> guard(g_keepvault_output_mutex);
    keepvault_require_root_identity_locked();
    struct stat st;
    if (fstat(fd, &st)!=0) error("cannot stat descriptor-bound extraction root");
    g_keepvault_output_directories[""]=keepvault_identity_from_stat(st);

    const int scan_fd=fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (scan_fd<0) error("cannot duplicate descriptor-bound extraction root");
    DIR* directory=fdopendir(scan_fd);
    if (!directory) {
      ::close(scan_fd);
      error("cannot enumerate descriptor-bound extraction root");
    }
    bool empty=true;
    errno=0;
    for (dirent* entry=readdir(directory); entry; entry=readdir(directory)) {
      if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
        empty=false;
        break;
      }
    }
    const int scan_error=errno;
    if (closedir(directory)!=0 || scan_error)
      error("cannot finish enumerating descriptor-bound extraction root");
    if (!empty)
      error("descriptor-bound extraction root was not empty before output");
  }
  catch (...) {
    ::close(g_keepvault_output_root_fd);
    g_keepvault_output_root_fd=-1;
    g_keepvault_output_directories.clear();
    throw;
  }
}

static vector<string> keepvault_path_components(const string& canonical) {
  vector<string> components;
  size_t start=0;
  while (start<canonical.size()) {
    const size_t separator=canonical.find('/', start);
    const size_t end=separator==string::npos ? canonical.size() : separator;
    if (end==start) error("unsafe empty archive path component");
    components.push_back(canonical.substr(start, end-start));
    if (separator==string::npos) break;
    start=separator+1;
  }
  return components;
}

static int keepvault_duplicate_root_locked() {
  keepvault_require_root_identity_locked();
  const int fd=fcntl(g_keepvault_output_root_fd, F_DUPFD_CLOEXEC, 0);
  if (fd<0) error("cannot duplicate descriptor-bound extraction root");
  return fd;
}

static KeepVaultPathIdentity keepvault_require_opened_entry(
    int parent_fd, const string& component, int opened_fd, bool directory) {
  struct stat opened;
  struct stat entry;
  if (fstat(opened_fd, &opened)!=0
      || fstatat(parent_fd, component.c_str(), &entry, AT_SYMLINK_NOFOLLOW)!=0)
    error("cannot verify descriptor-bound extraction entry");
  const KeepVaultPathIdentity opened_identity=keepvault_identity_from_stat(opened);
  const KeepVaultPathIdentity entry_identity=keepvault_identity_from_stat(entry);
  if (!keepvault_same_object(opened_identity, entry_identity)
      || (directory ? !S_ISDIR(opened.st_mode) : !S_ISREG(opened.st_mode))
      || (!directory && opened.st_nlink!=1))
    error("descriptor-bound extraction entry identity is unsafe");
  return opened_identity;
}

// Returns an owned descriptor for canonical_directory, creating each missing
// component exactly once. EEXIST on a component not already bound by this
// process is rejected. This turns APFS case/normalization aliases and
// same-UID pre-creation races into failures rather than traversals.
static int keepvault_open_output_directory_locked(
    const string& canonical_directory, bool create) {
  int current=keepvault_duplicate_root_locked();
  if (canonical_directory.empty()) return current;
  const vector<string> components=keepvault_path_components(canonical_directory);
  string prefix;
  try {
    for (size_t i=0; i<components.size(); ++i) {
      if (!prefix.empty()) prefix+='/';
      prefix+=components[i];
      std::map<string, KeepVaultPathIdentity>::const_iterator expected=
          g_keepvault_output_directories.find(prefix);
      if (expected==g_keepvault_output_directories.end()) {
        if (!create
            || mkdirat(current, components[i].c_str(), S_IRWXU)!=0)
          error("output directory component was pre-existing, colliding, or could not be created");
      }
      const int child=openat(current, components[i].c_str(),
          O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
      if (child<0) error("cannot open descriptor-bound output directory component");
      KeepVaultPathIdentity actual;
      try {
        actual=keepvault_require_opened_entry(current, components[i], child, true);
      }
      catch (...) {
        ::close(child);
        throw;
      }
      if (expected!=g_keepvault_output_directories.end()
          && !keepvault_same_object(expected->second, actual)) {
        ::close(child);
        error("bound output directory component was replaced");
      }
      if (expected==g_keepvault_output_directories.end())
        g_keepvault_output_directories[prefix]=actual;
      ::close(current);
      current=child;
    }
    return current;
  }
  catch (...) {
    ::close(current);
    throw;
  }
}

static void keepvault_apply_fd_metadata(
    int fd, int64_t date, int64_t attr) {
  if (date>0) {
    struct timespec times[2];
    times[0].tv_sec=time(NULL);
    times[0].tv_nsec=0;
    times[1].tv_sec=unix_time(date);
    times[1].tv_nsec=0;
    if (futimens(fd, times)!=0)
      error("cannot set descriptor-bound output timestamp");
  }
  if ((attr&255)=='u' && fchmod(fd, mode_t(attr>>8))!=0)
    error("cannot set descriptor-bound output mode");
}

static void keepvault_secure_makepath(
    const string& path, int64_t date=0, int64_t attr=0) {
  const bool is_directory=!path.empty()
      && (path[path.size()-1]=='/' || path[path.size()-1]=='\\');
  const string canonical=keepvault_canonical_output_path(path);
  const size_t separator=canonical.rfind('/');
  const string directory=is_directory ? canonical
      : (separator==string::npos ? string() : canonical.substr(0, separator));
  std::lock_guard<std::mutex> guard(g_keepvault_output_mutex);
  int fd=keepvault_open_output_directory_locked(directory, true);
  try {
    if (is_directory) keepvault_apply_fd_metadata(fd, date, attr);
    if (keepvault_close_owned_descriptor(fd)!=0)
      error("cannot close descriptor-bound output directory");
  }
  catch (...) {
    keepvault_close_owned_descriptor(fd);
    throw;
  }
}

static FP keepvault_secure_open_output(const string& path, bool create_new) {
  const string canonical=keepvault_canonical_output_path(path);
  const size_t separator=canonical.rfind('/');
  const string parent=separator==string::npos ? string() : canonical.substr(0, separator);
  const string leaf=separator==string::npos ? canonical : canonical.substr(separator+1);
  std::lock_guard<std::mutex> guard(g_keepvault_output_mutex);
  int parent_fd=keepvault_open_output_directory_locked(parent, true);
  int fd=-1;
  try {
    std::map<string, KeepVaultPathIdentity>::const_iterator expected=
        g_keepvault_output_files.find(canonical);
    if (create_new) {
      if (expected!=g_keepvault_output_files.end())
        error("duplicate descriptor-bound output file");
      if (g_keepvault_test_output_open_error.exchange(0)) {
        errno=ENOSPC;
        error("injected descriptor-bound output open failure");
      }
      fd=openat(parent_fd, leaf.c_str(),
          O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, S_IRUSR|S_IWUSR);
    }
    else {
      if (expected==g_keepvault_output_files.end())
        error("descriptor-bound output file was not created by this process");
      fd=openat(parent_fd, leaf.c_str(), O_RDWR|O_NOFOLLOW|O_CLOEXEC);
    }
    if (fd<0) error("cannot open descriptor-bound output file");
    const KeepVaultPathIdentity actual=
        keepvault_require_opened_entry(parent_fd, leaf, fd, false);
    if (expected!=g_keepvault_output_files.end()
        && !keepvault_same_object(expected->second, actual))
      error("descriptor-bound output file was replaced");
    if (create_new) g_keepvault_output_files[canonical]=actual;
    if (keepvault_close_owned_descriptor(parent_fd)!=0)
      error("cannot close descriptor-bound output parent");
    FP result=fdopen(fd, create_new ? "wb" : "rb+");
    if (!result) error("cannot attach a stream to descriptor-bound output file");
    fd=-1;
    return result;
  }
  catch (...) {
    keepvault_close_owned_descriptor(fd);
    keepvault_close_owned_descriptor(parent_fd);
    throw;
  }
}

static void keepvault_secure_close(
    const string& path, int64_t date, int64_t attr, FP fp=FPNULL) {
  const bool is_directory=!path.empty()
      && (path[path.size()-1]=='/' || path[path.size()-1]=='\\');
  const string canonical=keepvault_canonical_output_path(path);
  std::lock_guard<std::mutex> guard(g_keepvault_output_mutex);
  int fd=fp==FPNULL ? -1 : fileno(fp);
  bool close_descriptor=false;
  if (fd<0) {
    if (is_directory) {
      fd=keepvault_open_output_directory_locked(canonical, false);
      close_descriptor=true;
    }
    else {
      const size_t separator=canonical.rfind('/');
      const string parent=separator==string::npos ? string() : canonical.substr(0, separator);
      const string leaf=separator==string::npos ? canonical : canonical.substr(separator+1);
      int parent_fd=keepvault_open_output_directory_locked(parent, false);
      try {
        fd=openat(parent_fd, leaf.c_str(), O_RDWR|O_NOFOLLOW|O_CLOEXEC);
        if (fd<0)
          error("cannot reopen descriptor-bound output file for metadata");
        const KeepVaultPathIdentity actual=
            keepvault_require_opened_entry(parent_fd, leaf, fd, false);
        if (keepvault_close_owned_descriptor(parent_fd)!=0)
          error("cannot close descriptor-bound output parent");
        const std::map<string, KeepVaultPathIdentity>::const_iterator expected=
            g_keepvault_output_files.find(canonical);
        if (expected==g_keepvault_output_files.end()
            || !keepvault_same_object(expected->second, actual))
          error("descriptor-bound output file changed before metadata update");
      }
      catch (...) {
        keepvault_close_owned_descriptor(parent_fd);
        keepvault_close_owned_descriptor(fd);
        throw;
      }
      close_descriptor=true;
    }
  }
  try {
    struct stat st;
    if (fstat(fd, &st)!=0
        || (!is_directory && (!S_ISREG(st.st_mode) || st.st_nlink!=1)))
      error("descriptor-bound output changed before close");
    keepvault_apply_fd_metadata(fd, date, attr);
    if (fp!=FPNULL) {
      const int close_result=keepvault_checked_fclose(fp);
      fp=FPNULL;
      if (close_result!=0) error("cannot close descriptor-bound output stream");
    }
    else if (close_descriptor && ::close(fd)!=0) {
      close_descriptor=false;
      error("cannot close descriptor-bound output descriptor");
    }
    else {
      close_descriptor=false;
    }
  }
  catch (...) {
    if (fp!=FPNULL) fclose(fp);
    else if (close_descriptor) ::close(fd);
    throw;
  }
}

// Transfer stream ownership before closing it. fclose() consumes the FILE even
// when flushing reports an error, so a caller must never retain a stale FILE*
// that an outer cleanup handler could close a second time.
static void keepvault_secure_close_owned(
    const string& path, int64_t date, int64_t attr, FP& owner) {
  if (owner==FPNULL) return;
  FP closing=owner;
  owner=FPNULL;
  keepvault_secure_close(path, date, attr, closing);
}

static string keepvault_collision_component(const string& component) {
#if defined(__APPLE__) && defined(__MACH__)
  CFStringRef source=CFStringCreateWithBytes(kCFAllocatorDefault,
      reinterpret_cast<const UInt8*>(component.data()), CFIndex(component.size()),
      kCFStringEncodingUTF8, false);
  if (!source) error("archive path component is not valid UTF-8");
  CFMutableStringRef folded=CFStringCreateMutableCopy(kCFAllocatorDefault, 0, source);
  CFRelease(source);
  if (!folded) error("cannot normalize archive path component");
  CFStringNormalize(folded, kCFStringNormalizationFormD);
  CFStringLowercase(folded, NULL);
  const CFIndex characters=CFStringGetLength(folded);
  const CFIndex maximum=CFStringGetMaximumSizeForEncoding(
      characters, kCFStringEncodingUTF8);
  if (maximum<0) {
    CFRelease(folded);
    error("normalized archive path component is too large");
  }
  vector<UInt8> bytes(size_t(maximum)+1u);
  CFIndex used=0;
  const CFIndex converted=CFStringGetBytes(folded,
      CFRangeMake(0, characters), kCFStringEncodingUTF8, 0, false,
      bytes.empty() ? NULL : &bytes[0], maximum, &used);
  CFRelease(folded);
  if (converted!=characters || used<0)
    error("cannot encode normalized archive path component");
  return string(reinterpret_cast<const char*>(&bytes[0]), size_t(used));
#else
  string folded=component;
  for (size_t i=0; i<folded.size(); ++i)
    if (folded[i]>='A' && folded[i]<='Z') folded[i]+='a'-'A';
  return folded;
#endif
}

static string keepvault_collision_key(const string& path) {
  const string canonical=keepvault_canonical_output_path(path);
  const vector<string> components=keepvault_path_components(canonical);
  string key;
  for (size_t i=0; i<components.size(); ++i) {
    if (i) key+='/';
    key+=keepvault_collision_component(components[i]);
  }
  return key;
}
#endif

// Reserve the member and every parent directory that makepath() may create.
// The set is the authoritative inode-count budget, not merely the number of
// explicit archive records.
static void keepvault_reserve_output_entries(const string& name,
    std::map<string, string>& entries, uint64_t limit) {
  const string canonical=keepvault_canonical_output_path(name);
  vector<std::pair<string, string> > additions;
  for (size_t end=0; end<=canonical.size(); ++end) {
    if (end<canonical.size() && canonical[end]!='/') continue;
    const string prefix=canonical.substr(0, end);
    if (prefix.empty()) error("unsafe empty archive path component");
#ifdef unix
    const string collision_key=keepvault_collision_key(prefix);
#else
    const string collision_key=prefix;
#endif
    const std::map<string, string>::const_iterator existing=entries.find(collision_key);
    if (existing==entries.end())
      additions.push_back(std::make_pair(collision_key, prefix));
    else if (existing->second!=prefix)
      error("archive contains a case- or Unicode-normalization-colliding output path");
  }
  if (uint64_t(entries.size())>limit
      || uint64_t(additions.size())>limit-uint64_t(entries.size()))
    error("archive exceeds the extracted-entry limit");
  for (size_t i=0; i<additions.size(); ++i)
    entries.insert(additions[i]);
}

#ifdef unix
static int keepvault_root_identity_mismatch_self_test() {
  struct stat st;
  if (stat(".", &st)!=0) error("cannot stat root-identity self-test directory");
  g_keepvault_expected_root_device=uint64_t(st.st_dev);
  g_keepvault_expected_root_inode=uint64_t(st.st_ino)+1u;
  g_keepvault_has_expected_root_device=true;
  g_keepvault_has_expected_root_inode=true;
  try {
    keepvault_initialize_output_root();
  }
  catch (const std::exception&) {
    fprintf(stderr, "output_root_identity_mismatch=rejected\n");
    return 0;
  }
  error("output-root identity mismatch was accepted");
  return 2;
}

static int keepvault_secure_output_self_test() {
  struct stat st;
  if (stat(".", &st)!=0) error("cannot stat secure-output self-test directory");
  g_keepvault_expected_root_device=uint64_t(st.st_dev);
  g_keepvault_expected_root_inode=uint64_t(st.st_ino);
  g_keepvault_has_expected_root_device=true;
  g_keepvault_has_expected_root_inode=true;
  keepvault_initialize_output_root();

  g_keepvault_test_output_open_error.store(1);
  bool open_failure_rejected=false;
  try {
    FP unavailable=keepvault_secure_open_output("must-not-exist", true);
    keepvault_secure_close("must-not-exist", 0, 0, unavailable);
  }
  catch (const std::exception&) {
    open_failure_rejected=true;
  }
  struct stat absent;
  if (!open_failure_rejected
      || fstatat(g_keepvault_output_root_fd, "must-not-exist", &absent,
          AT_SYMLINK_NOFOLLOW)==0
      || errno!=ENOENT)
    error("descriptor-bound output-open failure was not fail-closed");

  std::map<string, string> entries;
  keepvault_reserve_output_entries("A", entries, 32);
  bool case_collision=false;
  try {
    keepvault_reserve_output_entries("a", entries, 32);
  }
  catch (const std::exception&) {
    case_collision=true;
  }
  if (!case_collision) error("case-normalizing output collision was accepted");

  entries.clear();
  const string nfc("\xC3\xA9.txt", 6);
  const string nfd("e\xCC\x81.txt", 7);
  keepvault_reserve_output_entries(nfc, entries, 32);
  bool unicode_collision=false;
  try {
    keepvault_reserve_output_entries(nfd, entries, 32);
  }
  catch (const std::exception&) {
    unicode_collision=true;
  }
  if (!unicode_collision)
    error("Unicode-normalizing output collision was accepted");

  FP first=keepvault_secure_open_output("Case", true);
  const char sentinel='X';
  if (fwrite(&sentinel, 1, 1, first)!=1)
    error("cannot write secure-output self-test sentinel");
  keepvault_secure_close("Case", 0, 0, first);
  bool exclusive_collision=false;
  try {
    FP conflicting=keepvault_secure_open_output("case", true);
    keepvault_secure_close("case", 0, 0, conflicting);
  }
  catch (const std::exception&) {
    exclusive_collision=true;
  }
  if (!exclusive_collision)
    error("filesystem-normalizing exclusive output collision was accepted");

  FP close_fault=keepvault_secure_open_output("close-fault", true);
  if (fwrite(&sentinel, 1, 1, close_fault)!=1)
    error("cannot write close-ownership self-test sentinel");
  g_keepvault_test_close_error.store(EIO);
  bool close_failure_rejected=false;
  try {
    keepvault_secure_close_owned("close-fault", 0, 0, close_fault);
  }
  catch (const std::exception&) {
    close_failure_rejected=true;
  }
  if (!close_failure_rejected || close_fault!=FPNULL)
    error("failed secure close retained stale caller ownership");
  FP foreign=tmpfile();
  if (foreign==FPNULL
      || fwrite(&sentinel, 1, 1, foreign)!=1
      || fflush(foreign)!=0
      || fcntl(fileno(foreign), F_GETFD)<0)
    error("secure close failure damaged an unrelated stream");
  if (fclose(foreign)!=0)
    error("cannot close unrelated close-ownership self-test stream");

  keepvault_secure_makepath("bound/file");
  if (renameat(g_keepvault_output_root_fd, "bound",
          g_keepvault_output_root_fd, "outside")!=0
      || symlinkat("outside", g_keepvault_output_root_fd, "bound")!=0)
    error("cannot construct secure-output symlink substitution self-test");
  bool symlink_rejected=false;
  try {
    FP escaped=keepvault_secure_open_output("bound/escape", true);
    keepvault_secure_close("bound/escape", 0, 0, escaped);
  }
  catch (const std::exception&) {
    symlink_rejected=true;
  }
  struct stat escaped;
  if (!symlink_rejected
      || fstatat(g_keepvault_output_root_fd, "outside/escape", &escaped,
          AT_SYMLINK_NOFOLLOW)==0
      || errno!=ENOENT)
    error("descriptor-relative output followed a substituted symlink");

  fprintf(stderr,
      "output_root_descriptor_binding=verified\n"
      "output_case_collision=rejected\n"
      "output_unicode_collision=rejected\n"
      "output_open_failure=fail_closed\n"
      "output_close_ownership=preserved\n"
      "output_symlink_substitution=rejected\n");
  return 0;
}
#endif

// Rename name using tofiles[]
string Jidac::rename(string name) {
  if (command=='x' && !safe_archive_member_path(name))
    error("unsafe archive member path");
  if (files.size()==0 && tofiles.size()>0)  // append prefix tofiles[0]
    name=append_path(tofiles[0], name);
  else {  // replace prefix files[i] with tofiles[i]
    const int n=name.size();
    for (unsigned i=0; i<files.size() && i<tofiles.size(); ++i) {
      const int fn=files[i].size();
      if (fn<=n && files[i]==name.substr(0, fn))
        return tofiles[i]+name.substr(fn);
    }
  }
  return name;
}

// Parse the command line. Return 1 if error else 0.
int Jidac::doCommand(int argc, const char** argv) {

  // Initialize options to default values
  command=0;
  force=false;
  fragment=6;
  all=0;
  password=0;  // no password
  index=0;
  method="";  // 0..5
  noattributes=false;
  repack=0;
  new_password=0;
  summary=0; // detailed: -1
  dotest=false;  // -test
  threads=0; // 0 = auto-detect
  keepvault_max_extracted_bytes=KEEPVAULT_MAX_EXTRACTED_BYTES;
  keepvault_max_single_file_bytes=KEEPVAULT_MAX_SINGLE_FILE_BYTES;
  keepvault_max_extracted_files=KEEPVAULT_MAX_EXTRACTED_FILES;
  bool keepvault_explicit_file_list=false;
  version=DEFAULT_VERSION;
  date=0;

  for (int i=1; i<argc; ++i) {
    if (!strcmp(argv[i], "--pipe")) {
      g_pipe_archive=true;
#ifdef _WIN32
      if (_setmode(_fileno(stdin), _O_BINARY)==-1
          || _setmode(_fileno(stdout), _O_BINARY)==-1)
        error("cannot set standard streams to binary mode");
#endif
      continue;
    }
    if (!strcmp(argv[i], "--verified-stdin"))
      g_verified_archive_stdin=true;
  }

  if (g_pipe_archive && g_verified_archive_stdin)
    error("--pipe and --verified-stdin are mutually exclusive");

  printf("zpaq v" ZPAQ_VERSION " journaling archiver, compiled "
         __DATE__ "\n");

  // Init archive state
  ht.resize(1);  // element 0 not used
  ver.resize(1); // version 0
  dhsize=dcsize=0;

  // Get date
  time_t now=time(NULL);
  tm utc_time;
#ifdef _WIN32
  if (gmtime_s(&utc_time, &now)!=0) error("cannot determine UTC time");
#else
  if (!gmtime_r(&now, &utc_time)) error("cannot determine UTC time");
#endif
  const tm* t=&utc_time;
  date=(t->tm_year+1900)*10000000000LL+(t->tm_mon+1)*100000000LL
      +t->tm_mday*1000000+t->tm_hour*10000+t->tm_min*100+t->tm_sec;

  // Get optional options
  for (int i=1; i<argc; ++i) {
    const string opt=argv[i];  // read command
    if ((opt=="add" || opt=="extract" || opt=="list" || opt=="convert"
         || opt=="a" || opt=="x" || opt=="l" || opt=="c")
        && i<argc-1 && (argv[i+1][0]!='-' || !strcmp(argv[i+1], "-")) && command==0) {
      command=opt[0];
      if (opt=="extract") command='x';
      archive=argv[++i];  // append ".zpaq" to archive if no extension
      const char* slash=strrchr(argv[i], '/');
      const char* dot=strrchr(slash ? slash : argv[i], '.');
      if (!dot && archive!="" && archive!="-") archive+=".zpaq";
      while (++i<argc && argv[i][0]!='-')  // read filename args
        files.push_back(argv[i]);
      --i;
    }
    else if (opt=="--pipe" || opt=="--verified-stdin") {}
    else if (opt=="--") {
      if (command!='a' || keepvault_explicit_file_list || files.size())
        error("invalid explicit v12 archive file list");
      keepvault_explicit_file_list=true;
      while (++i<argc) files.push_back(argv[i]);
      break;
    }
    else if (opt=="-kv-shm-name" && i<argc-1) {
#ifdef unix
      if (!g_keepvault_verified_shm_name.empty()
          || !keepvault_valid_verified_shm_name(argv[i+1]))
        error("invalid bound verified archive staging identity");
      const char* supplied_name=argv[++i];
      g_keepvault_verified_shm_name=supplied_name;
      const size_t supplied_name_size=strlen(supplied_name);
      volatile char* wipe=const_cast<char*>(supplied_name);
      for (size_t j=0; j<supplied_name_size; ++j) wipe[j]=0;
#else
      error("bound verified archive staging is available only on POSIX");
#endif
    }
    else if (opt.size()<2 || opt[0]!='-') usage();
    else if (opt=="-all") {
      all=4;
      if (i<argc-1 && isdigit(argv[i+1][0])) all=atoi(argv[++i]);
    }
    else if (opt=="-force" || opt=="-f") force=true;
    else if (opt=="-fragment" && i<argc-1) fragment=atoi(argv[++i]);
    else if (opt=="-index" && i<argc-1) index=argv[++i];
    else if (opt=="-key" && i<argc-1) {
      libzpaq::SHA256 sha256;
      for (const char* p=argv[++i]; *p; ++p) sha256.put(*p);
      memcpy(password_string, sha256.result(), 32);
      password=password_string;
    }
    else if (opt=="-method" && i<argc-1) method=argv[++i];
    else if (opt[1]=='m') method=argv[i]+2;
    else if (opt=="-noattributes") noattributes=true;
    else if (opt=="-not") {  // read notfiles
      while (++i<argc && argv[i][0]!='-') {
        if (argv[i][0]=='=') nottype=argv[i];
        else notfiles.push_back(argv[i]);
      }
      --i;
    }
    else if (opt=="-only") {  // read onlyfiles
      while (++i<argc && argv[i][0]!='-')
        onlyfiles.push_back(argv[i]);
      --i;
    }
    else if (opt=="-repack" && i<argc-1) {
      repack=argv[++i];
      if (i<argc-1 && argv[i+1][0]!='-') {
        libzpaq::SHA256 sha256;
        for (const char* p=argv[++i]; *p; ++p) sha256.put(*p);
        memcpy(new_password_string, sha256.result(), 32);
        new_password=new_password_string;
      }
    }
    else if (opt=="-summary" && i<argc-1) summary=atoi(argv[++i]);
    else if (opt[1]=='s') summary=atoi(argv[i]+2);
    else if (opt=="-test") dotest=true;
    else if (opt=="-to") {  // read tofiles
      while (++i<argc && argv[i][0]!='-')
        tofiles.push_back(argv[i]);
      if (tofiles.size()==0) tofiles.push_back("");
      --i;
    }
    else if (opt=="-threads" && i<argc-1)
      threads=parse_keepvault_thread_count(argv[++i]);
    else if (opt[1]=='t') threads=parse_keepvault_thread_count(argv[i]+2);
    else if (opt=="-kv-max-total" && i<argc-1) {
      errno=0;
      char* end=0;
      const unsigned long long value=strtoull(argv[++i], &end, 10);
      if (errno || !end || *end || value<1 || value>KEEPVAULT_MAX_EXTRACTED_BYTES)
        error("invalid v12 total extraction limit");
      keepvault_max_extracted_bytes=uint64_t(value);
    }
    else if (opt=="-kv-max-file" && i<argc-1) {
      errno=0;
      char* end=0;
      const unsigned long long value=strtoull(argv[++i], &end, 10);
      if (errno || !end || *end || value<1 || value>KEEPVAULT_MAX_SINGLE_FILE_BYTES)
        error("invalid v12 single-file extraction limit");
      keepvault_max_single_file_bytes=uint64_t(value);
    }
    else if (opt=="-kv-max-files" && i<argc-1) {
      errno=0;
      char* end=0;
      const unsigned long long value=strtoull(argv[++i], &end, 10);
      if (errno || !end || *end || value<1 || value>KEEPVAULT_MAX_EXTRACTED_FILES)
        error("invalid v12 extracted-file limit");
      keepvault_max_extracted_files=uint64_t(value);
    }
    else if (opt=="-kv-root-dev" && i<argc-1) {
#ifdef unix
      errno=0;
      char* end=0;
      const unsigned long long value=strtoull(argv[++i], &end, 10);
      if (errno || !end || end==argv[i] || *end
          || g_keepvault_has_expected_root_device)
        error("invalid v12 output-root device identity");
      g_keepvault_expected_root_device=uint64_t(value);
      g_keepvault_has_expected_root_device=true;
#else
      error("v12 output-root identity is available only on POSIX");
#endif
    }
    else if (opt=="-kv-root-ino" && i<argc-1) {
#ifdef unix
      errno=0;
      char* end=0;
      const unsigned long long value=strtoull(argv[++i], &end, 10);
      if (errno || !end || end==argv[i] || *end
          || g_keepvault_has_expected_root_inode)
        error("invalid v12 output-root inode identity");
      g_keepvault_expected_root_inode=uint64_t(value);
      g_keepvault_has_expected_root_inode=true;
#else
      error("v12 output-root identity is available only on POSIX");
#endif
    }
    else if (opt=="-until" && i+1<argc) {  // read date

      // Read digits from multiple args and fill in leading zeros
      version=0;
      int digits=0;
      if (argv[i+1][0]=='-') {  // negative version
        version=atol(argv[i+1]);
        if (version>-1) usage();
        ++i;
      }
      else {  // positive version or date
        while (++i<argc && argv[i][0]!='-') {
          for (int j=0; ; ++j) {
            if (isdigit(argv[i][j])) {
              version=version*10+argv[i][j]-'0';
              ++digits;
            }
            else {
              if (digits==1) version=version/10*100+version%10;
              digits=0;
              if (argv[i][j]==0) break;
            }
          }
        }
        --i;
      }

      // Append default time
      if (version>=19000000LL     && version<=29991231LL)
        version=version*100+23;
      if (version>=1900000000LL   && version<=2999123123LL)
        version=version*100+59;
      if (version>=190000000000LL && version<=299912312359LL)
        version=version*100+59;
      if (version>9999999) {
        if (version<19000101000000LL || version>29991231235959LL) {
          fflush(stdout);
          fprintf(stderr,
            "Version date %1.0f must be 19000101000000 to 29991231235959\n",
             double(version));
          exit(1);
        }
        date=version;
      }
    }
    else {
      printf("Unknown option ignored: %s\n", argv[i]);
      usage();
    }
  }

  // Set threads
  if (threads<1) threads=numberOfProcessors();
  if (threads>64) threads=64;

  // Test date
  if (now==-1 || date<19000000000000LL || date>30000000000000LL)
    error("date is incorrect, use -until YYYY-MM-DD HH:MM:SS to set");

#ifdef unix
  if (command=='x' && (g_pipe_archive || g_verified_archive_stdin)) {
    keepvault_initialize_output_root();
  }
  else if (g_keepvault_has_expected_root_device
      || g_keepvault_has_expected_root_inode) {
    error("v12 output-root identity is accepted only for extraction");
  }
#endif

  if (g_verified_archive_stdin) {
#ifdef unix
    if ((command!='x' && command!='l') || archive!="-" || password || repack
        || index || files.size() || tofiles.size() || onlyfiles.size()
        || notfiles.size() || all || force || dotest || method!=""
        || !keepvault_valid_verified_shm_name(
            g_keepvault_verified_shm_name.c_str()))
      error("--verified-stdin accepts only an unfiltered extract or list of archive -");
    stage_verified_archive_stdin();
#else
    error("--verified-stdin is available only in the macOS v12 native build");
#endif
  }
#ifdef unix
  else if (!g_keepvault_verified_shm_name.empty()) {
    error("bound verified archive staging is accepted only with --verified-stdin");
  }
#endif

  // Adjust negative version
  if (version<0) {
    Jidac jidac(*this);
    jidac.version=DEFAULT_VERSION;
    jidac.read_archive(archive.c_str());
    version+=jidac.ver.size()-1;
    printf("Version %1.0f\n", version+.0);
  }

  // Load dynamic functions in Windows Vista and later
#ifndef unix
  HMODULE h=GetModuleHandle(TEXT("kernel32.dll"));
  if (h==NULL) printerr("GetModuleHandle");
  else {
    findFirstStreamW=
      (FindFirstStreamW_t)GetProcAddress(h, "FindFirstStreamW");
    findNextStreamW=
      (FindNextStreamW_t)GetProcAddress(h, "FindNextStreamW");
  }
  if (!findFirstStreamW || !findNextStreamW)
    printf("Alternate streams not supported in Windows XP.\n");
#endif

  // Execute command
  if (command=='a' && files.size()>0) return add();
  else if (command=='x') return extract();
  else if (command=='l') list();
  else usage();
  return 0;
}

/////////////////////////// read_archive //////////////////////////////

// Read arc up to -date into ht, dt, ver. Return place to
// append. If errors is not NULL then set it to number of errors found.
int64_t Jidac::read_archive(const char* arc, int *errors) {
  if (errors) *errors=0;
  dcsize=dhsize=0;
  assert(ver.size()==1);
  unsigned files=0;  // count

  // Open archive
  InputArchive in(arc, password);
  if (!in.isopen()) {
    if (command!='a') {
      fflush(stdout);
      printUTF8(arc, stderr);
      fprintf(stderr, " not found.\n");
      if (errors) ++*errors;
    }
    return 0;
  }
  printUTF8(arc);
  if (version==DEFAULT_VERSION) printf(": ");
  else printf(" -until %1.0f: ", version+0.0);
  fflush(stdout);

  // Test password. A one-way pipe cannot rewind these probe bytes, and pipe
  // mode deliberately does not support zpaq's own password layer.
  if (!(g_pipe_archive && !strcmp(arc, "-"))) {
    char s[4]={0};
    const int nr=in.read(s, 4);
    if (nr>0 && memcmp(s, "7kSt", 4) && (memcmp(s, "zPQ", 3) || s[3]<1))
      error("password incorrect");
    in.seek(-nr, SEEK_CUR);
  }

  // Scan archive contents
  string lastfile=archive; // last named file in streaming format
  if (lastfile.size()>5 && lastfile.substr(lastfile.size()-5)==".zpaq")
    lastfile=lastfile.substr(0, lastfile.size()-5); // drop .zpaq
  int64_t block_offset=32*(password!=0);  // start of last block of any type
  int64_t data_offset=block_offset;    // start of last block of d fragments
  bool found_data=false;   // exit if nothing found
  bool first=true;         // first segment in archive?
  StringBuffer os(32832);  // decompressed block
  const bool renamed=command=='l' || command=='a';

  // Detect archive format and read the filenames, fragment sizes,
  // and hashes. In JIDAC format, these are in the index blocks, allowing
  // data to be skipped. Otherwise the whole archive is scanned to get
  // this information from the segment headers and trailers.
  bool done=false;
  while (!done) {
    std::unique_ptr<libzpaq::Decompresser> d(new libzpaq::Decompresser());
    try {
      d->setInput(&in);
      double mem=0;
      while (d->findBlock(&mem)) {
        found_data=true;

        // Read the segments in the current block
        StringWriter filename(KEEPVAULT_MAX_ARCHIVE_MEMBER_NAME_BYTES);
        StringWriter comment(KEEPVAULT_MAX_ARCHIVE_COMMENT_BYTES);
        int segs=0;  // segments in block
        bool skip=false;  // skip decompression?
        while (d->findFilename(&filename)) {
          if (filename.s.size()) {
            for (unsigned i=0; i<filename.s.size(); ++i)
              if (filename.s[i]=='\\') filename.s[i]='/';
            lastfile=filename.s.c_str();
          }
          comment.s="";
          d->readComment(&comment);

          // Test for JIDAC format. Filename is jDC<fdate>[cdhi]<num>
          // and comment ends with " jDC\x01". Skip d (data) blocks.
          if (comment.s.size()>=4
              && comment.s.substr(comment.s.size()-4)=="jDC\x01") {
            if (filename.s.size()!=28 || filename.s.substr(0, 3)!="jDC")
              error("bad journaling block name");
            if (skip) error("mixed journaling and streaming block");

            // Read uncompressed size from comment
            int64_t usize=0;
            unsigned i;
            for (i=0; i<comment.s.size() && isdigit(comment.s[i]); ++i) {
              usize=usize*10+comment.s[i]-'0';
              if (usize>0xffffffff) error("journaling block too big");
            }
            if (strchr("chi", filename.s[17])
                && uint64_t(usize)>MAX_INDEX_BLOCK_BYTES)
              error("journaling index block exceeds safety limit");

            // Read the date and number in the filename
            int64_t fdate=0, num=0;
            for (i=3; i<17 && isdigit(filename.s[i]); ++i)
              fdate=fdate*10+filename.s[i]-'0';
            if (i!=17 || fdate<19000000000000LL || fdate>=30000000000000LL)
              error("bad date");
            for (i=18; i<28 && isdigit(filename.s[i]); ++i)
              num=num*10+filename.s[i]-'0';
            if (i!=28 || num>0xffffffff) error("bad fragment");

            // Decompress the block.
            os.secureClear();
            os.setLimit(usize);
            d->setOutput(&os);
            libzpaq::SHA1 sha1;
            d->setSHA1(&sha1);
            if (strchr("chi", filename.s[17])) {
              if (!(mem>=0 && mem<=KEEPVAULT_REGULAR_MAX_MODEL_MEMORY))
                error("index block requires too much model memory");
              d->decompress();
              char sha1result[21]={0};
              d->readSegmentEnd(sha1result);
              if ((int64_t)os.size()!=usize) error("bad block size");
              if (usize!=int64_t(sha1.usize())) error("bad checksum size");
              if (sha1result[0]!=1)
                error("journaling index block has no checksum");
              if (memcmp(sha1result+1, sha1.result(), 20))
                error("bad checksum");
            }
            else
              d->readSegmentEnd();

            // Transaction header (type c).
            // If in the future then stop here, else read 8 byte data size
            // from input and jump over it.
            if (filename.s[17]=='c') {
              if (os.size()<8) error("c block too small");
              data_offset=in.tell()+1-d->buffered();
              const char* s=os.c_str();
              int64_t jmp=btol(s);
              if (jmp<0) printf("Incomplete transaction ignored\n");
              if (jmp<0
                  || (version<19000000000000LL && int64_t(ver.size())>version)
                  || (version>=19000000000000LL && version<fdate)) {
                done=true;  // roll back to here
                goto endblock;
              }
              else {
                dcsize+=jmp;
                if (jmp) in.seek(data_offset+jmp, SEEK_SET);
                ver.push_back(VER());
                ver.back().firstFragment=ht.size();
                ver.back().offset=block_offset;
                ver.back().data_offset=data_offset;
                ver.back().date=ver.back().lastdate=fdate;
                ver.back().csize=jmp;
                if (all) {
                  string fn=itos(ver.size()-1, all)+"/";
                  if (renamed) fn=rename(fn);
                  if (isselected(fn.c_str(), false))
                    dt[fn].date=fdate;
                }
                if (jmp) goto endblock;
              }
            }

            // Fragment table (type h).
            // Contents is bsize[4] (sha1[20] usize[4])... for fragment N...
            // where bsize is the compressed block size.
            // Store in ht[].{sha1,usize}. Set ht[].csize to block offset
            // assuming N in ascending order.
            else if (filename.s[17]=='h') {
              if (ver.size()==0) error("fragment table without transaction");
              if (fdate>ver.back().lastdate) ver.back().lastdate=fdate;
              if (os.size()%24!=4) error("bad h block size");
              const unsigned n=(os.size()-4)/24;
              if (num<1 || uint64_t(num)+n>MAX_ARCHIVE_FRAGMENTS)
                error("bad h fragment");
              if (block.size()>0 && num<=block.back().start)
                error("unordered fragment table");
              const char* s=os.c_str();
              const unsigned bsize=btoi(s);
              if (data_offset>INT64_MAX-bsize)
                error("fragment data offset overflow");
              dhsize+=bsize;
              if (int64_t(ht.size())>num) error("overlapping fragment table");
              for (unsigned i=0; i<n; ++i) {
                if (i==0) {
                  block.push_back(Block(num, data_offset));
                  block.back().usize=8;
                  block.back().bsize=bsize;
                  block.back().frags=os.size()/24;
                }
                while (int64_t(ht.size())<=num+i) ht.push_back(HT());
                memcpy(ht[num+i].sha1, s, 20);
                s+=20;
                if (block.size()==0) error("missing fragment block");
                unsigned f=btoi(s);
                if (f>0x7fffffff) error("fragment too big");
                block.back().usize+=(ht[num+i].usize=f)+4u;
              }
              data_offset+=bsize;
            }

            // Index (type i)
            // Contents is: 0[8] filename 0 (deletion)
            // or:       date[8] filename 0 na[4] attr[na] ni[4] ptr[ni][4]
            // Read into DT
            else if (filename.s[17]=='i') {
              if (ver.size()==0) error("index without transaction");
              if (fdate>ver.back().lastdate) ver.back().lastdate=fdate;
              const char* s=os.c_str();
              const char* const end=s+os.size();
              while (s+9<=end) {
                DT dtr;
                dtr.date=btol(s);  // date
                if (dtr.date) ++ver.back().updates;
                else ++ver.back().deletes;
                const char* const name_end=
                    static_cast<const char*>(memchr(s, 0, size_t(end-s)));
                if (!name_end) error("unterminated filename");
                const size_t len=size_t(name_end-s);
                if (len>65535) error("filename too long");
                string fn(s, len);  // filename renamed
                if (all) fn=append_path(itos(ver.size()-1, all), fn);
                const bool issel=isselected(fn.c_str(), renamed);
                s=name_end+1;  // skip filename
                if (s>end) error("filename too long");
                if (dtr.date) {
                  ++files;
                  if (s+4>end) error("missing attr");
                  unsigned na=btoi(s);  // attr bytes
                  if (s+na>end || na>65535) error("attr too long");
                  for (unsigned i=0; i<na; ++i, ++s)  // read attr
                    if (i<8) dtr.attr+=int64_t(*s&255)<<(i*8);
                  if (noattributes) dtr.attr=0;
                  if (s+4>end) error("missing ptr");
                  unsigned ni=btoi(s);  // ptr list size
                  if (ni>(end-s)/4u || ni>MAX_ARCHIVE_FRAGMENTS)
                    error("ptr list too long");
                  if (issel) dtr.ptr.resize(ni);
                  for (unsigned i=0; i<ni; ++i) {  // read ptr
                    const unsigned j=btoi(s);
                    if (issel) dtr.ptr[i]=j;
                  }
                }
                if (issel) dt[fn]=dtr;
              }  // end while more files
            }  // end if 'i'
            else {
              printf("Skipping %s %s\n",
                  filename.s.c_str(), comment.s.c_str());
              error("Unexpected journaling block");
            }
          }  // end if journaling

          // Streaming format
          else {

            // If previous version does not exist, start a new one
            if (ver.size()==1) {
              if (version<1) {
                done=true;
                goto endblock;
              }
              ver.push_back(VER());
              ver.back().firstFragment=ht.size();
              ver.back().offset=block_offset;
              ver.back().csize=-1;
            }

            char sha1result[21]={0};
            d->readSegmentEnd(sha1result);
            if (sha1result[0]!=1)
              error("streaming archive segment has no checksum");
            skip=true;
            string fn=lastfile;
            if (all) fn=append_path(itos(ver.size()-1, all), fn);
            if (isselected(fn.c_str(), renamed)) {
              DT& dtr=dt[fn];
              if (filename.s.size()>0 || first) {
                ++files;
                dtr.date=date;
                dtr.attr=0;
                dtr.ptr.resize(0);
                ++ver.back().updates;
              }
              dtr.ptr.push_back(ht.size());
            }
            assert(ver.size()>0);
            if (segs==0 || block.size()==0)
              block.push_back(Block(ht.size(), block_offset));
            assert(block.size()>0);
            ht.push_back(HT(sha1result+1, -1));
          }  // end else streaming
          ++segs;
          filename.s="";
          first=false;
        }  // end while findFilename
        if (!done) block_offset=in.tell()-d->buffered();
      }  // end while findBlock
      done=true;
    }  // end try
    catch (std::exception&) {
      // Keep Vault v12 never salvages around a malformed block. KPAR2 is the
      // only recovery layer; parser resynchronization could otherwise turn a
      // truncated or injected prefix into a seemingly successful listing.
      throw;
    }
endblock:;
  }  // end while !done
  if (in.tell()>32*(password!=0) && !found_data)
    error("archive contains no data");
  printf("%d versions, %u files, %u fragments, %1.6f MB\n", 
      int(ver.size()-1), files, unsigned(ht.size())-1,
      block_offset/1000000.0);

  // Calculate file sizes
  for (DTMap::iterator p=dt.begin(); p!=dt.end(); ++p) {
    for (unsigned i=0; i<p->second.ptr.size(); ++i) {
      unsigned j=p->second.ptr[i];
      if (j>0 && j<ht.size() && p->second.size>=0) {
        if (ht[j].usize>=0) p->second.size+=ht[j].usize;
        else p->second.size=-1;  // unknown size
      }
    }
  }
  return block_offset;
}

// Test whether filename and attributes are selected by files, -only, and -not
// If rn then test renamed filename.
bool Jidac::isselected(const char* filename, bool rn) {
  bool matched=true;
  if (files.size()>0) {
    matched=false;
    for (unsigned i=0; i<files.size() && !matched; ++i) {
      if (rn && i<tofiles.size()) {
        if (ispath(tofiles[i].c_str(), filename)) matched=true;
      }
      else if (ispath(files[i].c_str(), filename)) matched=true;
    }
  }
  if (!matched) return false;
  if (onlyfiles.size()>0) {
    matched=false;
    for (unsigned i=0; i<onlyfiles.size() && !matched; ++i)
      if (ispath(onlyfiles[i].c_str(), filename))
        matched=true;
  }
  if (!matched) return false;
  for (unsigned i=0; i<notfiles.size(); ++i) {
    if (ispath(notfiles[i].c_str(), filename))
      return false;
  }
  return true;
}

// Return the part of fn up to the last slash
string path(const string& fn) {
  int n=0;
  for (int i=0; fn[i]; ++i)
    if (fn[i]=='/' || fn[i]=='\\') n=i+1;
  return fn.substr(0, n);
}

// Insert external filename (UTF-8 with "/") into dt if selected
// by files, onlyfiles, and notfiles. If filename
// is a directory then also insert its contents.
// In Windows, filename might have wildcards like "file.*" or "dir/*"
void Jidac::scandir(string filename) {

  // Don't scan diretories excluded by -not
  for (unsigned i=0; i<notfiles.size(); ++i)
    if (ispath(notfiles[i].c_str(), filename.c_str()))
      return;

#ifdef unix

  // Add regular files and directories
  while (filename.size()>1 && filename[filename.size()-1]=='/')
    filename=filename.substr(0, filename.size()-1);  // remove trailing /
  struct stat sb;
  if (!lstat(filename.c_str(), &sb)) {
    if (S_ISREG(sb.st_mode))
      addfile(filename, decimal_time(sb.st_mtime), sb.st_size,
              'u'+(sb.st_mode<<8));

    // Traverse directory
    if (S_ISDIR(sb.st_mode)) {
      addfile(filename=="/" ? "/" : filename+"/", decimal_time(sb.st_mtime),
              0, 'u'+(int64_t(sb.st_mode)<<8));
      DIR* dirp=opendir(filename.c_str());
      if (dirp) {
        for (dirent* dp=readdir(dirp); dp; dp=readdir(dirp)) {
          if (strcmp(".", dp->d_name) && strcmp("..", dp->d_name)) {
            string s=filename;
            if (s!="/") s+="/";
            s+=dp->d_name;
            scandir(s);
          }
        }
        closedir(dirp);
      }
      else
        perror(filename.c_str());
    }
  }
  else
    perror(filename.c_str());

#else  // Windows: expand wildcards in filename

  // Expand wildcards
  WIN32_FIND_DATA ffd;
  string t=filename;
  if (t.size()>0 && t[t.size()-1]=='/') t+="*";
  HANDLE h=FindFirstFile(utow(t.c_str()).c_str(), &ffd);
  if (h==INVALID_HANDLE_VALUE
      && GetLastError()!=ERROR_FILE_NOT_FOUND
      && GetLastError()!=ERROR_PATH_NOT_FOUND)
    printerr(t.c_str());
  while (h!=INVALID_HANDLE_VALUE) {

    // For each file, get name, date, size, attributes
    SYSTEMTIME st;
    int64_t edate=0;
    if (FileTimeToSystemTime(&ffd.ftLastWriteTime, &st))
      edate=st.wYear*10000000000LL+st.wMonth*100000000LL+st.wDay*1000000
            +st.wHour*10000+st.wMinute*100+st.wSecond;
    const int64_t esize=ffd.nFileSizeLow+(int64_t(ffd.nFileSizeHigh)<<32);
    const int64_t eattr='w'+(int64_t(ffd.dwFileAttributes)<<8);

    // Ignore links, the names "." and ".." or any unselected file
    t=wtou(ffd.cFileName);
    if (ffd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT
        || t=="." || t=="..") edate=0;  // don't add
    string fn=path(filename)+t;

    // Save directory names with a trailing / and scan their contents
    // Otherwise, save plain files
    if (edate) {
      if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) fn+="/";
      addfile(fn, edate, esize, eattr);
      if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        fn+="*";
        scandir(fn);
      }

      // NTFS alternate data streams are deliberately omitted. Extraction rejects
      // colon-bearing member names to prevent hidden ADS writes, so including them
      // here would create an archive that this hardened build cannot extract.
    }
    if (!FindNextFile(h, &ffd)) {
      if (GetLastError()!=ERROR_NO_MORE_FILES) printerr(fn.c_str());
      break;
    }
  }
  if (h!=INVALID_HANDLE_VALUE && h!=NULL) FindClose(h);
#endif
}

// Add external file and its date, size, and attributes to dt
void Jidac::addfile(string filename, int64_t edate,
                    int64_t esize, int64_t eattr) {
  if (!isselected(filename.c_str(), false)) return;
  DT& d=edt[filename];
  d.date=edate;
  d.size=esize;
  d.attr=noattributes?0:eattr;
  d.data=0;
}

//////////////////////////////// add //////////////////////////////////

// Append n bytes of x to sb in LSB order
inline void puti(libzpaq::StringBuffer& sb, uint64_t x, int n) {
  for (; n>0; --n) sb.put(x&255), x>>=8;
}

// Print percent done (td/ts) and estimated time remaining
void print_progress(int64_t ts, int64_t td, int sum) {
  if (td>ts) td=ts;
  if (td>=1000000) {
    double eta=0.001*(mtime()-global_start)*(ts-td)/(td+1.0);
    printf("%5.2f%% %d:%02d:%02d ", td*100.0/(ts+0.5),
       int(eta/3600), int(eta/60)%60, int(eta)%60);
    if (sum>0) printf("\r"), fflush(stdout);
  }
}

// A CompressJob is a queue of blocks to compress and write to the archive.
// Each block cycles through states EMPTY, FILLING, FULL, COMPRESSING,
// COMPRESSED, WRITING. The main thread waits for EMPTY buffers and
// fills them. A set of compressThreads waits for FULL threads and compresses
// them. A writeThread waits for COMPRESSED buffers at the front
// of the queue and writes and removes them.

class KeepVaultMemoryBudget {
  std::mutex mutex;
  std::condition_variable changed;
  uint64_t used;
  const uint64_t limit;
  bool stopped;
public:
  explicit KeepVaultMemoryBudget(uint64_t maximum): used(0), limit(maximum), stopped(false) {
    if (maximum<1) error("invalid native processing-memory budget");
  }
  void acquire(uint64_t amount) {
    if (amount<1 || amount>limit)
      error("native job exceeds the v12 processing-memory budget");
    std::unique_lock<std::mutex> lock(mutex);
    changed.wait(lock, [this, amount]() {
      return stopped || used<=limit-amount;
    });
    if (stopped) error("native processing-memory budget was stopped");
    used+=amount;
  }
  void release_bytes(uint64_t amount) {
    std::lock_guard<std::mutex> lock(mutex);
    if (amount>used) {
      fprintf(stderr, "native processing-memory accounting underflow\n");
      std::abort();
    }
    used-=amount;
    changed.notify_all();
  }
  void stop() {
    std::lock_guard<std::mutex> lock(mutex);
    stopped=true;
    changed.notify_all();
  }
};

class KeepVaultMemoryReservation {
  KeepVaultMemoryBudget* budget;
  uint64_t bytes;
  KeepVaultMemoryReservation(const KeepVaultMemoryReservation&);
  KeepVaultMemoryReservation& operator=(const KeepVaultMemoryReservation&);
public:
  KeepVaultMemoryReservation(): budget(0), bytes(0) {}
  KeepVaultMemoryReservation(KeepVaultMemoryBudget& owner, uint64_t amount):
      budget(0), bytes(0) {
    owner.acquire(amount);
    budget=&owner;
    bytes=amount;
  }
  ~KeepVaultMemoryReservation() {
    if (budget) budget->release_bytes(bytes);
  }
};

// Buffer queue element
struct CJ {
  enum {EMPTY, FULL, COMPRESSING, COMPRESSED, WRITING} state;
  StringBuffer in;       // uncompressed input
  StringBuffer out;      // compressed output
  string filename;       // to write in filename field
  string comment;        // if "" use default
  string method;         // compression level or "" to mark end of data
  Semaphore full;        // 1 if in is FULL of data ready to compress
  Semaphore compressed;  // 1 if out contains COMPRESSED data
  CJ(): state(EMPTY) {}
};

// Instructions to a compression job
class CompressJob {
public:
  Mutex mutex;           // protects state changes
private:
  int job;               // number of jobs
  CJ* q;                 // buffer queue
  unsigned qsize;        // number of elements in q
  int front;             // next to remove from queue
  libzpaq::Writer* out;  // archive
  Semaphore empty;       // number of empty buffers ready to fill
  Semaphore compressors; // number of compressors available to run
  KeepVaultMemoryBudget processing_memory;
public:
  friend ThreadReturn compressThread(void* arg);
  friend ThreadReturn writeThread(void* arg);
  CompressJob(int threads, int buffers, libzpaq::Writer* f):
      job(0), q(0), qsize(buffers), front(0), out(f),
      processing_memory(KEEPVAULT_NATIVE_PROCESSING_BUDGET) {
    q=new CJ[buffers];
    if (!q) throw std::bad_alloc();
    init_mutex(mutex);
    empty.init(buffers);
    compressors.init(threads);
    for (int i=0; i<buffers; ++i) {
      q[i].full.init(0);
      q[i].compressed.init(0);
    }
  }
  ~CompressJob() {
    for (int i=qsize-1; i>=0; --i) {
      q[i].compressed.destroy();
      q[i].full.destroy();
    }
    compressors.destroy();
    empty.destroy();
    destroy_mutex(mutex);
    delete[] q;
  }      
  void write(StringBuffer& s, const char* filename, string method,
             const char* comment=0);
  vector<int> csize;  // compressed block sizes
};

// Write s at the back of the queue. Signal end of input with method=""
void CompressJob::write(StringBuffer& s, const char* fn, string method,
                        const char* comment) {
  for (unsigned k=(method=="")?qsize:1; k>0; --k) {
    empty.wait();
    lock(mutex);
    unsigned i, j;
    for (i=0; i<qsize; ++i) {
      if (q[j=(i+front)%qsize].state==CJ::EMPTY) {
        q[j].filename=fn?fn:"";
        q[j].comment=comment?comment:"jDC\x01";
        q[j].method=method;
        q[j].in.resize(0);
        q[j].in.swap(s);
        q[j].state=CJ::FULL;
        q[j].full.signal();
        break;
      }
    }
    release(mutex);
    assert(i<qsize);  // queue should not be full
  }
}

// Compress data in the background, one per buffer
ThreadReturn compressThread(void* arg) {
  CompressJob& job=*(CompressJob*)arg;
  int jobNumber=0;
  try {

    // Get job number = assigned position in queue
    lock(job.mutex);
    jobNumber=job.job++;
    assert(jobNumber>=0 && jobNumber<int(job.qsize));
    CJ& cj=job.q[jobNumber];
    release(job.mutex);

    // Work until done
    while (true) {
      cj.full.wait();
      lock(job.mutex);

      // Check for end of input
      if (cj.method=="") {
        cj.compressed.signal();
        release(job.mutex);
        return 0;
      }

      // Compress
      assert(cj.state==CJ::FULL);
      cj.state=CJ::COMPRESSING;
      release(job.mutex);
      job.compressors.wait();
      {
        KeepVaultMemoryReservation memory(
            job.processing_memory, KEEPVAULT_COMPRESSION_JOB_RESERVATION);
        libzpaq::compressBlock(&cj.in, &cj.out, cj.method.c_str(),
            cj.filename.c_str(), cj.comment=="" ? 0 : cj.comment.c_str());
        cj.in.reset();
      }
      lock(job.mutex);
      cj.state=CJ::COMPRESSED;
      cj.compressed.signal();
      job.compressors.signal();
      release(job.mutex);
    }
  }
  catch (std::exception& e) {
    lock(job.mutex);
    fflush(stdout);
    fprintf(stderr, "job %d: %s\n", jobNumber+1, e.what());
    release(job.mutex);
    exit(1);
  }
  return 0;
}

static void write_keepvault_pipe_u64(libzpaq::Writer* out, uint64_t value) {
  char encoded[8];
  for (int i=0; i<8; ++i) {
    encoded[i]=char(value>>(i*8));
  }
  out->write(encoded, 8);
}

// Write compressed data to the archive in the background
ThreadReturn writeThread(void* arg) {
  CompressJob& job=*(CompressJob*)arg;
  try {

    bool pipe_header_written=false;

    // work until done
    while (true) {

      // wait for something to write
      CJ& cj=job.q[job.front];  // no other threads move front
      cj.compressed.wait();

      // Quit if end of input
      lock(job.mutex);
      if (cj.method=="") {
        if (g_pipe_archive && job.out) {
          release(job.mutex);
          if (!pipe_header_written) {
            job.out->write(KEEPVAULT_PIPE_MAGIC, sizeof(KEEPVAULT_PIPE_MAGIC));
            pipe_header_written=true;
          }
          write_keepvault_pipe_u64(job.out, 0);
          lock(job.mutex);
        }
        release(job.mutex);
        return 0;
      }

      // Write to archive
      assert(cj.state==CJ::COMPRESSED);
      cj.state=CJ::WRITING;
      job.csize.push_back(cj.out.size());
      if (job.out && cj.out.size()>0) {
        release(job.mutex);
        assert(cj.out.c_str());
        const char* p=cj.out.c_str();
        int64_t n=cj.out.size();
        if (g_pipe_archive) {
          if (uint64_t(n)>KEEPVAULT_PIPE_MAX_COMPRESSED)
            error("v12 pipe frame exceeds compressed-size limit");
          if (!pipe_header_written) {
            job.out->write(KEEPVAULT_PIPE_MAGIC, sizeof(KEEPVAULT_PIPE_MAGIC));
            pipe_header_written=true;
          }
          write_keepvault_pipe_u64(job.out, uint64_t(n));
        }
        const int64_t N=1<<30;
        while (n>N) {
          job.out->write(p, N);
          p+=N;
          n-=N;
        }
        job.out->write(p, n);
        lock(job.mutex);
      }
      cj.out.reset();
      cj.state=CJ::EMPTY;
      job.front=(job.front+1)%job.qsize;
      job.empty.signal();
      release(job.mutex);
    }
  }
  catch (std::exception& e) {
    fflush(stdout);
    fprintf(stderr, "zpaq exiting from writeThread: %s\n", e.what());
    exit(1);
  }
  return 0;
}

// Write a ZPAQ compressed JIDAC block header. Output size should not
// depend on input data.
void writeJidacHeader(libzpaq::Writer *out, int64_t date,
                      int64_t cdata, unsigned htsize) {
  if (!out) return;
  assert(date>=19000000000000LL && date<30000000000000LL);
  StringBuffer is;
  puti(is, cdata, 8);
  libzpaq::compressBlock(&is, out, "0",
      ("jDC"+itos(date, 14)+"c"+itos(htsize, 10)).c_str(), "jDC\x01");
}

// Maps sha1 -> fragment ID in ht with known size
class HTIndex {
  vector<HT>& htr;  // reference to ht
  libzpaq::Array<unsigned> t;  // sha1 prefix -> index into ht
  unsigned htsize;  // number of IDs in t

  // Compuate a hash index for sha1[20]
  unsigned hash(const char* sha1) {
    return (*(const unsigned*)sha1)&(t.size()-1);
  }

public:
  // r = ht, sz = estimated number of fragments needed
  HTIndex(vector<HT>& r, size_t sz): htr(r), t(0), htsize(1) {
    int b;
    for (b=1; sz*3>>b; ++b);
    t.resize(1, b-1);
    update();
  }

  // Find sha1 in ht. Return its index or 0 if not found.
  unsigned find(const char* sha1) {
    unsigned h=hash(sha1);
    for (unsigned i=0; i<t.size(); ++i) {
      if (t[h^i]==0) return 0;
      if (memcmp(sha1, htr[t[h^i]].sha1, 20)==0) return t[h^i];
    }
    return 0;
  }

  // Update index of ht. Do not index if fragment size is unknown.
  void update() {
    char zero[20]={0};
    while (htsize<htr.size()) {
      if (htsize>=t.size()/4*3) {
        t.resize(t.size(), 1);
        htsize=1;
      }
      if (htr[htsize].usize>=0 && memcmp(htr[htsize].sha1, zero, 20)!=0) {
        unsigned h=hash((const char*)htr[htsize].sha1);
        for (unsigned i=0; i<t.size(); ++i) {
          if (t[h^i]==0) {
            t[h^i]=htsize;
            break;
          }
        }
      }
      ++htsize;
    }
  }    
};

// Sort by sortkey, then by full path
bool compareFilename(DTMap::iterator ap, DTMap::iterator bp) {
  if (ap->second.data!=bp->second.data)
    return ap->second.data<bp->second.data;
  return ap->first<bp->first;
}

// For writing to two archives at once
struct WriterPair: public libzpaq::Writer {
  OutputArchive *a, *b;
  void put(int c) {
    if (a) a->put(c);
    if (b) b->put(c);
  }
  void write(const char* buf, int n) {
    if (a) a->write(buf, n);
    if (b) b->write(buf, n);
  }
  WriterPair(): a(0), b(0) {}
};

// Add or delete files from archive. Return 1 if error else 0.
int Jidac::add() {

  // Read archive or index into ht, dt, ver.
  int errors=0;
  const bool archive_exists=exists(subpart(archive, 1).c_str());
  string arcname=archive;  // input archive name
  if (index) arcname=index;
  int64_t header_pos=0;
  if (exists(subpart(arcname, 1).c_str()))
    header_pos=read_archive(arcname.c_str(), &errors);

  // Set arcname, offset, header_pos, and salt to open out archive
  arcname=archive;  // output file name
  int64_t offset=0;  // total size of existing parts
  char salt[32]={0};  // encryption salt
  if (password) libzpaq::random(salt, 32);

  // Remote archive
  if (index) {
    if (dcsize>0) error("index is a regular archive");
    if (version!=DEFAULT_VERSION) error("cannot truncate with an index");
    offset=header_pos+dhsize;
    header_pos=32*(password && offset==0);
    arcname=subpart(archive, ver.size());
    if (exists(arcname.c_str())) {
      printUTF8(arcname.c_str(), stderr);
      fprintf(stderr, ": archive exists\n");
      error("archive exists");
    }
    if (password) {  // derive archive salt from index
      FP fp=fopen(index, RB);
      if (fp!=FPNULL) {
        if (fread(salt, 1, 32, fp)!=32) error("cannot read salt from index");
        salt[0]^='7'^'z';
        fclose(fp);
      }
    }
  }

  // Local single or multi-part archive
  else {
    int parts=0;  // number of existing parts in multipart
    string part0=subpart(archive, 0);
    if (part0!=archive) {  // multi-part?
      for (int i=1;; ++i) {
        string partname=subpart(archive, i);
        if (partname==part0) error("too many archive parts");
        FP fp=fopen(partname.c_str(), RB);
        if (fp==FPNULL) break;
        ++parts;
        fseeko(fp, 0, SEEK_END);
        offset+=ftello(fp);
        fclose(fp);
      }
      header_pos=32*(password && parts==0);
      arcname=subpart(archive, parts+1);
      if (exists(arcname.c_str())) error("part exists");
    }

    // Get salt from first part if it exists
    if (password) {
      FP fp=fopen(subpart(archive, 1).c_str(), RB);
      if (fp==FPNULL) {
        if (header_pos>32) error("archive first part not found");
        header_pos=32;
      }
      else {
        if (fread(salt, 1, 32, fp)!=32) error("cannot read salt");
        fclose(fp);
      }
    }
  }
  if (exists(arcname.c_str())) printf("Updating ");
  else printf("Creating ");
  printUTF8(arcname.c_str());
  printf(" at offset %1.0f + %1.0f\n", double(header_pos), double(offset));

  // Set method
  if (method=="") method="1";
  if (method.size()==1) {  // set default blocksize
    if (method[0]>='2' && method[0]<='9') method+="6";
    else method+="4";
  }
  if (strchr("0123456789xs", method[0])==0)
    error("-method must begin with 0..5, x, s");
  assert(method.size()>=2);
  if (g_pipe_archive && archive=="-" && method[0]!='s')
    error("--pipe add - requires streaming method -method s...");
  if (method[0]=='s' && index) error("cannot index in streaming mode");

  // Set block and fragment sizes
  if (fragment<0) fragment=0;
  const int log_blocksize=20+atoi(method.c_str()+1);
  if (log_blocksize<20 || log_blocksize>31) error("blocksize must be 0..11");
  const unsigned blocksize=(1u<<log_blocksize)-4096;
  const unsigned MAX_FRAGMENT=fragment>19 || (8128u<<fragment)>blocksize-12
      ? blocksize-12 : 8128u<<fragment;
  const unsigned MIN_FRAGMENT=fragment>25 || (64u<<fragment)>MAX_FRAGMENT
      ? MAX_FRAGMENT : 64u<<fragment;

  // Don't mix streaming and journaling
  for (unsigned i=0; i<block.size(); ++i) {
    if (method[0]=='s') {
      if (block[i].usize>=0)
        error("cannot update journaling archive in streaming format");
    }
    else if (block[i].usize<0)
      error("cannot update streaming archive in journaling format");
  }

  // Make list of files to add or delete
  for (unsigned i=0; i<files.size(); ++i)
    scandir(files[i].c_str());

  // Sort the files to be added by filename extension and decreasing size
  vector<DTMap::iterator> vf;
  int64_t total_size=0;  // size of all input
  int64_t total_done=0;  // input deduped so far
  for (DTMap::iterator p=edt.begin(); p!=edt.end(); ++p) {
    DTMap::iterator a=dt.find(rename(p->first));
    if (a!=dt.end()) a->second.data=1;  // keep
    if (p->second.date && p->first!="" && p->first[p->first.size()-1]!='/'
        && (force || a==dt.end()
            || p->second.date!=a->second.date
            || p->second.size!=a->second.size)) {
      total_size+=p->second.size;

      // Key by first 5 bytes of filename extension, case insensitive
      int sp=0;  // sortkey byte position
      for (string::const_iterator q=p->first.begin(); q!=p->first.end(); ++q){
        uint64_t c=*q&255;
        if (c>='A' && c<='Z') c+='a'-'A';
        if (c=='/') sp=0, p->second.data=0;
        else if (c=='.') sp=8, p->second.data=0;
        else if (sp>3) p->second.data+=c<<(--sp*8);
      }

      // Key by descending size rounded to 16K
      int64_t s=p->second.size>>14;
      if (s>=(1<<24)) s=(1<<24)-1;
      p->second.data+=(1<<24)-s-1;
      vf.push_back(p);
    }
  }
  std::sort(vf.begin(), vf.end(), compareFilename);

  // Test for reliable access to archive
  if (archive_exists!=exists(subpart(archive, 1).c_str()))
    error("archive access is intermittent");

  // Open output
  OutputArchive out(arcname.c_str(), password, salt, offset);
  out.seek(header_pos, SEEK_SET);

  // Start compress and write jobs
  const int compression_workers=int(min(
      uint64_t(threads),
      KEEPVAULT_NATIVE_PROCESSING_BUDGET/KEEPVAULT_COMPRESSION_JOB_RESERVATION));
  if (compression_workers<1) error("native compression memory budget permits no workers");

  // One queued block beyond the active compressors is sufficient to keep the
  // reader, compressors and ordered writer busy. The older 2N-1 queue could
  // retain several GiB of 64 MiB blocks before the RSS monitor observed it.
  vector<ThreadID> tid(compression_workers+1);
  ThreadID wid;
  CompressJob job(compression_workers, tid.size(), &out);
  printf(
      "Adding %1.6f MB in %d files -method %s -threads %d at %s.\n",
      total_size/1000000.0, int(vf.size()), method.c_str(), compression_workers,
      dateToString(date).c_str());
  for (unsigned i=0; i<tid.size(); ++i) run(tid[i], compressThread, &job);
  run(wid, writeThread, &job);
  bool compression_threads_joined=false;
  const auto finish_compression_threads = [&]() {
    if (compression_threads_joined) return;
    StringBuffer end_of_input;
    job.write(end_of_input, 0, "");
    for (unsigned i=0; i<tid.size(); ++i) join(tid[i]);
    join(wid);
    compression_threads_joined=true;
  };

  // Append in streaming mode. Each file is a separate block. Large files
  // are split into blocks of size blocksize.
  int64_t dedupesize=0;  // input size after dedupe
  if (method[0]=='s') {
    StringBuffer sb(blocksize+4096-128);
    try {
      for (unsigned fi=0; fi<vf.size(); ++fi) {
        DTMap::iterator p=vf[fi];
        print_progress(total_size, total_done, summary);
        if (summary<=0) {
          printf("+ ");
          printUTF8(p->first.c_str());
          printf(" %1.0f\n", p->second.size+0.0);
        }
        FP in=fopen(p->first.c_str(), RB);
        if (in==FPNULL) {
          printerr(p->first.c_str());
          total_size-=p->second.size;
          ++errors;
          continue;
        }
        try {
          uint64_t i=0;
          const int BUFSIZE=4096;
          char buf[BUFSIZE];
          while (true) {
            const size_t read_count=keepvault_read_creation_input(buf, BUFSIZE, in);
            const int r=int(read_count);
            sb.write(buf, r);
            i+=r;
            if (r==0 || sb.size()+BUFSIZE>blocksize) {
              string filename="";
              string comment="";
              if (i==sb.size()) {  // first block?
                filename=rename(p->first);
                comment=itos(p->second.date);
                if ((p->second.attr&255)>0) {
                  comment+=" ";
                  comment+=char(p->second.attr&255);
                  comment+=itos(p->second.attr>>8);
                }
              }
              total_done+=sb.size();
              job.write(sb, filename.c_str(), method, comment.c_str());
              assert(sb.size()==0);
            }
            if (r==0) break;
          }
          if (i!=uint64_t(p->second.size))
            error("creation input size changed after the validated scan");
          FP closing=in;
          in=FPNULL;
          if (keepvault_checked_fclose(closing)!=0)
            error("creation input close failed");
        }
        catch (...) {
          if (in!=FPNULL) {
            FP closing=in;
            in=FPNULL;
            fclose(closing);
          }
          throw;
        }
      }
    }
    catch (...) {
      sb.secureClear();
      finish_compression_threads();
      throw;
    }

    finish_compression_threads();

    // Done
    const int64_t outsize=out.tell();
    printf("%1.0f + (%1.0f -> %1.0f) = %1.0f\n",
        double(header_pos),
        double(total_size),
        double(outsize-header_pos),
        double(outsize));
    out.close();
    return errors>0;
  }  // end if streaming

  // Adjust date to maintain sequential order
  if (ver.size() && ver.back().lastdate>=date) {
    const int64_t newdate=decimal_time(unix_time(ver.back().lastdate)+1);
    fflush(stdout);
    fprintf(stderr, "Warning: adjusting date from %s to %s\n",
      dateToString(date).c_str(), dateToString(newdate).c_str());
    assert(newdate>date);
    date=newdate;
  }

  // Build htinv for fast lookups of sha1 in ht
  HTIndex htinv(ht, ht.size()+(total_size>>(10+fragment))+vf.size());
  const unsigned htsize=ht.size();  // fragments at start of update

  // reserve space for the header block
  writeJidacHeader(&out, date, -1, htsize);
  const int64_t header_end=out.tell();

  // Compress until end of last file
  assert(method!="");
  StringBuffer sb(blocksize+4096-128);  // block to compress
  unsigned frags=0;    // number of fragments in sb
  unsigned redundancy=0;  // estimated bytes that can be compressed out of sb
  unsigned text=0;     // number of fragents containing text
  unsigned exe=0;      // number of fragments containing x86 (exe, dll)
  const int ON=4;      // number of order-1 tables to save
  unsigned char o1prev[ON*256]={0};  // last ON order 1 predictions
  libzpaq::Array<char> fragbuf(MAX_FRAGMENT);
  vector<unsigned> blocklist;  // list of starting fragments

  // For each file to be added
  try {
  for (unsigned fi=0; fi<=vf.size(); ++fi) {
    FP in=FPNULL;
    const int BUFSIZE=4096;  // input buffer
    char buf[BUFSIZE];
    int bufptr=0, buflen=0;  // read pointer and limit
    if (fi<vf.size()) {
      assert(vf[fi]->second.ptr.size()==0);
      DTMap::iterator p=vf[fi];

      // Open input file
      bufptr=buflen=0;
      in=fopen(p->first.c_str(), RB);
      if (in==FPNULL) {  // skip if not found
        p->second.date=0;
        total_size-=p->second.size;
        printerr(p->first.c_str());
        ++errors;
        continue;
      }
      p->second.data=1;  // add
    }

    try {
    // Read fragments
    int64_t fsize=0;  // file size after dedupe
    uint64_t source_bytes=0;
    for (unsigned fj=0; true; ++fj) {
      int64_t sz=0;  // fragment size;
      unsigned hits=0;  // correct prediction count
      int c=EOF;  // current byte
      unsigned htptr=0;  // fragment index
      char sha1result[20]={0};  // fragment hash
      unsigned char o1[256]={0};  // order 1 context -> predicted byte
      if (fi<vf.size()) {
        int c1=0;  // previous byte
        unsigned h=0;  // rolling hash for finding fragment boundaries
        libzpaq::SHA1 sha1;
        assert(in!=FPNULL);
        while (true) {
          if (bufptr>=buflen) {
            bufptr=0;
            buflen=int(keepvault_read_creation_input(buf, BUFSIZE, in));
            source_bytes+=uint64_t(buflen);
          }
          if (bufptr>=buflen) c=EOF;
          else c=(unsigned char)buf[bufptr++];
          if (c!=EOF) {
            if (c==o1[c1]) h=(h+c+1)*314159265u, ++hits;
            else h=(h+c+1)*271828182u;
            o1[c1]=c;
            c1=c;
            sha1.put(c);
            fragbuf[sz++]=c;
          }
          if (c==EOF
              || sz>=MAX_FRAGMENT
              || (fragment<=22 && h<(1u<<(22-fragment)) && sz>=MIN_FRAGMENT))
            break;
        }
        assert(sz<=MAX_FRAGMENT);
        total_done+=sz;

        // Look for matching fragment
        assert(uint64_t(sz)==sha1.usize());
        memcpy(sha1result, sha1.result(), 20);
        htptr=htinv.find(sha1result);
      }  // end if fi<vf.size()

      if (htptr==0) {  // not matched or last block

        // Analyze fragment for redundancy, x86, text.
        // Test for text: letters, digits, '.' and ',' followed by spaces
        //   and no invalid UTF-8.
        // Test for exe: 139 (mov reg, r/m) in lots of contexts.
        // 4 tests for redundancy, measured as hits/sz. Take the highest of:
        //   1. Successful prediction count in o1.
        //   2. Non-uniform distribution in o1 (counted in o2).
        //   3. Fraction of zeros in o1 (bytes never seen).
        //   4. Fraction of matches between o1 and previous o1 (o1prev).
        int text1=0, exe1=0;
        int64_t h1=sz;
        unsigned char o1ct[256]={0};  // counts of bytes in o1
        static const unsigned char dt[256]={  // 32768/((i+1)*204)
          160,80,53,40,32,26,22,20,17,16,14,13,12,11,10,10,
            9, 8, 8, 8, 7, 7, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5,
            4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        for (int i=0; i<256; ++i) {
          if (o1ct[o1[i]]<255) h1-=(sz*dt[o1ct[o1[i]]++])>>15;
          if (o1[i]==' ' && (isalnum(i) || i=='.' || i==',')) ++text1;
          if (o1[i] && (i<9 || i==11 || i==12 || (i>=14 && i<=31) || i>=240))
            --text1;
          if (i>=192 && i<240 && o1[i] && (o1[i]<128 || o1[i]>=192))
            --text1;
          if (o1[i]==139) ++exe1;
        }
        text1=(text1>=3);
        exe1=(exe1>=5);
        if (sz>0) h1=h1*h1/sz; // Test 2: near 0 if random.
        unsigned h2=h1;
        if (h2>hits) hits=h2;
        h2=o1ct[0]*sz/256;  // Test 3: bytes never seen or that predict 0.
        if (h2>hits) hits=h2;
        h2=0;
        for (int i=0; i<256*ON; ++i)  // Test 4: compare to previous o1.
          h2+=o1prev[i]==o1[i&255];
        h2=h2*sz/(256*ON);
        if (h2>hits) hits=h2;
        if (hits>sz) hits=sz;

        // Start a new block if the current block is almost full, or at
        // the start of a file that won't fit or doesn't share mutual
        // information with the current block, or last file.
        bool newblock=false;
        if (frags>0 && fj==0 && fi<vf.size()) {
          const int64_t esize=vf[fi]->second.size;
          const int64_t newsize=sb.size()+esize+(esize>>14)+4096+frags*4;
          if (newsize>blocksize/4 && redundancy<sb.size()/128) newblock=true;
          if (newblock) {  // test for mutual information
            unsigned ct=0;
            for (unsigned i=0; i<256*ON; ++i)
              if (o1prev[i] && o1prev[i]==o1[i&255]) ++ct;
            if (ct>ON*2) newblock=false;
          }
          if (newsize>=blocksize) newblock=true;  // won't fit?
        }
        if (sb.size()+sz+80+frags*4>=blocksize) newblock=true; // full?
        if (fi==vf.size()) newblock=true;  // last file?
        if (frags<1) newblock=false;  // block is empty?

        // Pad sb with fragment size list, then compress
        if (newblock) {
          assert(frags>0);
          assert(frags<ht.size());
          for (unsigned i=ht.size()-frags; i<ht.size(); ++i)
            puti(sb, ht[i].usize, 4);  // list of frag sizes
          puti(sb, 0, 4); // omit first frag ID to make block movable
          puti(sb, frags, 4);  // number of frags
          string m=method;
          if (isdigit(method[0]))
            m+=","+itos(redundancy/(sb.size()/256+1))
                 +","+itos((exe>frags)*2+(text>frags));
          string fn="jDC"+itos(date, 14)+"d"+itos(ht.size()-frags, 10);
          print_progress(total_size, total_done, summary);
          if (summary<=0)
            printf("[%u..%u] %u -method %s\n",
                unsigned(ht.size())-frags, unsigned(ht.size())-1,
                unsigned(sb.size()), m.c_str());
          if (method[0]!='i')
            job.write(sb, fn.c_str(), m.c_str());
          else {  // index: don't compress data
            job.csize.push_back(sb.size());
            sb.secureClear();
          }
          assert(sb.size()==0);
          blocklist.push_back(ht.size()-frags);  // mark block start
          frags=redundancy=text=exe=0;
          memset(o1prev, 0, sizeof(o1prev));
        }

        // Append fragbuf to sb and update block statistics
        assert(sz==0 || fi<vf.size());
        sb.write(&fragbuf[0], sz);
        ++frags;
        redundancy+=hits;
        exe+=exe1*4;
        text+=text1*2;
        if (sz>=MIN_FRAGMENT) {
          memmove(o1prev, o1prev+256, 256*(ON-1));
          memcpy(o1prev+256*(ON-1), o1, 256);
        }
      }  // end if frag not matched or last block

      // Update HT and ptr list
      if (fi<vf.size()) {
        if (htptr==0) {
          htptr=ht.size();
          ht.push_back(HT(sha1result, sz));
          htinv.update();
          fsize+=sz;
        }
        vf[fi]->second.ptr.push_back(htptr);
      }
      if (c==EOF) break;
    }  // end for each fragment fj
    if (fi<vf.size()) {
      dedupesize+=fsize;
      DTMap::iterator p=vf[fi];
      print_progress(total_size, total_done, summary);
      if (summary<=0) {
        string newname=rename(p->first.c_str());
        DTMap::iterator a=dt.find(newname);
        if (a==dt.end() || a->second.date==0) printf("+ ");
        else printf("# ");
        printUTF8(p->first.c_str());
        if (newname!=p->first) {
          printf(" -> ");
          printUTF8(newname.c_str());
        }
        printf(" %1.0f", p->second.size+0.0);
        if (fsize!=p->second.size) printf(" -> %1.0f", fsize+0.0);
        printf("\n");
      }
      assert(in!=FPNULL);
      if (p->second.size<0 || source_bytes!=uint64_t(p->second.size))
        error("creation input size changed after the validated scan");
      FP closing=in;
      in=FPNULL;
      if (keepvault_checked_fclose(closing)!=0)
        error("creation input close failed");
    }
    }
    catch (...) {
      if (in!=FPNULL) {
        FP closing=in;
        in=FPNULL;
        fclose(closing);
      }
      throw;
    }
  }  // end for each file fi
  assert(sb.size()==0);
  }
  catch (...) {
    sb.secureClear();
    finish_compression_threads();
    throw;
  }

  finish_compression_threads();

  // Open index
  salt[0]^='7'^'z';
  OutputArchive outi(index ? index : "", password, salt, 0);
  WriterPair wp;
  wp.a=&out;
  if (index) wp.b=&outi;
  writeJidacHeader(&outi, date, 0, htsize);

  // Append compressed fragment tables to archive
  int64_t cdatasize=out.tell()-header_end;
  StringBuffer is;
  assert(blocklist.size()==job.csize.size());
  blocklist.push_back(ht.size());
  for (unsigned i=0; i<job.csize.size(); ++i) {
    if (blocklist[i]<blocklist[i+1]) {
      puti(is, job.csize[i], 4);  // compressed size of block
      for (unsigned j=blocklist[i]; j<blocklist[i+1]; ++j) {
        is.write((const char*)ht[j].sha1, 20);
        puti(is, ht[j].usize, 4);
      }
      libzpaq::compressBlock(&is, &wp, "0",
          ("jDC"+itos(date, 14)+"h"+itos(blocklist[i], 10)).c_str(),
          "jDC\x01");
      is.secureClear();
    }
  }

  // Delete from archive
  int dtcount=0;  // index block header name
  int removed=0;  // count
  for (DTMap::iterator p=dt.begin(); p!=dt.end(); ++p) {
    if (p->second.date && !p->second.data) {
      puti(is, 0, 8);
      is.write(p->first.c_str(), strlen(p->first.c_str()));
      is.put(0);
      if (summary<=0) {
        printf("- ");
        printUTF8(p->first.c_str());
        printf("\n");
      }
      ++removed;
      if (is.size()>16000) {
        libzpaq::compressBlock(&is, &wp, "1",
            ("jDC"+itos(date)+"i"+itos(++dtcount, 10)).c_str(), "jDC\x01");
        is.secureClear();
      }
    }
  }

  // Append compressed index to archive
  int added=0;  // count
  for (DTMap::iterator p=edt.begin();; ++p) {
    if (p!=edt.end()) {
      string filename=rename(p->first);
      DTMap::iterator a=dt.find(filename);
      if (p->second.date && (a==dt.end() // new file
         || a->second.date!=p->second.date  // date change
         || (a->second.attr && a->second.attr!=p->second.attr)  // attr ch.
         || a->second.size!=p->second.size  // size change
         || (p->second.data && a->second.ptr!=p->second.ptr))) { // content
        if (summary<=0 && p->second.data==0) {  // not compressed?
          if (a==dt.end() || a->second.date==0) printf("+ ");
          else printf("# ");
          printUTF8(p->first.c_str());
          if (filename!=p->first) {
            printf(" -> ");
            printUTF8(filename.c_str());
          }
          printf("\n");
        }
        ++added;
        puti(is, p->second.date, 8);
        is.write(filename.c_str(), strlen(filename.c_str()));
        is.put(0);
        if ((p->second.attr&255)=='u') {  // unix attributes
          puti(is, 3, 4);
          puti(is, p->second.attr, 3);
        }
        else if ((p->second.attr&255)=='w') {  // windows attributes
          puti(is, 5, 4);
          puti(is, p->second.attr, 5);
        }
        else puti(is, 0, 4);  // no attributes
        if (a==dt.end() || p->second.data) a=p;  // use new frag pointers
        puti(is, a->second.ptr.size(), 4);  // list of frag pointers
        for (unsigned i=0; i<a->second.ptr.size(); ++i)
          puti(is, a->second.ptr[i], 4);
      }
    }
    if (is.size()>16000 || (is.size()>0 && p==edt.end())) {
      libzpaq::compressBlock(&is, &wp, "1",
          ("jDC"+itos(date)+"i"+itos(++dtcount, 10)).c_str(), "jDC\x01");
      is.secureClear();
    }
    if (p==edt.end()) break;
  }
  printf("%d +added, %d -removed.\n", added, removed);
  assert(is.size()==0);

  // Back up and write the header
  outi.close();
  int64_t archive_end=out.tell();
  out.seek(header_pos, SEEK_SET);
  writeJidacHeader(&out, date, cdatasize, htsize);
  out.seek(0, SEEK_END);
  int64_t archive_size=out.tell();
  out.close();

  // Truncate empty update from archive (if not indexed)
  if (!index) {
    if (added+removed==0 && archive_end-header_pos==104) // no update
      archive_end=header_pos;
    if (archive_end<archive_size) {
      if (archive_end>0) {
        printf("truncating archive from %1.0f to %1.0f\n",
            double(archive_size), double(archive_end));
        if (truncate(arcname.c_str(), archive_end)) printerr(archive.c_str());
      }
      else if (archive_end==0) {
        if (delete_file(arcname.c_str())) {
          printf("deleted ");
          printUTF8(arcname.c_str());
          printf("\n");
        }
      }
    }
  }
  fflush(stdout);
  fprintf(stderr, "\n%1.6f + (%1.6f -> %1.6f -> %1.6f) = %1.6f MB\n",
      header_pos/1000000.0, total_size/1000000.0, dedupesize/1000000.0,
      (archive_end-header_pos)/1000000.0, archive_end/1000000.0);
  return errors>0;
}

/////////////////////////////// extract ///////////////////////////////

// Return true if the internal file p
// and external file contents are equal or neither exists.
// If filename is 0 then return true if it is possible to compare.
bool Jidac::equal(DTMap::const_iterator p, const char* filename) {

  // test if all fragment sizes and hashes exist
  if (filename==0) {
    static const char zero[20]={0};
    for (unsigned i=0; i<p->second.ptr.size(); ++i) {
      unsigned j=p->second.ptr[i];
      if (j<1 || j>=ht.size()
          || ht[j].usize<0 || !memcmp(ht[j].sha1, zero, 20))
        return false;
    }
    return true;
  }

  // internal or neither file exists
  if (p->second.date==0) return !exists(filename);

  // directories always match
  if (p->first!="" && p->first[p->first.size()-1]=='/')
    return exists(filename);

  // compare sizes
  FP in=fopen(filename, RB);
  if (in==FPNULL) return false;
  fseeko(in, 0, SEEK_END);
  if (ftello(in)!=p->second.size) return fclose(in), false;

  // compare hashes
  fseeko(in, 0, SEEK_SET);
  libzpaq::SHA1 sha1;
  const int BUFSIZE=4096;
  char buf[BUFSIZE];
  for (unsigned i=0; i<p->second.ptr.size(); ++i) {
    unsigned f=p->second.ptr[i];
    if (f<1 || f>=ht.size() || ht[f].usize<0) return fclose(in), false;
    for (int j=0; j<ht[f].usize;) {
      int n=ht[f].usize-j;
      if (n>BUFSIZE) n=BUFSIZE;
      int r=fread(buf, 1, n, in);
      if (r!=n) return fclose(in), false;
      sha1.write(buf, n);
      j+=n;
    }
    if (memcmp(sha1.result(), ht[f].sha1, 20)!=0) return fclose(in), false;
  }
  if (fread(buf, 1, BUFSIZE, in)!=0) return fclose(in), false;
  fclose(in);
  return true;
}

// An extract job is a set of blocks with at least one file pointing to them.
// Blocks are extracted in separate threads, set READY -> WORKING.
// A block is extracted to memory up to the last fragment that has a file
// pointing to it. Then the checksums are verified. Then for each file
// pointing to the block, each of the fragments that it points to within
// the block are written in order.

struct ExtractJob {         // list of jobs
  Mutex mutex;              // protects state
  Mutex write_mutex;        // protects writing to disk
  int job;                  // number of jobs started
  Jidac& jd;                // what to extract
  FP outf;                  // currently open output file
  DTMap::iterator lastdt;   // currently open output file name
  double maxMemory;         // largest memory used by any block (test mode)
  int64_t total_size;       // bytes to extract
  int64_t total_done;       // bytes extracted so far
  unsigned io_errors;       // output seek/write failures
  KeepVaultMemoryBudget processing_memory;
  ExtractJob(Jidac& j): job(0), jd(j), outf(FPNULL), lastdt(j.dt.end()),
      maxMemory(0), total_size(0), total_done(0), io_errors(0),
      processing_memory(KEEPVAULT_NATIVE_PROCESSING_BUDGET) {
    init_mutex(mutex);
    init_mutex(write_mutex);
  }
  ~ExtractJob() {
    destroy_mutex(mutex);
    destroy_mutex(write_mutex);
  }
};

// Decompress blocks in a job until none are READY
ThreadReturn decompressThread(void* arg) {
  ExtractJob& job=*(ExtractJob*)arg;
  int jobNumber=0;

  // Get job number
  lock(job.mutex);
  jobNumber=++job.job;
  release(job.mutex);

  // Open archive for reading
  InputArchive in(job.jd.archive.c_str(), job.jd.password);
  if (!in.isopen()) return 0;
  KeepVaultMemoryReservation worker_memory(
      job.processing_memory, KEEPVAULT_REGULAR_JOB_RESERVATION);
  StringBuffer out;

  // Look for next READY job.
  int next=0;  // current job
  while (true) {
    lock(job.mutex);
    for (unsigned i=0; i<=job.jd.block.size(); ++i) {
      unsigned k=i+next;
      if (k>=job.jd.block.size()) k-=job.jd.block.size();
      if (i==job.jd.block.size()) {  // no more jobs?
        release(job.mutex);
        return 0;
      }
      Block& b=job.jd.block[k];
      if (b.state==Block::READY && b.size>0 && b.usize>=0) {
        b.state=Block::WORKING;
        release(job.mutex);
        next=k;
        break;
      }
    }
    Block& b=job.jd.block[next];

    // Get uncompressed size of block. Archive metadata is attacker-controlled,
    // so these checks must remain active in release builds.
    uint64_t output_size64=0;
    bool invalid_block=b.start==0 || b.size==0
        || uint64_t(b.start)+b.size>job.jd.ht.size()
        || b.usize<0 || uint64_t(b.usize)>KEEPVAULT_REGULAR_MAX_UNCOMPRESSED;
    for (unsigned j=0; j<b.size; ++j) {
      if (invalid_block || b.start+j>=job.jd.ht.size()
          || job.jd.ht[b.start+j].usize<0) {
        invalid_block=true;
        break;
      }
      output_size64+=unsigned(job.jd.ht[b.start+j].usize);
      if (output_size64>UINT32_MAX || output_size64>uint64_t(b.usize)) {
        invalid_block=true;
        break;
      }
    }
    if (invalid_block) {
      lock(job.mutex);
      b.state=Block::BAD;
      b.extracted=0;
      fprintf(stderr, "Job %d: invalid block metadata\n", jobNumber);
      release(job.mutex);
      continue;
    }
    const unsigned output_size=unsigned(output_size64);

    // Decompress
    double mem=0;  // how much memory used to decompress
    try {
      in.seek(b.offset, SEEK_SET);
      std::unique_ptr<libzpaq::Decompresser> d(new libzpaq::Decompresser());
      d->setInput(&in);
      out.secureClear();
      out.setLimit(b.usize);
      d->setOutput(&out);
      if (!d->findBlock(&mem)) error("archive block not found");
      if (!(mem>=0 && mem<=KEEPVAULT_REGULAR_MAX_MODEL_MEMORY))
        error("regular archive block requires too much model memory");
      lock(job.mutex);
      if (mem>job.maxMemory) job.maxMemory=mem;
      release(job.mutex);
      while (d->findFilename()) {
        d->readComment();
        while (out.size()<output_size && d->decompress(1<<14));
        lock(job.mutex);
        print_progress(job.total_size, job.total_done, job.jd.summary);
        if (job.jd.summary<=0)
          printf("[%u..%u] -> %1.0f\n", b.start, b.start+b.size-1,
              out.size()+0.0);
        release(job.mutex);
        if (out.size()>=output_size) break;
        d->readSegmentEnd();
      }
      if (out.size()<output_size) {
        lock(job.mutex);
        fflush(stdout);
        fprintf(stderr, "output [%u..%u] %zu of %u bytes\n",
             b.start, b.start+b.size-1, out.size(), output_size);
        release(job.mutex);
        error("unexpected end of compressed data");
      }

      // Verify fragment checksums if present
      uint64_t q=0;  // fragment start
      libzpaq::SHA1 sha1;
      if (b.extracted!=0) error("invalid extracted fragment state");
      for (unsigned j=b.start; j<b.start+b.size; ++j) {
        if (j==0 || j>=job.jd.ht.size() || job.jd.ht[j].usize<0
            || job.jd.ht[j].usize>0x7fffffff)
          error("invalid fragment metadata");
        if (q+job.jd.ht[j].usize>out.size())
          error("Incomplete decompression");
        char sha1result[20];
        sha1.write(out.c_str()+q, job.jd.ht[j].usize);
        memcpy(sha1result, sha1.result(), 20);
        q+=job.jd.ht[j].usize;
        if (memcmp(sha1result, job.jd.ht[j].sha1, 20)) {
          lock(job.mutex);
          fflush(stdout);
          fprintf(stderr, "Job %d: fragment %u size %d checksum failed\n",
                 jobNumber, j, job.jd.ht[j].usize);
          release(job.mutex);
          error("bad checksum");
        }
        ++b.extracted;
      }
    }

    // If out of memory, let another thread try
    catch (std::bad_alloc& e) {
      lock(job.mutex);
      fflush(stdout);
      fprintf(stderr, "Job %d killed: %s\n", jobNumber, e.what());
      b.state=Block::READY;
      b.extracted=0;
      out.secureClear();
      release(job.mutex);
      return 0;
    }

    // Other errors: assume bad input
    catch (std::exception& e) {
      lock(job.mutex);
      fflush(stdout);
      fprintf(stderr, "Job %d: skipping [%u..%u] at %1.0f: %s\n",
              jobNumber, b.start+b.extracted, b.start+b.size-1,
              b.offset+0.0, e.what());
      release(job.mutex);
      continue;
    }

    // Write the files in dt that point to this block
    lock(job.write_mutex);
    if (job.io_errors>0) {
      release(job.write_mutex);
      return 0;
    }
    bool local_io_failure=false;
    for (unsigned ip=0; ip<b.files.size(); ++ip) {
      DTMap::iterator p=b.files[ip];
      if (p->second.date==0 || p->second.data<0
          || p->second.data>=int64_t(p->second.ptr.size()))
        continue;  // don't write

      // Look for pointers to this block
      const vector<unsigned>& ptr=p->second.ptr;
      int64_t offset=0;  // write offset
      for (unsigned j=0; j<ptr.size(); ++j) {
        if (ptr[j]<b.start || ptr[j]>=b.start+b.extracted) {
          offset+=job.jd.ht[ptr[j]].usize;
          continue;
        }

        // Close last opened file if different
        if (p!=job.lastdt) {
          if (job.outf!=FPNULL) {
            assert(job.lastdt!=job.jd.dt.end());
            assert(job.lastdt->second.date);
            assert(job.lastdt->second.data
                   <int64_t(job.lastdt->second.ptr.size()));
            if (keepvault_checked_fclose(job.outf)!=0) {
              job.outf=FPNULL;
              job.lastdt=job.jd.dt.end();
              lock(job.mutex);
              ++job.io_errors;
              fprintf(stderr, "output close or flush failed\n");
              release(job.mutex);
              release(job.write_mutex);
              return 0;
            }
            job.outf=FPNULL;
          }
          job.lastdt=job.jd.dt.end();
        }

        // Open file for output
        if (job.lastdt==job.jd.dt.end()) {
          string filename=job.jd.rename(p->first);
          assert(job.outf==FPNULL);
          if (p->second.data==0) {
            if (!job.jd.dotest) {
#ifdef unix
              if (g_keepvault_output_root_fd>=0) keepvault_secure_makepath(filename);
              else
#endif
                makepath(filename);
            }
            if (job.jd.summary<=0) {
              lock(job.mutex);
              print_progress(job.total_size, job.total_done, job.jd.summary);
              if (job.jd.summary<=0) {
                printf("> ");
                printUTF8(filename.c_str());
                printf("\n");
              }
              release(job.mutex);
            }
            if (!job.jd.dotest) {
              job.outf=
#ifdef unix
                  g_keepvault_output_root_fd>=0
                    ? keepvault_secure_open_output(filename, true) :
#endif
                    fopen(filename.c_str(), WB);
              if (job.outf==FPNULL) {
                lock(job.mutex);
                printerr(filename.c_str());
                release(job.mutex);
              }
#ifndef unix
              else if ((p->second.attr&0x200ff)==0x20000+'w') {  // sparse?
                DWORD br=0;
                if (!DeviceIoControl(job.outf, FSCTL_SET_SPARSE,
                    NULL, 0, NULL, 0, &br, NULL))  // set sparse attribute
                  printerr(filename.c_str());
              }
#endif
            }
          }
          else if (!job.jd.dotest)
            job.outf=
#ifdef unix
                g_keepvault_output_root_fd>=0
                  ? keepvault_secure_open_output(filename, false) :
#endif
                  fopen(filename.c_str(), RBPLUS);  // update existing file
          if (!job.jd.dotest && job.outf==FPNULL) break;  // skip errors
          job.lastdt=p;
          assert(job.jd.dotest || job.outf!=FPNULL);
        }
        assert(job.lastdt==p);

        // Find block offset of fragment
        uint64_t q=0;  // fragment offset from start of block
        for (unsigned k=b.start; k<ptr[j]; ++k) {
          assert(k>0);
          assert(k<job.jd.ht.size());
          if (job.jd.ht[k].usize<0) error("streaming fragment in file");
          assert(job.jd.ht[k].usize>=0);
          q+=job.jd.ht[k].usize;
        }
        assert(q+job.jd.ht[ptr[j]].usize<=out.size());

        // Combine consecutive fragments into a single write
        assert(offset>=0);
        ++p->second.data;
        uint64_t usize=job.jd.ht[ptr[j]].usize;
        assert(usize<=0x7fffffff);
        assert(b.start+b.size<=job.jd.ht.size());
        while (j+1<ptr.size() && ptr[j+1]==ptr[j]+1
               && ptr[j+1]<b.start+b.size
               && job.jd.ht[ptr[j+1]].usize>=0
               && usize+job.jd.ht[ptr[j+1]].usize<=0x7fffffff) {
          ++p->second.data;
          assert(p->second.data<=int64_t(ptr.size()));
          assert(job.jd.ht[ptr[j+1]].usize>=0);
          usize+=job.jd.ht[ptr[++j]].usize;
        }
        assert(usize<=0x7fffffff);
        assert(q+usize<=out.size());

        // Write the merged fragment unless they are all zeros and it
        // does not include the last fragment.
        uint64_t nz=q;  // first nonzero byte in fragments to be written
        while (nz<q+usize && out.c_str()[nz]==0) ++nz;
        if (!job.jd.dotest && (nz<q+usize || j+1==ptr.size())) {
          const bool exceeds_declared_size=offset<0 || p->second.size<0
              || uint64_t(offset)>uint64_t(p->second.size)
              || usize>uint64_t(p->second.size)-uint64_t(offset)
              || uint64_t(offset)>job.jd.keepvault_max_single_file_bytes
              || usize>job.jd.keepvault_max_single_file_bytes-uint64_t(offset);
          if (exceeds_declared_size
              || fseeko(job.outf, offset, SEEK_SET)!=0
              || fwrite(out.c_str()+q, 1, size_t(usize), job.outf)!=size_t(usize)) {
            p->second.data=-2;
            if (job.outf!=FPNULL
                && keepvault_checked_fclose(job.outf)!=0) {
              lock(job.mutex);
              ++job.io_errors;
              fprintf(stderr, "output close or flush failed after a write error\n");
              release(job.mutex);
            }
            job.outf=FPNULL;
            job.lastdt=job.jd.dt.end();
            lock(job.mutex);
            ++job.io_errors;
            fprintf(stderr, "output seek/write failed\n");
            release(job.mutex);
            local_io_failure=true;
            break;
          }
        }
        offset+=usize;
        lock(job.mutex);
        job.total_done+=usize;
        release(job.mutex);

        // Close file. If this is the last fragment then set date and attr.
        // Do not set read-only attribute in Windows yet.
        if (p->second.data==int64_t(ptr.size())) {
          assert(p->second.date);
          assert(job.lastdt!=job.jd.dt.end());
          assert(job.jd.dotest || job.outf!=FPNULL);
          if (!job.jd.dotest) {
            assert(job.outf!=FPNULL);
            string fn=job.jd.rename(p->first);
            int64_t attr=p->second.attr;
            int64_t date=p->second.date;
            if ((p->second.attr&0x1ff)=='w'+256) attr=0;  // read-only?
            if (p->second.data!=int64_t(p->second.ptr.size()))
              date=attr=0;  // not last frag
            try {
#ifdef unix
              if (g_keepvault_output_root_fd>=0)
                keepvault_secure_close_owned(fn, date, attr, job.outf);
              else
#endif
                close(fn.c_str(), date, attr, job.outf);
              job.outf=FPNULL;
            }
            catch (const std::exception& e) {
              job.outf=FPNULL;
              job.lastdt=job.jd.dt.end();
              lock(job.mutex);
              ++job.io_errors;
              fprintf(stderr, "output close or flush failed: %s\n", e.what());
              release(job.mutex);
              local_io_failure=true;
              break;
            }
          }
          job.lastdt=job.jd.dt.end();
        }
      } // end for j
      if (local_io_failure) break;
    } // end for ip

    // Last file
    release(job.write_mutex);
  } // end while true

  // Last block
  return 0;
}

// Streaming output destination
struct OutputFile: public libzpaq::Writer {
  FP f;
  uint64_t written;
  void put(int c) {
    char ch=c;
    if (f!=FPNULL && fwrite(&ch, 1, 1, f)!=1) error("output write failed");
    ++written;
  }
  void write(const char* buf, int n) {
    if (f!=FPNULL && n>0 && fwrite(buf, 1, n, f)!=size_t(n))
      error("output write failed");
    if (n>0) written+=n;
  }
  OutputFile(FP out=FPNULL): f(out), written(0) {}
};

static void keepvault_wipe_vector(vector<char>& value) {
  if (!value.empty()) {
    volatile char* p=&value[0];
    for (size_t i=0; i<value.size(); ++i) p[i]=0;
  }
  vector<char>().swap(value);
}

static void keepvault_wipe_string(string& value) {
  if (!value.empty()) {
    volatile char* p=&value[0];
    for (size_t i=0; i<value.size(); ++i) p[i]=0;
  }
  string().swap(value);
}

struct KeepVaultFrameReader: public libzpaq::Reader {
  const vector<char>& data;
  size_t position;
  KeepVaultFrameReader(const vector<char>& source): data(source), position(0) {}
  int get() {
    return position<data.size() ? (unsigned char)data[position++] : -1;
  }
  int read(char* output, int count) {
    if (count<=0 || position>=data.size()) return 0;
    const size_t available=data.size()-position;
    const size_t take=available<size_t(count) ? available : size_t(count);
    memcpy(output, &data[position], take);
    position+=take;
    return int(take);
  }
};

struct KeepVaultBoundedWriter: public libzpaq::Writer {
  vector<char> data;
  size_t limit;
  explicit KeepVaultBoundedWriter(size_t max_bytes): limit(max_bytes) {}
  ~KeepVaultBoundedWriter() {keepvault_wipe_vector(data);}
  void put(int c) {
    if (data.size()>=limit)
      throw std::runtime_error("v12 pipe block exceeds uncompressed-size limit");
    data.push_back(char(c));
  }
  void write(const char* source, int count) {
    if (count<0 || data.size()>limit || size_t(count)>limit-data.size())
      throw std::runtime_error("v12 pipe block exceeds uncompressed-size limit");
    data.insert(data.end(), source, source+count);
  }
};

struct KeepVaultPipeSegment {
  string filename;
  string comment;
  vector<char> data;
  ~KeepVaultPipeSegment() {
    keepvault_wipe_string(filename);
    keepvault_wipe_string(comment);
    keepvault_wipe_vector(data);
  }
};

struct KeepVaultPipeFrame {
  std::unique_ptr<KeepVaultMemoryReservation> processing_memory;
  uint64_t sequence;
  uint64_t compressed_accounted;
  vector<char> compressed;
  vector<std::shared_ptr<KeepVaultPipeSegment> > segments;
  KeepVaultPipeFrame(uint64_t n): sequence(n), compressed_accounted(0) {}
  ~KeepVaultPipeFrame() {keepvault_wipe_vector(compressed);}
};

struct KeepVaultPipeState {
  std::mutex mutex;
  std::condition_variable changed;
  KeepVaultMemoryBudget processing_memory;
  std::deque<std::shared_ptr<KeepVaultPipeFrame> > pending;
  std::map<uint64_t, std::shared_ptr<KeepVaultPipeFrame> > ready;
  size_t inflight;
  size_t capacity;
  uint64_t compressed_bytes;
  uint64_t frame_count;
  bool input_done;
  std::atomic<bool> failed;
  string failure;
  KeepVaultPipeState(size_t limit):
      processing_memory(KEEPVAULT_NATIVE_PROCESSING_BUDGET),
      inflight(0), capacity(limit),
      compressed_bytes(0), frame_count(0), input_done(false), failed(false),
      failure() {}
};

static void keepvault_pipe_fail(KeepVaultPipeState& state, const string& message) {
  std::lock_guard<std::mutex> guard(state.mutex);
  if (!state.failed) {
    state.failure=message;
    state.failed=true;
  }
  state.changed.notify_all();
  state.processing_memory.stop();
}

static bool keepvault_pipe_read_exact(InputArchive& input, char* output, size_t count) {
  size_t total=0;
  while (total<count) {
    const size_t remaining=count-total;
    const int request=remaining>size_t(INT_MAX) ? INT_MAX : int(remaining);
    const int read=input.read(output+total, request);
    if (read<=0) return false;
    total+=size_t(read);
  }
  return true;
}

static uint64_t keepvault_pipe_read_u64(const char encoded[8]) {
  uint64_t value=0;
  for (int i=7; i>=0; --i) value=(value<<8)|(unsigned char)encoded[i];
  return value;
}

static void keepvault_decompress_frame(
    KeepVaultPipeFrame& frame, KeepVaultMemoryBudget& processing_memory) {
  if (frame.compressed.size()<sizeof(KEEPVAULT_ZPAQ_BLOCK_MAGIC)
      || memcmp(&frame.compressed[0], KEEPVAULT_ZPAQ_BLOCK_MAGIC,
          sizeof(KEEPVAULT_ZPAQ_BLOCK_MAGIC))!=0)
    throw std::runtime_error("v12 pipe frame does not start at a ZPAQ block boundary");
  KeepVaultFrameReader input(frame.compressed);
  std::unique_ptr<libzpaq::Decompresser> d(new libzpaq::Decompresser());
  d->setInput(&input);
  double memory=0;
  unsigned segments=0;
  size_t total_uncompressed=0;
  if (!d->findBlock(&memory))
    throw std::runtime_error("v12 pipe frame contains no ZPAQ block");
  if (!(memory>=0 && memory<=KEEPVAULT_PIPE_MAX_MODEL_MEMORY))
    throw std::runtime_error("v12 pipe block requires too much model memory");
  const uint64_t model_bytes=uint64_t(memory)+uint64_t(memory!=uint64_t(memory));
  frame.processing_memory.reset(new KeepVaultMemoryReservation(
      processing_memory,
      model_bytes+KEEPVAULT_PIPE_MAX_UNCOMPRESSED+(16ull<<20)));

  StringWriter filename(KEEPVAULT_MAX_ARCHIVE_MEMBER_NAME_BYTES);
  StringWriter comment(KEEPVAULT_MAX_ARCHIVE_COMMENT_BYTES);
  while (d->findFilename(&filename)) {
    if (++segments!=1)
      throw std::runtime_error("v12 pipe frame contains more than one segment");
    comment.s="";
    d->readComment(&comment);
    if (comment.s.size()>=4
        && comment.s.substr(comment.s.size()-4)=="jDC\x01")
      throw std::runtime_error("journaling archive is not supported on an input pipe");
    const size_t metadata_bytes=filename.s.size()+comment.s.size();
    if (metadata_bytes>size_t(KEEPVAULT_PIPE_MAX_UNCOMPRESSED)-total_uncompressed)
      throw std::runtime_error("v12 pipe frame exceeds its metadata budget");
    total_uncompressed+=metadata_bytes;

    std::shared_ptr<KeepVaultPipeSegment> segment(new KeepVaultPipeSegment());
    segment->filename.swap(filename.s);
    segment->comment.swap(comment.s);
    libzpaq::SHA1 sha1;
    d->setSHA1(&sha1);
    KeepVaultBoundedWriter output(
        size_t(KEEPVAULT_PIPE_MAX_UNCOMPRESSED)-total_uncompressed);
    d->setOutput(&output);
    d->decompress();
    char sha1result[21];
    d->readSegmentEnd(sha1result);
    if (sha1result[0]!=1)
      throw std::runtime_error("v12 pipe segment has no SHA1 checksum");
    if (memcmp(sha1result+1, sha1.result(), 20)!=0)
      throw std::runtime_error("checksum failed");
    total_uncompressed+=output.data.size();
    segment->data.swap(output.data);
    frame.segments.push_back(segment);
  }

  const int buffered=d->buffered();
  if (buffered<0 || size_t(buffered)>input.position)
    throw std::runtime_error("v12 pipe decoder reported an invalid input boundary");
  const size_t exact_consumed=input.position-size_t(buffered);
  if (segments!=1 || exact_consumed!=frame.compressed.size())
    throw std::runtime_error("v12 pipe frame is truncated or has trailing bytes");
}

// Extract or list a Keep Vault v12 streaming archive from stdin. Compression
// writes one complete ZPAQ block per length-delimited frame. Workers can thus
// decompress and verify frames independently; one ordered writer is the only
// code allowed to create or append output files. Memory is bounded by twice the
// worker count, and a failed worker wakes and joins the whole group.
int Jidac::extract_pipe_streaming(bool list_only) {
  if (password || index || repack || all || version!=DEFAULT_VERSION)
    error("archive pipe extraction supports only current streaming archives");

  InputArchive in("-", 0);
  char magic[sizeof(KEEPVAULT_PIPE_MAGIC)];
  if (!keepvault_pipe_read_exact(in, magic, sizeof(magic))
      || memcmp(magic, KEEPVAULT_PIPE_MAGIC, sizeof(magic))!=0)
    error("input is not a Keep Vault v12 framed pipe archive");

  const int worker_count=threads<1 ? 1 : (threads>64 ? 64 : threads);
  KeepVaultPipeState state(size_t(worker_count)*2u);
  unsigned segments=0;
  unsigned files_extracted=0;
  vector<std::thread> workers;
  workers.reserve(worker_count);
  try {
    for (int worker=0; worker<worker_count; ++worker) {
      workers.push_back(std::thread([&state]() {
      for (;;) {
        std::shared_ptr<KeepVaultPipeFrame> frame;
        {
          std::unique_lock<std::mutex> lock(state.mutex);
          state.changed.wait(lock, [&state]() {
            return state.failed || !state.pending.empty() || state.input_done;
          });
          if (state.failed) return;
          if (state.pending.empty()) {
            if (state.input_done) return;
            continue;
          }
          frame=state.pending.front();
          state.pending.pop_front();
        }
        try {
          keepvault_decompress_frame(*frame, state.processing_memory);
          keepvault_wipe_vector(frame->compressed);
          std::lock_guard<std::mutex> guard(state.mutex);
          if (frame->compressed_accounted>state.compressed_bytes)
            throw std::runtime_error("v12 pipe compressed-memory accounting underflow");
          state.compressed_bytes-=frame->compressed_accounted;
          frame->compressed_accounted=0;
          state.ready[frame->sequence]=frame;
          state.changed.notify_all();
        }
        catch (const std::exception& e) {
          keepvault_pipe_fail(state, e.what());
          return;
        }
        catch (...) {
          keepvault_pipe_fail(state, "unknown v12 pipe worker failure");
          return;
        }
      }
      }));
    }
  }
  catch (const std::exception& e) {
    keepvault_pipe_fail(state, e.what());
  }
  catch (...) {
    keepvault_pipe_fail(state, "unable to start v12 pipe workers");
  }
  if (state.failed) {
    for (size_t i=0; i<workers.size(); ++i) workers[i].join();
    error(state.failure.c_str());
  }

  std::thread writer;
  try {
    writer=std::thread([this, &state, &segments, &files_extracted, list_only]() {
	    FP outf=FPNULL;
	    string output_name;
	    std::set<string> published_names;
	    std::map<string, string> output_entries;
	    uint64_t archive_total_bytes=0;
	    uint64_t current_file_bytes=0;
	    bool first_segment=true;
	    bool selected=false;
	    uint64_t next=0;
	    const auto close_output = [this](FP& stream,
	        const string& path, int64_t output_date) {
	      if (stream==FPNULL) return;
#ifdef unix
	      if (g_keepvault_output_root_fd>=0) {
	        keepvault_secure_close_owned(path, output_date, 0, stream);
	        return;
	      }
#endif
	      FP closing=stream;
	      stream=FPNULL;
	      close(path.c_str(), output_date, 0, closing);
	    };
	    try {
      for (;;) {
        std::shared_ptr<KeepVaultPipeFrame> frame;
        {
          std::unique_lock<std::mutex> lock(state.mutex);
          state.changed.wait(lock, [&state, next]() {
            return state.failed || state.ready.find(next)!=state.ready.end()
                || (state.input_done && next==state.frame_count);
          });
          if (state.failed) break;
          std::map<uint64_t, std::shared_ptr<KeepVaultPipeFrame> >::iterator found=
              state.ready.find(next);
          if (found==state.ready.end()) {
            if (state.input_done && next==state.frame_count) break;
            continue;
          }
          frame=found->second;
          state.ready.erase(found);
        }

        for (size_t si=0; si<frame->segments.size(); ++si) {
          KeepVaultPipeSegment& segment=*frame->segments[si];
	          if (segment.filename!="" || first_segment) {
	            if (outf!=FPNULL) {
	              close_output(outf, output_name, date);
	            }
            if (segment.filename=="")
              throw std::runtime_error("first streaming segment has no filename");
            for (unsigned i=0; i<segment.filename.size(); ++i)
              if (segment.filename[i]=='\\') segment.filename[i]='/';
            selected=isselected(segment.filename.c_str(), false);
            output_name=rename(segment.filename.c_str());
	            if (!safe_archive_member_path(output_name))
	              throw std::runtime_error("unsafe renamed archive member path");
	            const string member_key=keepvault_canonical_output_path(output_name);
	            if (!published_names.insert(member_key).second)
	              throw std::runtime_error("duplicate or conflicting streaming archive member");
	            keepvault_reserve_output_entries(
	                output_name, output_entries, keepvault_max_extracted_files);
	            current_file_bytes=0;
	            if (selected) {
              if (!list_only
#ifdef unix
                  && g_keepvault_output_root_fd<0
#endif
                  && exists(output_name))
                throw std::runtime_error("duplicate or conflicting streaming archive member");
              if (summary<=0) {
                printf("> ");
                printUTF8(output_name.c_str());
                printf("\n");
              }
              if (!list_only && !dotest) {
                if (output_name[output_name.size()-1]=='/') {
#ifdef unix
                  if (g_keepvault_output_root_fd>=0)
                    keepvault_secure_makepath(output_name, date, 0);
                  else
#endif
                    makepath(output_name, date, 0);
                }
                else {
#ifdef unix
                  if (g_keepvault_output_root_fd>=0) {
                    keepvault_secure_makepath(output_name);
                    outf=keepvault_secure_open_output(output_name, true);
                  }
                  else {
#endif
                    makepath(output_name);
                    outf=fopen(output_name.c_str(), WB);
#ifdef unix
                  }
#endif
                  if (outf==FPNULL) {
                    printerr(output_name.c_str());
                    throw std::runtime_error("cannot create streaming output file");
                  }
                }
              }
              ++files_extracted;
            }
          }

          if (selected && output_name[output_name.size()-1]=='/'
              && !segment.data.empty())
            throw std::runtime_error("directory streaming member contains file data");
	          const uint64_t segment_bytes=uint64_t(segment.data.size());
	          if (segment_bytes>keepvault_max_single_file_bytes-current_file_bytes)
	            throw std::runtime_error("v12 pipe archive exceeds the single-file extraction limit");
	          if (segment_bytes>keepvault_max_extracted_bytes-archive_total_bytes)
	            throw std::runtime_error("v12 pipe archive exceeds the total extraction limit");
	          if (selected && !list_only && !dotest && outf!=FPNULL
	              && !segment.data.empty()
	              && fwrite(&segment.data[0], 1, segment.data.size(), outf)!=segment.data.size())
	            throw std::runtime_error("output write failed");
	          current_file_bytes+=segment_bytes;
	          archive_total_bytes+=segment_bytes;
	          keepvault_wipe_vector(segment.data);
          first_segment=false;
          ++segments;
        }

        frame->segments.clear();
        frame->processing_memory.reset();
        {
          std::lock_guard<std::mutex> guard(state.mutex);
          --state.inflight;
          ++next;
          state.changed.notify_all();
        }
	      }
	      if (outf!=FPNULL) {
	        close_output(outf, output_name, date);
	      }
    }
    catch (const std::exception& e) {
      if (outf!=FPNULL) fclose(outf);
      keepvault_pipe_fail(state, e.what());
    }
    catch (...) {
      if (outf!=FPNULL) fclose(outf);
      keepvault_pipe_fail(state, "unknown v12 pipe writer failure");
    }
    });
  }
  catch (const std::exception& e) {
    keepvault_pipe_fail(state, e.what());
  }
  catch (...) {
    keepvault_pipe_fail(state, "unable to start v12 pipe writer");
  }
  if (state.failed) {
    for (size_t i=0; i<workers.size(); ++i) workers[i].join();
    error(state.failure.c_str());
  }

  uint64_t sequence=0;
  try {
    for (;;) {
      char encoded_length[8];
      if (!keepvault_pipe_read_exact(in, encoded_length, sizeof(encoded_length)))
        throw std::runtime_error("v12 pipe archive is truncated before a frame length");
      const uint64_t length=keepvault_pipe_read_u64(encoded_length);
      if (length==0) break;
      if (length>KEEPVAULT_PIPE_MAX_COMPRESSED)
        throw std::runtime_error("v12 pipe frame exceeds compressed-size limit");
      if (sequence>=MAX_ARCHIVE_FRAGMENTS)
        throw std::runtime_error("v12 pipe archive has too many frames");

      std::shared_ptr<KeepVaultPipeFrame> frame(new KeepVaultPipeFrame(sequence));
      bool accounted=false;
      try {
        {
          std::unique_lock<std::mutex> lock(state.mutex);
          state.changed.wait(lock, [&state, length]() {
            return state.failed
                || (state.inflight<state.capacity
                    && state.compressed_bytes
                        <=KEEPVAULT_PIPE_PENDING_COMPRESSED_BUDGET-length);
          });
          if (state.failed) throw std::runtime_error(state.failure);
          ++state.inflight;
          state.compressed_bytes+=length;
          frame->compressed_accounted=length;
          accounted=true;
        }

        frame->compressed.resize(size_t(length));
        if (!keepvault_pipe_read_exact(in, &frame->compressed[0], size_t(length)))
          throw std::runtime_error("v12 pipe archive is truncated inside a frame");
        {
          std::lock_guard<std::mutex> guard(state.mutex);
          if (state.failed) throw std::runtime_error(state.failure);
          state.pending.push_back(frame);
          state.changed.notify_all();
          accounted=false;  // worker/writer now own both counters
        }
      }
      catch (...) {
        if (accounted) {
          std::lock_guard<std::mutex> guard(state.mutex);
          if (frame->compressed_accounted>state.compressed_bytes
              || state.inflight<1)
            throw std::runtime_error("v12 pipe reader-memory accounting underflow");
          state.compressed_bytes-=frame->compressed_accounted;
          frame->compressed_accounted=0;
          --state.inflight;
          state.changed.notify_all();
        }
        throw;
      }
      ++sequence;
    }
    char trailing;
    if (in.read(&trailing, 1)!=0)
      throw std::runtime_error("v12 pipe archive has data after its terminator");
  }
  catch (const std::exception& e) {
    keepvault_pipe_fail(state, e.what());
  }
  catch (...) {
    keepvault_pipe_fail(state, "unknown v12 pipe reader failure");
  }

  {
    std::lock_guard<std::mutex> guard(state.mutex);
    state.frame_count=sequence;
    state.input_done=true;
    state.changed.notify_all();
  }
  for (size_t i=0; i<workers.size(); ++i) workers[i].join();
  writer.join();

  if (state.failed) error(state.failure.c_str());
  if (segments==0) error("archive contains no data");
  printf("%u v12 parallel streaming segments in %u files %s\n",
      segments, files_extracted, list_only ? "listed" : "extracted");
  return 0;
}

// Copy at most n bytes from in to out (default all). Return how many copied.
int64_t copy(libzpaq::Reader& in, libzpaq::Writer& out, uint64_t n=~0ull) {
  const unsigned BUFSIZE=4096;
  int64_t result=0;
  char buf[BUFSIZE];
  while (n>0) {
    const int nc=n>BUFSIZE ? int(BUFSIZE) : int(n);
    int nr=in.read(buf, nc);
    if (nr<1) break;
    out.write(buf, nr);
    result+=nr;
    n-=nr;
  }
  return result;
}

// Extract files from archive. If force is true then overwrite
// existing files and set the dates and attributes of exising directories.
// Otherwise create only new files and directories. Return 1 if error else 0.
int Jidac::extract() {

  if (g_pipe_archive && archive=="-")
    return extract_pipe_streaming();

  // Encrypt or decrypt whole archive
  if (repack && all) {
    if (files.size()>0 || tofiles.size()>0 || onlyfiles.size()>0
        || noattributes || version!=DEFAULT_VERSION || method!="")
      error("-repack -all does not allow partial copy");
    InputArchive in(archive.c_str(), password);
    if (force) delete_file(repack);
    if (exists(repack)) error("output file exists");

    // Get key and salt
    char salt[32]={0};
    if (new_password) libzpaq::random(salt, 32);

    // Copy
    OutputArchive out(repack, new_password, salt, 0);
    copy(in, out);
    printUTF8(archive.c_str());
    printf(" %1.0f ", in.tell()+.0);
    printUTF8(repack);
    printf(" -> %1.0f\n", out.tell()+.0);
    out.close();
    return 0;
  }

  // Read archive
  const int64_t sz=read_archive(archive.c_str());
  if (sz<1) error("archive not found");

  // test blocks
  for (unsigned i=0; i<block.size(); ++i) {
    if (block[i].bsize<0) error("negative block size");
    if (block[i].start<1) error("block starts at fragment 0");
    if (block[i].start>=ht.size()) error("block start too high");
    if (i>0 && block[i].start<block[i-1].start) error("unordered frags");
    if (i>0 && block[i].start==block[i-1].start) error("empty block");
    if (i>0 && block[i].offset<block[i-1].offset+block[i-1].bsize)
      error("unordered blocks");
    if (i>0 && block[i-1].offset+block[i-1].bsize>block[i].offset)
      error("overlapping blocks");
  }

  // Create index instead of extract files
  if (index) {
    if (ver.size()<2) error("no journaling data");
    if (force) delete_file(index);
    if (exists(index)) error("index file exists");

    // Get salt
    char salt[32];
    if (ver[1].offset==32) {  // encrypted?
      FP fp=fopen(subpart(archive, 1).c_str(), RB);
      if (fp==FPNULL) error("cannot read part 1");
      if (fread(salt, 1, 32, fp)!=32) error("cannot read salt");
      salt[0]^='7'^'z';  // for index
      fclose(fp);
    }
    InputArchive in(archive.c_str(), password);
    OutputArchive out(index, password, salt, 0);
    for (unsigned i=1; i<ver.size(); ++i) {
      if (in.tell()!=ver[i].offset) error("I'm lost");

      // Read C block. Assume uncompressed and hash is present
      static char hdr[256]={0};  // Read C block
      const int64_t header_size=ver[i].data_offset-ver[i].offset;
      if (header_size<70 || header_size>255) error("bad C block size");
      const int hsize=int(header_size);
      if (in.read(hdr, hsize)!=hsize) error("EOF in header");
      if (hdr[hsize-36]!=9  // size of uncompressed block low byte
          || (hdr[hsize-22]&255)!=253  // start of SHA1 marker
          || (hdr[hsize-1]&255)!=255) {  // end of block marker
        for (int j=0; j<hsize; ++j)
          printf("%d%c", hdr[j]&255, j%10==9 ? '\n' : ' ');
        printf("at %1.0f\n", ver[i].offset+.0);
        error("C block in weird format");
      }
      memcpy(hdr+hsize-34, 
          "\x00\x00\x00\x00\x00\x00\x00\x00"  // csize = 0
          "\x00\x00\x00\x00"  // compressed data terminator
          "\xfd"  // start of hash marker
          "\x05\xfe\x40\x57\x53\x16\x6f\x12\x55\x59\xe7\xc9\xac\x55\x86"
          "\x54\xf1\x07\xc7\xe9"  // SHA-1('0'*8)
          "\xff", 34);  // EOB
      out.write(hdr, hsize);
      in.seek(ver[i].csize, SEEK_CUR);  // skip D blocks
      int64_t end=sz;
      if (i+1<ver.size()) end=ver[i+1].offset;
      int64_t n=end-in.tell();
      if (copy(in, out, n)!=n) error("EOF");  // copy H and I blocks
    }
    printUTF8(index);
    printf(" -> %1.0f\n", out.tell()+.0);
    out.close();
    return 0;
  }

  // Label files to extract with data=0.
  // Skip existing output files. If force then skip only if equal
  // and set date and attributes.
  ExtractJob job(*this);
  for (unsigned i=0; i<block.size(); ++i) {
    if (block[i].start==0 || block[i].start>=ht.size()
        || (i>0 && block[i].start<=block[i-1].start))
      error("invalid archive block table");
  }
  int total_files=0, skipped=0;
  std::map<string, string> planned_output_entries;
  for (DTMap::iterator p=dt.begin(); p!=dt.end(); ++p) {
    p->second.data=-1;  // skip
    if (p->second.date && p->first!="") {
      const string fn=rename(p->first);
      const bool isdir=p->first[p->first.size()-1]=='/';
      if (!repack && !dotest && force && !isdir && equal(p, fn.c_str())) {
        if (summary<=0) {  // identical
          printf("= ");
          printUTF8(fn.c_str());
          printf("\n");
        }
        close(fn.c_str(), p->second.date, p->second.attr);
        ++skipped;
      }
      else if (!repack && !dotest && !force
#ifdef unix
          && g_keepvault_output_root_fd<0
#endif
          && exists(fn)) {  // exists, skip
        if (summary<=0) {
          printf("? ");
          printUTF8(fn.c_str());
          printf("\n");
        }
        ++skipped;
      }
      else if (isdir) {  // update directories later
        keepvault_reserve_output_entries(
            fn, planned_output_entries, keepvault_max_extracted_files);
        p->second.data=0;
      }
      else if (block.size()>0) {  // files to decompress
	        if (p->second.size<0
	            || uint64_t(p->second.size)>keepvault_max_single_file_bytes)
	          error("archive exceeds the single-file extraction limit");
	        if (job.total_size<0 || uint64_t(p->second.size)>
	            keepvault_max_extracted_bytes-uint64_t(job.total_size))
	          error("archive exceeds the total extraction limit");
	        uint64_t reconstructed_size=0;
	        for (unsigned fragment=0; fragment<p->second.ptr.size(); ++fragment) {
	          const unsigned fragment_index=p->second.ptr[fragment];
	          if (fragment_index==0 || fragment_index>=ht.size()
	              || ht[fragment_index].usize<0
	              || uint64_t(ht[fragment_index].usize)>
	                 uint64_t(p->second.size)-reconstructed_size)
	            error("archive file has inconsistent fragment sizes");
	          reconstructed_size+=uint64_t(ht[fragment_index].usize);
	        }
	        if (reconstructed_size!=uint64_t(p->second.size))
	          error("archive file size does not match its fragments");
	        keepvault_reserve_output_entries(
	            fn, planned_output_entries, keepvault_max_extracted_files);
	        p->second.data=0;
        unsigned lo=0, hi=block.size()-1;  // block indexes for binary search
        for (unsigned i=0; p->second.data>=0 && i<p->second.ptr.size(); ++i) {
          unsigned j=p->second.ptr[i];  // fragment index
          if (j==0 || j>=ht.size() || ht[j].usize<-1) {
            fflush(stdout);
            printUTF8(p->first.c_str(), stderr);
            fprintf(stderr, ": bad frag IDs, skipping...\n");
            p->second.data=-1;  // skip
            continue;
          }
          if (lo!=hi || lo>=block.size() || j<block[lo].start
              || (lo+1<block.size() && j>=block[lo+1].start)) {
            lo=0;  // find block with fragment j by binary search
            hi=block.size()-1;
            while (lo<hi) {
              unsigned mid=(lo+hi+1)/2;
              assert(mid>lo);
              assert(mid<=hi);
              if (j<block[mid].start) hi=mid-1;
              else (lo=mid);
            }
          }
          if (lo!=hi || lo>=block.size() || j<block[lo].start
              || (lo+1<block.size() && j>=block[lo+1].start)) {
            fflush(stdout);
            printUTF8(p->first.c_str(), stderr);
            fprintf(stderr, ": inconsistent block table, skipping...\n");
            p->second.data=-1;
            continue;
          }
          unsigned c=j-block[lo].start+1;
          if (uint64_t(block[lo].start)+c>ht.size()) {
            p->second.data=-1;
            continue;
          }
          if (block[lo].size<c) block[lo].size=c;
          if (block[lo].files.size()==0 || block[lo].files.back()!=p)
            block[lo].files.push_back(p);
        }
        ++total_files;
        job.total_size+=p->second.size;
      }
    }  // end if selected
  }  // end for
  if (!force && skipped>0)
    printf("%d ?existing files skipped (-force overwrites).\n", skipped);
  if (force && skipped>0)
    printf("%d =identical files skipped.\n", skipped);

  // Repack to new archive
  if (repack) {

    // Get total D block size
    if (ver.size()<2) error("cannot repack streaming archive");
    int64_t csize=0;  // total compressed size of D blocks
    for (unsigned i=0; i<block.size(); ++i) {
      if (block[i].bsize<1) error("empty block");
      if (block[i].size>0) csize+=block[i].bsize;
    }

    // Open input
    InputArchive in(archive.c_str(), password);

    // Open output
    if (!force && exists(repack)) error("repack output exists");
    delete_file(repack);
    char salt[32]={0};
    if (new_password) libzpaq::random(salt, 32);
    OutputArchive out(repack, new_password, salt, 0);
    int64_t cstart=out.tell();

    // Write C block using first version date
    writeJidacHeader(&out, ver[1].date, -1, 1);
    int64_t dstart=out.tell();

    // Copy only referenced D blocks. If method then recompress.
    for (unsigned i=0; i<block.size(); ++i) {
      if (block[i].size>0) {
        in.seek(block[i].offset, SEEK_SET);
        copy(in, out, block[i].bsize);
      }
    }
    printf("Data %1.0f -> ", csize+.0);
    csize=out.tell()-dstart;
    printf("%1.0f\n", csize+.0);

    // Re-create referenced H blocks using latest date
    for (unsigned i=0; i<block.size(); ++i) {
      if (block[i].size>0) {
        StringBuffer is;
        puti(is, block[i].bsize, 4);
        for (unsigned j=0; j<block[i].frags; ++j) {
          const unsigned k=block[i].start+j;
          if (k<1 || k>=ht.size()) error("frag out of range");
          is.write((const char*)ht[k].sha1, 20);
          puti(is, ht[k].usize, 4);
        }
        libzpaq::compressBlock(&is, &out, "0",
            ("jDC"+itos(ver.back().date, 14)+"h"
            +itos(block[i].start, 10)).c_str(),
            "jDC\x01");
      }
    }

    // Append I blocks of selected files
    unsigned dtcount=0;
    StringBuffer is;
    for (DTMap::iterator p=dt.begin();; ++p) {
      if (p!=dt.end() && p->second.date>0 && p->second.data>=0) {
        string filename=rename(p->first);
        puti(is, p->second.date, 8);
        if (filename.size()>INT_MAX) error("filename too long");
        is.write(filename.c_str(), int(filename.size()));
        is.put(0);
        if ((p->second.attr&255)=='u') {  // unix attributes
          puti(is, 3, 4);
          puti(is, p->second.attr, 3);
        }
        else if ((p->second.attr&255)=='w') {  // windows attributes
          puti(is, 5, 4);
          puti(is, p->second.attr, 5);
        }
        else puti(is, 0, 4);  // no attributes
        puti(is, p->second.ptr.size(), 4);  // list of frag pointers
        for (unsigned i=0; i<p->second.ptr.size(); ++i)
          puti(is, p->second.ptr[i], 4);
      }
      if (is.size()>16000 || (is.size()>0 && p==dt.end())) {
        libzpaq::compressBlock(&is, &out, "1",
            ("jDC"+itos(ver.back().date)+"i"+itos(++dtcount, 10)).c_str(),
            "jDC\x01");
        is.secureClear();
      }
      if (p==dt.end()) break;
    }

    // Summarize result
    printUTF8(archive.c_str());
    printf(" %1.0f -> ", sz+.0);
    printUTF8(repack);
    printf(" %1.0f\n", out.tell()+.0);

    // Rewrite C block
    out.seek(cstart, SEEK_SET);
    writeJidacHeader(&out, ver[1].date, csize, 1);
    out.close();
    return 0;
  }

  // Decompress archive in parallel
  const int regular_workers=int(min(
      uint64_t(threads),
      KEEPVAULT_NATIVE_PROCESSING_BUDGET/KEEPVAULT_REGULAR_JOB_RESERVATION));
  if (regular_workers<1) error("native regular-extraction memory budget permits no workers");
  printf("Extracting %1.6f MB in %d files -threads %d\n",
      job.total_size/1000000.0, total_files, regular_workers);
  vector<ThreadID> tid(regular_workers);
  for (unsigned i=0; i<tid.size(); ++i) run(tid[i], decompressThread, &job);

  // Extract streaming files
  unsigned segments=0;  // count
  InputArchive in(archive.c_str(), password);
  if (in.isopen()) {
    FP outf=FPNULL;
    DTMap::iterator dtptr=dt.end();
    const auto close_stream_output = [this, &dtptr](FP& stream) {
      if (stream==FPNULL) return;
      if (dtptr==dt.end()) error("streaming output lost its bound manifest entry");
      FP closing=stream;
      stream=FPNULL;
      const string path=rename(dtptr->first);
#ifdef unix
      if (g_keepvault_output_root_fd>=0)
        keepvault_secure_close(path, 0, 0, closing);
      else
#endif
        close(path.c_str(), 0, 0, closing);
    };
    for (unsigned i=0; i<block.size(); ++i) {
      if (block[i].usize<0 && block[i].size>0) {
        Block& b=block[i];
        try {
          in.seek(b.offset, SEEK_SET);
          std::unique_ptr<libzpaq::Decompresser> d(new libzpaq::Decompresser());
          d->setInput(&in);
          if (!d->findBlock()) error("block not found");
          StringWriter filename(KEEPVAULT_MAX_ARCHIVE_MEMBER_NAME_BYTES);
          for (unsigned j=0; j<b.size; ++j) {
            if (!d->findFilename(&filename)) error("segment not found");
            d->readComment();

            // Start of new output file
            if (filename.s!="" || segments==0) {
              unsigned k;
              for (k=0; k<b.files.size(); ++k) {  // find in dt
                if (b.files[k]->second.ptr.size()>0
                    && b.files[k]->second.ptr[0]==b.start+j
                    && b.files[k]->second.date>0
                    && b.files[k]->second.data==0)
                  break;
              }
              if (k<b.files.size()) {  // found new file
                close_stream_output(outf);
                string outname=rename(b.files[k]->first);
                dtptr=b.files[k];
                lock(job.mutex);
                if (summary<=0) {
                  printf("> ");
                  printUTF8(outname.c_str());
                  printf("\n");
                }
                if (!dotest) {
#ifdef unix
                  if (g_keepvault_output_root_fd>=0) {
                    keepvault_secure_makepath(outname);
                    outf=keepvault_secure_open_output(outname, true);
                  }
                  else {
#endif
                    makepath(outname);
                    outf=fopen(outname.c_str(), WB);
#ifdef unix
                  }
#endif
                  if (outf==FPNULL) printerr(outname.c_str());
                }
                release(job.mutex);
              }
              else {  // end of file
                close_stream_output(outf);
                dtptr=dt.end();
              }
            }

            // Decompress segment
            libzpaq::SHA1 sha1;
            d->setSHA1(&sha1);
            OutputFile o(outf);
            d->setOutput(&o);
            d->decompress();

            // Verify checksum
            char sha1result[21];
            d->readSegmentEnd(sha1result);
            if (sha1result[0]!=1)
              error("regular streaming segment has no checksum");
            if (memcmp(sha1result+1, sha1.result(), 20)!=0)
              error("checksum failed");
            ++b.extracted;
            if (dtptr!=dt.end()) ++dtptr->second.data;
            filename.s="";
            ++segments;
          }
        }
        catch(std::exception& e) {
          if (outf!=FPNULL) {
            if (keepvault_checked_fclose(outf)!=0)
              fprintf(stderr, "output close or flush failed while abandoning a block\n");
            outf=FPNULL;
            dtptr=dt.end();
          }
          lock(job.mutex);
          ++job.io_errors;
          printf("Skipping block: %s\n", e.what());
          release(job.mutex);
        }
      }
    }
    if (outf!=FPNULL) {
      try {
        close_stream_output(outf);
      }
      catch (const std::exception& e) {
        ++job.io_errors;
        fprintf(stderr, "output close or flush failed: %s\n", e.what());
      }
    }
  }
  if (segments>0) printf("%u streaming segments extracted\n", segments);

  // Wait for threads to finish
  for (unsigned i=0; i<tid.size(); ++i) join(tid[i]);

  // Create empty directories and set file dates and attributes
  if (!dotest) {
    for (DTMap::reverse_iterator p=dt.rbegin(); p!=dt.rend(); ++p) {
      if (p->second.data>=0 && p->second.date && p->first!="") {
        string s=rename(p->first);
        if (p->first[p->first.size()-1]=='/')
        {
#ifdef unix
          if (g_keepvault_output_root_fd>=0)
            keepvault_secure_makepath(s, p->second.date, p->second.attr);
          else
#endif
            makepath(s, p->second.date, p->second.attr);
        }
        else if ((p->second.attr&0x1ff)=='w'+256)  // read-only?
        {
#ifdef unix
          if (g_keepvault_output_root_fd>=0)
            keepvault_secure_close(s, 0, p->second.attr);
          else
#endif
            close(s.c_str(), 0, p->second.attr);
        }
      }
    }
  }

  // Report failed extractions
  unsigned extracted=0, errors=0;
  for (DTMap::iterator p=dt.begin(); p!=dt.end(); ++p) {
    string fn=rename(p->first);
    if (p->second.data>=0 && p->second.date
        && fn!="" && fn[fn.size()-1]!='/') {
      ++extracted;
      if (p->second.ptr.size()!=unsigned(p->second.data)) {
        fflush(stdout);
        if (++errors==1)
          fprintf(stderr,
          "\nFailed (extracted/total fragments, file):\n");
        fprintf(stderr, "%u/%u ",
                unsigned(p->second.data), unsigned(p->second.ptr.size()));
        printUTF8(fn.c_str(), stderr);
        fprintf(stderr, "\n");
      }
    }
  }
  if (errors>0 || job.io_errors>0) {
    fflush(stdout);
    fprintf(stderr,
        "\nExtracted %u of %u files OK (%u content errors, %u I/O errors)"
        " using %1.3f MB x %d threads\n",
        extracted-errors, extracted, errors, job.io_errors, job.maxMemory/1000000,
        int(tid.size()));
  }
  return errors>0 || job.io_errors>0;
}

/////////////////////////////// list //////////////////////////////////

// Return p<q for sorting files by decreasing size, then fragment ID list
bool compareFragmentList(DTMap::const_iterator p, DTMap::const_iterator q) {
  if (p->second.size!=q->second.size) return p->second.size>q->second.size;
  if (p->second.ptr<q->second.ptr) return true;
  if (q->second.ptr<p->second.ptr) return false;
  if (p->second.data!=q->second.data) return p->second.data<q->second.data;
  return p->first<q->first;
}

// Return p<q for sort by name and comparison result
bool compareName(DTMap::const_iterator p, DTMap::const_iterator q) {
  if (p->first!=q->first) return p->first<q->first;
  return p->second.data<q->second.data;
}

// List contents
int Jidac::list() {

  if (g_pipe_archive && archive=="-")
    return extract_pipe_streaming(true);

  // Read archive into dt, which may be "" for empty.
  int64_t csize=0;
  if (archive!="") csize=read_archive(archive.c_str());
  if (archive!="" && (csize<1 || (ver.size()<2 && dt.empty())))
    error("archive contains no complete version or streaming segment");

  // Read external files into edt
  for (unsigned i=0; i<files.size(); ++i)
    scandir(files[i].c_str());
  if (files.size()) printf("%d external files.\n", int(edt.size()));
  printf("\n");

  // Compute directory sizes as the sum of their contents
  DTMap* dp[2]={&dt, &edt};
  for (int i=0; i<2; ++i) {
    for (DTMap::iterator p=dp[i]->begin(); p!=dp[i]->end(); ++p) {
      const size_t len=p->first.size();
      if (len>0 && p->first[len-1]!='/') {
        for (size_t j=0; j<len; ++j) {
          if (p->first[j]=='/') {
            DTMap::iterator q=dp[i]->find(p->first.substr(0, j+1));
            if (q!=dp[i]->end())
              q->second.size+=p->second.size;
          }
        }
      }
    }
  }

  // Make list of files to list. List each external file preceded
  // by the matching internal file, if any. Then list any unmatched
  // internal files at the end.
  vector<DTMap::iterator> filelist;
  for (DTMap::iterator p=edt.begin(); p!=edt.end(); ++p) {
    DTMap::iterator a=dt.find(rename(p->first));
    if (a!=dt.end() && (all || a->second.date)) {
      a->second.data='-';
      filelist.push_back(a);
    }
    p->second.data='+';
    filelist.push_back(p);
  }
  for (DTMap::iterator a=dt.begin(); a!=dt.end(); ++a) {
    if (a->second.data!='-' && (all || a->second.date)) {
      a->second.data='-';
      filelist.push_back(a);
    }
  }

  // Sort
  if (summary>0)
    sort(filelist.begin(), filelist.end(), compareFragmentList);

  // List
  int64_t usize=0;
  unsigned matches=0, mismatches=0, internal=0, external=0,
           duplicates=0;  // counts
  for (unsigned fi=0;
       fi<filelist.size() && (summary<=0 || int(fi)<summary); ++fi) {
    DTMap::iterator p=filelist[fi];

    // Compare external files
    if (summary<=0 && p->second.data=='-' && fi+1<filelist.size()
        && filelist[fi+1]->second.data=='+') {
      DTMap::const_iterator p1=filelist[fi+1];
      if ((force && equal(p, p1->first.c_str()))
          || (!force && p->second.date==p1->second.date
              && p->second.size==p1->second.size
              && (!p->second.attr || !p1->second.attr
                  || p->second.attr==p1->second.attr))) {
        p->second.data='=';
        ++fi;
      }
      else
        p->second.data='#';
    }

    // Compare with previous file in summary
    if (summary>0 && fi>0 && p->second.date && p->first!=""
        && p->first[p->first.size()-1]!='/'
        && p->second.ptr.size()
        && filelist[fi-1]->second.ptr==p->second.ptr)
      p->second.data='^';

    if (p->second.data=='=') ++matches;
    if (p->second.data=='#') ++mismatches;
    if (p->second.data=='-') ++internal;
    if (p->second.data=='+') ++external;
    if (p->second.data=='^') ++duplicates;

    // List selected comparison results
    if (!strchr(nottype.c_str(), p->second.data)) {
      if (p->first!="" && p->first[p->first.size()-1]!='/')
        usize+=p->second.size;
      printf("%c %s %12.0f ", char(p->second.data),
          dateToString(p->second.date).c_str(), p->second.size+0.0);
      if (!noattributes)
        printf("%s ", attrToString(p->second.attr).c_str());
      printUTF8(p->first.c_str());
      if (summary<0) {  // frag pointers
        const vector<unsigned>& ptr=p->second.ptr;
        bool hyphen=false;
        for (int j=0; j<int(ptr.size()); ++j) {
          if (j==0 || j==int(ptr.size())-1 || ptr[j]!=ptr[j-1]+1
              || ptr[j]!=ptr[j+1]-1) {
            if (!hyphen) printf(" ");
            hyphen=false;
            printf("%d", ptr[j]);
          }
          else {
            if (!hyphen) printf("-");
            hyphen=true;
          }
        }
      }
      unsigned v;  // list version updates, deletes, compressed size
      if (all>0 && p->first.size()==all+1u && (v=atoi(p->first.c_str()))>0
          && v<ver.size()) {  // version info
        printf(" +%d -%d -> %1.0f", ver[v].updates, ver[v].deletes,
            (v+1<ver.size() ? ver[v+1].offset : csize)-ver[v].offset+0.0);
        if (summary<0)  // print fragment range
          printf(" %u-%u", ver[v].firstFragment,
              v+1<ver.size()?ver[v+1].firstFragment-1:unsigned(ht.size())-1);
      }
      printf("\n");
    }
  }  // end for i = each file version

  // Compute dedupe size
  int64_t ddsize=0, allsize=0;
  unsigned nfiles=0, nfrags=0, unknown_frags=0, refs=0;
  vector<bool> ref(ht.size());
  for (DTMap::const_iterator p=dt.begin(); p!=dt.end(); ++p) {
    if (p->second.date) {
      ++nfiles;
      for (unsigned j=0; j<p->second.ptr.size(); ++j) {
        unsigned k=p->second.ptr[j];
        if (k>0 && k<ht.size()) {
          ++refs;
          if (ht[k].usize>=0) allsize+=ht[k].usize;
          if (!ref[k]) {
            ref[k]=true;
            ++nfrags;
            if (ht[k].usize>=0) ddsize+=ht[k].usize;
            else ++unknown_frags;
          }
        }
      }
    }
  }

  // Print archive statistics
  printf("\n"
      "%1.6f MB of %1.6f MB (%d files) shown\n"
      "  -> %1.6f MB (%u refs to %u of %u frags) after dedupe\n"
      "  -> %1.6f MB compressed.\n",
       usize/1000000.0, allsize/1000000.0, nfiles, 
       ddsize/1000000.0, refs, nfrags, unsigned(ht.size())-1,
       (csize+dhsize-dcsize)/1000000.0);
  if (unknown_frags)
    printf("%d fragments have unknown size\n", unknown_frags);
  if (files.size())
    printf(
       "%d =same, %d #different, %d +external, %d -internal\n",
        matches, mismatches, external, internal);
  if (summary>0)
    printf("%d of largest %d files are ^duplicates\n",
        duplicates, summary);
  if (dhsize!=dcsize)  // index?
    printf("Note: %1.0f of %1.0f compressed bytes are in archive\n",
        dcsize+0.0, dhsize+0.0);
  return 0;
}

/////////////////////////////// main //////////////////////////////////

#ifdef unix
static void keepvault_write_creation_pipeline_self_test_source(
    const char* path) {
  FP source=fopen(path, WB);
  if (source==FPNULL) error("cannot create pipeline stdio self-test source");
  char data[8192];
  for (size_t i=0; i<sizeof(data); ++i) data[i]=char(i*37u+11u);
  if (fwrite(data, 1, sizeof(data), source)!=sizeof(data)) {
    fclose(source);
    error("cannot write pipeline stdio self-test source");
  }
  if (fclose(source)!=0)
    error("cannot close pipeline stdio self-test source");
}

static bool keepvault_run_creation_pipeline_stdio_fault(
    const char* archive, const char* source, bool inject_read) {
  keepvault_write_creation_pipeline_self_test_source(source);
  if (inject_read) g_keepvault_test_creation_read_error.store(EIO);
  else g_keepvault_test_close_error.store(EIO);
  const char* args[]={
    "zpaq", "a", archive, source, "-method", "s4", "-threads", "2"
  };
  bool rejected=false;
  try {
    Jidac jidac;
    rejected=jidac.doCommand(int(sizeof(args)/sizeof(args[0])), args)!=0;
  }
  catch (const std::exception& e) {
    rejected=strstr(e.what(), inject_read
        ? "creation input read failed" : "creation input close failed")!=NULL;
  }
  remove(source);
  remove(archive);
  const string with_extension=string(archive)+".zpaq";
  remove(with_extension.c_str());
  return rejected;
}

static int keepvault_creation_pipeline_stdio_self_test() {
  if (!keepvault_run_creation_pipeline_stdio_fault(
          "kv-pipeline-read-output", "kv-pipeline-read-source", true))
    error("creation pipeline accepted an injected fread failure");
  if (!keepvault_run_creation_pipeline_stdio_fault(
          "kv-pipeline-close-output", "kv-pipeline-close-source", false))
    error("creation pipeline accepted an injected fclose failure");
  fprintf(stderr,
      "creation_pipeline_fread_failure=joined\n"
      "creation_pipeline_fclose_failure=joined\n");
  return 0;
}
#endif

#if defined(__APPLE__) && defined(__MACH__)
static bool keepvault_expected_sandbox_denial(int error_code) {
  return error_code==EPERM || error_code==EACCES;
}

// Seatbelt does not revoke descriptors acquired before sandbox_init(3). The
// managed launcher therefore relies on this entry guard as a second boundary:
// only stdin/stdout/stderr may survive into either the parser or the canary.
static bool keepvault_close_all_non_stdio_descriptors() {
  DIR* directory=opendir("/dev/fd");
  if (!directory) return false;
  const int enumeration_fd=dirfd(directory);
  vector<int> inherited;
  errno=0;
  while (dirent* entry=readdir(directory)) {
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
    char* end=0;
    errno=0;
    const long value=strtol(entry->d_name, &end, 10);
    if (errno || !end || end==entry->d_name || *end || value<0
        || value>INT_MAX) {
      closedir(directory);
      return false;
    }
    if (value>2 && value!=enumeration_fd) inherited.push_back(int(value));
  }
  if (errno || closedir(directory)!=0) return false;
  for (size_t i=0; i<inherited.size(); ++i) {
    while (::close(inherited[i])!=0) {
      const int failure=errno;
      if (failure==EINTR) continue;
      if (failure!=EBADF) return false;
      break;
    }
  }

  directory=opendir("/dev/fd");
  if (!directory) return false;
  const int verification_fd=dirfd(directory);
  bool clean=true;
  errno=0;
  while (dirent* entry=readdir(directory)) {
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
    char* end=0;
    errno=0;
    const long value=strtol(entry->d_name, &end, 10);
    if (errno || !end || end==entry->d_name || *end || value<0
        || value>INT_MAX || (value>2 && value!=verification_fd)) {
      clean=false;
      break;
    }
  }
  if (errno || closedir(directory)!=0) clean=false;
  return clean;
}

static bool keepvault_parse_canary_number(
    const char* text, long minimum, long maximum, long& result) {
  errno=0;
  char* end=0;
  const long parsed=strtol(text, &end, 10);
  if (errno || !end || end==text || *end || parsed<minimum || parsed>maximum)
    return false;
  result=parsed;
  return true;
}

static bool keepvault_canary_denied_read(const char* path) {
  errno=0;
  const int fd=open(path, O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
  if (fd>=0) {
    ::close(fd);
    return false;
  }
  return keepvault_expected_sandbox_denial(errno);
}

static bool keepvault_canary_denied_write(const char* path) {
  errno=0;
  const int fd=open(path, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW, 0600);
  if (fd>=0) {
    ::close(fd);
    unlink(path);
    return false;
  }
  return keepvault_expected_sandbox_denial(errno);
}

static bool keepvault_canary_denied_tcp_connect(int port) {
  const int fd=socket(AF_INET, SOCK_STREAM, 0);
  if (fd<0) return false;
  sockaddr_in address;
  memset(&address, 0, sizeof(address));
  address.sin_family=AF_INET;
  address.sin_port=htons(static_cast<uint16_t>(port));
  address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  errno=0;
  const int result=connect(fd, reinterpret_cast<sockaddr*>(&address),
      sizeof(address));
  const int failure=errno;
  ::close(fd);
  return result<0 && keepvault_expected_sandbox_denial(failure);
}

static bool keepvault_canary_denied_unix_connect(const char* path) {
  if (!path || strlen(path)>=sizeof(sockaddr_un::sun_path)) return false;
  const int fd=socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd<0) return false;
  sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family=AF_UNIX;
  memcpy(address.sun_path, path, strlen(path)+1);
  errno=0;
  const int result=connect(fd, reinterpret_cast<sockaddr*>(&address),
      sizeof(address));
  const int failure=errno;
  ::close(fd);
  return result<0 && keepvault_expected_sandbox_denial(failure);
}

static bool keepvault_canary_denied_fork() {
  errno=0;
  const pid_t child=fork();
  if (child==0) _exit(91);
  if (child>0) {
    kill(child, SIGKILL);
    while (waitpid(child, 0, 0)<0 && errno==EINTR) {}
    return false;
  }
  return keepvault_expected_sandbox_denial(errno);
}

static bool keepvault_canary_denied_spawn(const char* executable) {
  pid_t child=-1;
  char* const spawn_argv[]={const_cast<char*>(executable), 0};
  char* const empty_environment[]={0};
  const int result=posix_spawn(
      &child, executable, 0, 0, spawn_argv, empty_environment);
  if (result==0) {
    kill(child, SIGKILL);
    while (waitpid(child, 0, 0)<0 && errno==EINTR) {}
    return false;
  }
  return keepvault_expected_sandbox_denial(result);
}

static bool keepvault_canary_allowed_exact_shm(const char* name) {
  if (!keepvault_valid_verified_shm_name(name)) return false;
  const int fd=shm_open(name, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
  if (fd<0) return false;
  struct stat status;
  const bool valid=fcntl(fd, F_SETFD, FD_CLOEXEC)==0
      && fstat(fd, &status)==0 && S_ISREG(status.st_mode)
      && status.st_uid==geteuid() && (status.st_mode&0777)==0600
      && status.st_nlink==1;
  const bool removed=shm_unlink(name)==0;
  const bool closed=::close(fd)==0;
  return valid && removed && closed;
}

static bool keepvault_canary_denied_other_shm(const char* name) {
  if (!keepvault_valid_verified_shm_name(name)) return false;
  errno=0;
  const int fd=shm_open(name, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
  if (fd>=0) {
    shm_unlink(name);
    ::close(fd);
    return false;
  }
  return keepvault_expected_sandbox_denial(errno);
}

static int keepvault_sandbox_canary(int argc, const char** argv) {
  static const char* flags[]={
    "--keepvault-sandbox-canary", "--deny-read", "--deny-home-write",
    "--deny-tmp-write", "--tcp-port", "--unix-socket", "--exec",
    "--inherited-fd", "--shm-mode", "--allowed-shm", "--denied-shm"
  };
  if (argc!=22 || strcmp(argv[1], flags[0]) || strcmp(argv[2], flags[1])
      || strcmp(argv[4], flags[2]) || strcmp(argv[6], flags[3])
      || strcmp(argv[8], flags[4]) || strcmp(argv[10], flags[5])
      || strcmp(argv[12], flags[6]) || strcmp(argv[14], flags[7])
      || strcmp(argv[16], flags[8]) || strcmp(argv[18], flags[9])
      || strcmp(argv[20], flags[10])) {
    fprintf(stderr, "keepvault sandbox canary arguments rejected\n");
    return 64;
  }
  long port=0;
  long inherited_fd=0;
  if (!keepvault_parse_canary_number(argv[9], 1, 65535, port)
      || !keepvault_parse_canary_number(argv[15], 3, 1048575, inherited_fd)
      || strcmp(argv[13], "/usr/bin/true")
      || (strcmp(argv[17], "exact") && strcmp(argv[17], "none"))
      || !keepvault_valid_verified_shm_name(argv[19])
      || !keepvault_valid_verified_shm_name(argv[21])
      || !strcmp(argv[19], argv[21])) {
    fprintf(stderr, "keepvault sandbox canary values rejected\n");
    return 64;
  }
  errno=0;
  const bool inherited_closed=fcntl(int(inherited_fd), F_GETFD)==-1
      && errno==EBADF;
  const bool verified= inherited_closed
      && keepvault_canary_denied_read(argv[3])
      && keepvault_canary_denied_write(argv[5])
      && keepvault_canary_denied_write(argv[7])
      && keepvault_canary_denied_tcp_connect(int(port))
      && keepvault_canary_denied_unix_connect(argv[11])
      && keepvault_canary_denied_fork()
      && keepvault_canary_denied_spawn(argv[13])
      && (!strcmp(argv[17], "exact")
          ? keepvault_canary_allowed_exact_shm(argv[19])
          : keepvault_canary_denied_other_shm(argv[19]))
      && keepvault_canary_denied_other_shm(argv[21]);
  if (!verified) {
    fprintf(stderr, "keepvault sandbox canary enforcement failed\n");
    return 77;
  }
  fprintf(stderr, "keepvault_sandbox_canary=verified\n");
  return 0;
}

// This is deliberately a separate process from the fork/spawn canary above.
// It attempts execve(2) in the current process, so an EPERM/EACCES result proves
// the literal process-exec rule independently of process-fork enforcement. If
// Seatbelt ever permits the exec, /usr/bin/true replaces us and the required
// marker can no longer be emitted; the managed parent treats that as failure.
static int keepvault_sandbox_exec_canary(int argc, const char** argv) {
  if (argc!=4 || strcmp(argv[1], "--keepvault-sandbox-exec-canary")
      || strcmp(argv[2], "--exec") || strcmp(argv[3], "/usr/bin/true")) {
    fprintf(stderr, "keepvault sandbox exec canary arguments rejected\n");
    return 64;
  }
  char* const exec_argv[]={const_cast<char*>(argv[3]), 0};
  char* const empty_environment[]={0};
  errno=0;
  execve(argv[3], exec_argv, empty_environment);
  const int failure=errno;
  if (!keepvault_expected_sandbox_denial(failure)) {
    fprintf(stderr, "keepvault sandbox exec canary enforcement failed\n");
    return 77;
  }
  fprintf(stderr, "keepvault_sandbox_exec_canary=verified\n");
  return 0;
}

// A native posix_spawn harness maps an intentionally inheritable descriptor to
// this exact number. Entry has already executed the production descriptor guard;
// only EBADF is accepted. The ordinary application rejects this internal mode.
static int keepvault_inherited_fd_guard_canary(int argc, const char** argv) {
  if (argc!=3 || strcmp(argv[1], "--keepvault-inherited-fd-guard-canary")) {
    fprintf(stderr, "keepvault inherited-fd canary arguments rejected\n");
    return 64;
  }
  long descriptor=0;
  if (!keepvault_parse_canary_number(argv[2], 3, 1048575, descriptor)) {
    fprintf(stderr, "keepvault inherited-fd canary value rejected\n");
    return 64;
  }
  errno=0;
  if (fcntl(int(descriptor), F_GETFD)!=-1 || errno!=EBADF) {
    fprintf(stderr, "keepvault inherited descriptor closure failed\n");
    return 77;
  }
  fprintf(stderr, "keepvault_inherited_fd_guard=verified\n");
  return 0;
}
#elif defined(unix)
static bool keepvault_close_all_non_stdio_descriptors() {
  long maximum=sysconf(_SC_OPEN_MAX);
  if (maximum<4 || maximum>1048576) maximum=1048576;
  for (int fd=3; fd<maximum; ++fd) {
    while (::close(fd)!=0 && errno==EINTR) {}
  }
  for (int fd=3; fd<maximum; ++fd) {
    errno=0;
    if (fcntl(fd, F_GETFD)!=-1 || errno!=EBADF) return false;
  }
  return true;
}
#endif

// Convert argv to UTF-8 and replace \ with /
#ifdef unix
int main(int argc, const char** argv) {
#if defined(__APPLE__) && defined(__MACH__)
  if (!keepvault_close_all_non_stdio_descriptors()) {
    fprintf(stderr, "keepvault inherited descriptor closure failed\n");
    return 126;
  }
  if (argc>1 && !strcmp(argv[1], "--keepvault-sandbox-canary"))
    return keepvault_sandbox_canary(argc, argv);
  if (argc>1 && !strcmp(argv[1], "--keepvault-sandbox-exec-canary"))
    return keepvault_sandbox_exec_canary(argc, argv);
  if (argc>1 && !strcmp(argv[1], "--keepvault-inherited-fd-guard-canary"))
    return keepvault_inherited_fd_guard_canary(argc, argv);
#else
  if (!keepvault_close_all_non_stdio_descriptors()) {
    fprintf(stderr, "keepvault inherited descriptor closure failed\n");
    return 126;
  }
#endif
  if (argc==2 && !strcmp(argv[1], "--kv-self-test-root-identity-mismatch"))
    return keepvault_root_identity_mismatch_self_test();
  if (argc==2 && !strcmp(argv[1], "--kv-self-test-secure-output"))
    return keepvault_secure_output_self_test();
  if (argc==2 && !strcmp(argv[1], "--kv-self-test-stdio-failures")) {
    FP input=tmpfile();
    if (input==FPNULL) error("cannot create stdio failure self-test file");
    g_keepvault_test_creation_read_error.store(EIO);
    bool read_rejected=false;
    char byte=0;
    try {
      keepvault_read_creation_input(&byte, 1, input);
    }
    catch (const std::exception&) {
      read_rejected=true;
    }
    if (!read_rejected) error("injected creation read failure was accepted");
    g_keepvault_test_close_error.store(EIO);
    if (keepvault_checked_fclose(input)==0)
      error("injected close failure was accepted");
    fprintf(stderr,
        "creation_fread_failure=fail_closed\n"
        "output_fclose_failure=fail_closed\n");
    return 0;
  }
  if (argc==2 && !strcmp(argv[1], "--kv-self-test-creation-pipeline-stdio"))
    return keepvault_creation_pipeline_stdio_self_test();
  if (argc==2 && !strcmp(argv[1], "--kv-self-test-pthread-create-failure")) {
    g_keepvault_test_pthread_create_error.store(EAGAIN);
    ThreadID thread;
    run(thread, keepvault_thread_self_test_noop, NULL);
    return 70;
  }
  if (argc==2 && !strcmp(argv[1], "--kv-self-test-pthread-join-failure")) {
    ThreadID thread;
    run(thread, keepvault_thread_self_test_noop, NULL);
    g_keepvault_test_pthread_join_error.store(EINVAL);
    join(thread);
    return 70;
  }
  if (argc==2 && !strcmp(argv[1], "--kv-self-test-semaphore-spurious"))
    return keepvault_semaphore_spurious_wakeup_self_test();
#else
#ifdef _MSC_VER
int wmain(int argc, LPWSTR* argw) {
#else
int main() {
  int argc=0;
  LPWSTR* argw=CommandLineToArgvW(GetCommandLine(), &argc);
#endif
  vector<string> args(argc);
  libzpaq::Array<const char*> argp(argc);
  for (int i=0; i<argc; ++i) {
    args[i]=wtou(argw[i]);
    argp[i]=args[i].c_str();
  }
  const char** argv=&argp[0];
#endif

  global_start=mtime();  // get start time
  int errorcode=0;
  try {
    Jidac jidac;
    errorcode=jidac.doCommand(argc, argv);
  }
  catch (std::exception& e) {
    fflush(stdout);
    fprintf(stderr, "zpaq error: %s\n", e.what());
    errorcode=2;
  }
#ifdef unix
  if (g_verified_archive_fd>=0) {
    if (::close(g_verified_archive_fd)!=0 && errorcode<2) errorcode=2;
    g_verified_archive_fd=-1;
    g_verified_archive_size=0;
  }
  if (g_keepvault_output_root_fd>=0) {
    ::close(g_keepvault_output_root_fd);
    g_keepvault_output_root_fd=-1;
    g_keepvault_output_directories.clear();
    g_keepvault_output_files.clear();
  }
  keepvault_wipe_verified_shm_name();
#endif
  fflush(stdout);
  fprintf(stderr, "%1.3f seconds %s\n", (mtime()-global_start)/1000.0,
      errorcode>1 ? "(with errors)" :
      errorcode>0 ? "(with warnings)" : "(all OK)");
  return errorcode;
}
