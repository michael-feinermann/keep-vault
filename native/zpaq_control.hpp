#pragma once

#include <array>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace keepvault {

// Internal parent/child control channel, independent of every archive format.
// Exactly 48 header bytes, BE integers and <=1 MiB payload. Only the managed
// parent can grant work or supply source bytes; telemetry grants nothing.
enum class control_kind : std::uint32_t {
    cpu_acquire=1, cpu_release=2, source_entry=3, source_read=4,
    progress=5, output_window=6, memory_acquire=7, memory_release=8, close=9, output_complete=10
};
struct control_message {
    std::uint32_t kind=0;
    std::uint64_t sequence=0, a=0, b=0, c=0;
    std::vector<unsigned char> payload;
    control_message()=default;
    control_message(control_message&&)=default;
    control_message& operator=(control_message&&)=default;
    control_message(const control_message&)=delete;
    ~control_message() { volatile unsigned char* p=payload.data(); for(std::size_t n=payload.size();n;--n) *p++=0; }
};

class control_channel final {
    static constexpr std::size_t max_payload=1u<<20;
    struct pending {
        bool complete=false;
        control_message result;
        std::condition_variable changed;
    };
#ifdef _WIN32
    HANDLE handle_=INVALID_HANDLE_VALUE;
#else
    int handle_=-1;
#endif
    std::mutex gate_, write_gate_;
    std::map<std::uint64_t,std::shared_ptr<pending>> pending_;
    std::uint64_t sequence_=0;
    bool stopped_=false;
    bool orderly_closed_=false;
    std::thread reader_;
    const std::size_t maximum_pending_;

    static void put(unsigned char* p,std::uint64_t x,unsigned n) {
        for(unsigned i=0;i<n;++i) p[i]=static_cast<unsigned char>(x>>(8*(n-1-i)));
    }
    static std::uint64_t get(const unsigned char* p,unsigned n) {
        std::uint64_t x=0; for(unsigned i=0;i<n;++i) x=(x<<8)|p[i]; return x;
    }
    void transfer(void* data,std::size_t length,bool writing) {
        auto* p=static_cast<unsigned char*>(data);
        while(length) {
#ifdef _WIN32
            DWORD n=0;
            BOOL ok=writing?WriteFile(handle_,p,DWORD(length),&n,nullptr)
                           :ReadFile(handle_,p,DWORD(length),&n,nullptr);
            if(!ok || !n) throw std::runtime_error("native control channel I/O failed");
#else
            const ssize_t n=writing ? ::send(handle_,p,length,0) : ::recv(handle_,p,length,0);
            if(n<0 && errno==EINTR) continue;
            if(n<=0) throw std::runtime_error("native control channel I/O failed");
#endif
            p+=n; length-=std::size_t(n);
        }
    }
    void send(const control_message& m) {
        if(m.payload.size()>max_payload) throw std::runtime_error("oversize native control message");
        std::array<unsigned char,48> h{};
        std::memcpy(h.data(),"KV13CTL1",8);
        put(h.data()+8,m.kind,4); put(h.data()+12,m.payload.size(),4);
        put(h.data()+16,m.sequence,8); put(h.data()+24,m.a,8);
        put(h.data()+32,m.b,8); put(h.data()+40,m.c,8);
        transfer(h.data(),h.size(),true);
        if(!m.payload.empty()) transfer(const_cast<unsigned char*>(m.payload.data()),m.payload.size(),true);
    }
    void receive_loop() noexcept {
        try {
            for(;;) {
                std::array<unsigned char,48> h{}; transfer(h.data(),h.size(),false);
                if(std::memcmp(h.data(),"KV13CTL1",8)) throw std::runtime_error("invalid control magic");
                control_message m; m.kind=std::uint32_t(get(h.data()+8,4));
                const auto n=get(h.data()+12,4);
                if(n>max_payload || !(m.kind&0x80000000u)) throw std::runtime_error("invalid control response");
                m.sequence=get(h.data()+16,8);m.a=get(h.data()+24,8);
                m.b=get(h.data()+32,8);m.c=get(h.data()+40,8);
                m.payload.resize(std::size_t(n));if(n) transfer(m.payload.data(),std::size_t(n),false);
                std::lock_guard<std::mutex> lock(gate_);
                const auto entry=pending_.find(m.sequence);
                if(entry==pending_.end() || entry->second->complete)
                    throw std::runtime_error("unexpected control response identity");
                entry->second->result=std::move(m);entry->second->complete=true;
                entry->second->changed.notify_one();
            }
        } catch(...) { fail(); }
    }
    void fail() noexcept {
        std::lock_guard<std::mutex> lock(gate_);stopped_=true;
        for(auto& p:pending_) p.second->changed.notify_all();
    }
public:
    explicit control_channel(const std::string& address,std::uint64_t parent_pid,std::size_t maximum_pending)
        :maximum_pending_(maximum_pending) {
        if(!maximum_pending) throw std::runtime_error("invalid control request window");
#ifdef _WIN32
        std::wstring wide(address.begin(),address.end()); // generated ASCII pipe identifier only
        handle_=CreateFileW(wide.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);
        if(handle_==INVALID_HANDLE_VALUE) throw std::runtime_error("cannot connect native control pipe");
        ULONG peer=0;
        if(!GetNamedPipeServerProcessId(handle_,&peer) || peer!=parent_pid) {
            close_handle();throw std::runtime_error("native control parent identity mismatch");
        }
#else
        sockaddr_un a{};a.sun_family=AF_UNIX;
        if(address.empty() || address.size()>=sizeof(a.sun_path)) throw std::runtime_error("invalid control socket path");
        std::memcpy(a.sun_path,address.c_str(),address.size()+1);
        handle_=::socket(AF_UNIX,SOCK_STREAM,0);
        if(handle_<0) throw std::runtime_error("cannot create native control socket");
#ifdef SO_NOSIGPIPE
        const int yes=1;::setsockopt(handle_,SOL_SOCKET,SO_NOSIGPIPE,&yes,sizeof(yes));
#endif
        if(::connect(handle_,reinterpret_cast<sockaddr*>(&a),sizeof(a))!=0) {
            ::close(handle_);handle_=-1;throw std::runtime_error("cannot connect native control socket");
        }
#if defined(__APPLE__)
        pid_t peer=0; socklen_t peer_size=sizeof(peer);
        if(::getsockopt(handle_,0,2,&peer,&peer_size)!=0 || peer_size!=sizeof(peer)
                || peer!=::getppid() || std::uint64_t(peer)!=parent_pid) {
            close_handle();throw std::runtime_error("native control parent identity mismatch");
        }
#endif
#endif
        try {reader_=std::thread([this]{receive_loop();});}
        catch(...) {close_handle();throw;}
    }
    control_channel(const control_channel&)=delete;
    control_channel& operator=(const control_channel&)=delete;
    void close_handle() noexcept {
#ifdef _WIN32
        if(handle_!=INVALID_HANDLE_VALUE) {CancelIoEx(handle_,nullptr);CloseHandle(handle_);handle_=INVALID_HANDLE_VALUE;}
#else
        if(handle_>=0) {::shutdown(handle_,SHUT_RDWR);::close(handle_);handle_=-1;}
#endif
    }
    ~control_channel() {
        // Normal shutdown proves all native jobs have returned before the
        // parent drains its replies. Failure paths are terminated by the owner.
        if(!orderly_closed_)try { finish(); } catch(...) { }
#ifdef _WIN32
        if(reader_.joinable()) CancelSynchronousIo(reader_.native_handle());
        if(handle_!=INVALID_HANDLE_VALUE) CancelIoEx(handle_,nullptr);
#else
        if(handle_>=0) ::shutdown(handle_,SHUT_RDWR);
#endif
        if(reader_.joinable())reader_.join();
        close_handle();
    }
    void finish() {
        if(orderly_closed_)return;
        auto reply=request(control_kind::close);
        if(reply.a || reply.b || reply.c || !reply.payload.empty())throw std::runtime_error("invalid native close acknowledgment");
        orderly_closed_=true;
    }
    control_message request(control_kind kind,std::uint64_t a=0,std::uint64_t b=0,std::uint64_t c=0) {
        std::unique_lock<std::mutex> submission(write_gate_);
        auto wait=std::make_shared<pending>();
        control_message m;m.kind=std::uint32_t(kind);m.a=a;m.b=b;m.c=c;
        {
            std::lock_guard<std::mutex> lock(gate_);
            if(stopped_ || pending_.size()>=maximum_pending_ || sequence_==UINT64_MAX)
                throw std::runtime_error("native control request window exhausted");
            m.sequence=++sequence_;pending_.emplace(m.sequence,wait);
        }
        try {send(m);} catch(...) {fail();throw;}
        submission.unlock();
        std::unique_lock<std::mutex> lock(gate_);
        wait->changed.wait(lock,[&]{return stopped_||wait->complete;});
        pending_.erase(m.sequence);
        if(stopped_ || !wait->complete || wait->result.kind!=(m.kind|0x80000000u))
            throw std::runtime_error("native control request failed");
        return std::move(wait->result);
    }
};

// Scope ends BEFORE pipe reads/writes, queue waits or child joins. The returned
// grant id, not an advisory progress count, owns the parent's actual CPU lease.
class control_cpu_scope final {
    control_channel* channel_; std::uint64_t grant_=0;
    control_cpu_scope* previous_;
    inline static thread_local control_cpu_scope* current_=nullptr;
public:
    explicit control_cpu_scope(control_channel* channel):channel_(channel),previous_(current_) {
        if(previous_) throw std::runtime_error("nested native CPU scope");
        acquire(); current_=this;
    }
    void acquire() {
        if(channel_ && !grant_) {auto reply=channel_->request(control_kind::cpu_acquire);grant_=reply.a;
            if(!grant_ || reply.b || reply.c || !reply.payload.empty()) throw std::runtime_error("invalid CPU grant");}
    }
    void release() {
        if(grant_) {const auto grant=grant_;grant_=0;
            auto reply=channel_->request(control_kind::cpu_release,grant);
            if(reply.a || reply.b || reply.c || !reply.payload.empty()) throw std::runtime_error("invalid CPU release");}
    }
    bool owns_grant() const noexcept {return grant_!=0;}
    static control_cpu_scope* current() noexcept {return current_;}
    ~control_cpu_scope() noexcept {
        current_=previous_;
        if(grant_) {try {release();}catch(...) {std::terminate();}}
    }
};
// Release before acquiring an I/O serialization lock as its owner may need
// parent CPU work. Reacquire only after that lock has been released.
class control_cpu_pause final {
    control_cpu_scope* scope_;
public:
    control_cpu_pause():scope_(control_cpu_scope::current()) {
        if(scope_ && scope_->owns_grant())scope_->release(); else scope_=nullptr;
    }
    ~control_cpu_pause() noexcept {if(scope_) {try {scope_->acquire();}catch(...) {std::terminate();}}}
};
class control_memory_scope final {
    control_channel* channel_; std::uint64_t grant_=0;
public:
    control_memory_scope(control_channel* channel,std::uint64_t bytes):channel_(channel) {
        control_cpu_pause pause;
        if(channel_) {auto reply=channel_->request(control_kind::memory_acquire,bytes);grant_=reply.a;
            if(!grant_ || reply.b || reply.c || !reply.payload.empty())throw std::runtime_error("invalid memory grant");}
    }
    ~control_memory_scope() noexcept {
        if(grant_)try {auto reply=channel_->request(control_kind::memory_release,grant_);
            if(reply.a || reply.b || reply.c || !reply.payload.empty()) std::terminate();}
        catch(...) {std::terminate();}
    }
};

}
