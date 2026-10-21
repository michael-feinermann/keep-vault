// Real Windows named-pipe peer for the production control_channel. Public,
// synthetic protocol values only; this executable is never shipped.
#include "zpaq_control.hpp"
#include <atomic>
#include <exception>
#include <iostream>

#ifndef _WIN32
#error This fixture validates Windows synchronous named-pipe shutdown.
#endif

namespace {
struct handle {
    HANDLE value=INVALID_HANDLE_VALUE;
    explicit handle(HANDLE v):value(v) { if(v==INVALID_HANDLE_VALUE || v==nullptr) throw std::runtime_error("fixture handle creation failed"); }
    ~handle() { if(value!=INVALID_HANDLE_VALUE) CloseHandle(value); }
    handle(const handle&)=delete;
};
struct frame {
    std::uint32_t kind=0;
    std::uint64_t sequence=0,a=0,b=0,c=0;
    std::vector<unsigned char> payload;
};
struct disconnect_on_failure {
    HANDLE pipe;
    int exceptions=std::uncaught_exceptions();
    ~disconnect_on_failure() {if(std::uncaught_exceptions()>exceptions)DisconnectNamedPipe(pipe);}
};
void require(bool value,const char* message) { if(!value) throw std::runtime_error(message); }
void put(unsigned char* p,std::uint64_t value,unsigned bytes) {
    for(unsigned i=0;i<bytes;++i) p[i]=static_cast<unsigned char>(value>>(8*(bytes-1-i)));
}
std::uint64_t get(const unsigned char* p,unsigned bytes) {
    std::uint64_t value=0;for(unsigned i=0;i<bytes;++i) value=(value<<8)|p[i];return value;
}
void transfer(HANDLE pipe,void* bytes,std::size_t length,bool writing) {
    auto* p=static_cast<unsigned char*>(bytes);
    while(length) {
        DWORD done=0;
        const BOOL ok=writing?WriteFile(pipe,p,static_cast<DWORD>(length),&done,nullptr)
                             :ReadFile(pipe,p,static_cast<DWORD>(length),&done,nullptr);
        require(ok && done,"fixture protocol transfer failed");p+=done;length-=done;
    }
}
frame receive(HANDLE pipe) {
    std::array<unsigned char,48> bytes{};transfer(pipe,bytes.data(),bytes.size(),false);
    require(std::memcmp(bytes.data(),"KV13CTL1",8)==0,"fixture received invalid magic");
    frame result;result.kind=static_cast<std::uint32_t>(get(bytes.data()+8,4));
    const auto length=get(bytes.data()+12,4);require(length<=1024,"fixture received oversized payload");
    result.sequence=get(bytes.data()+16,8);result.a=get(bytes.data()+24,8);
    result.b=get(bytes.data()+32,8);result.c=get(bytes.data()+40,8);
    result.payload.resize(static_cast<std::size_t>(length));
    if(length) transfer(pipe,result.payload.data(),result.payload.size(),false);
    return result;
}
void respond(HANDLE pipe,const frame& request,const std::string& mode) {
    std::array<unsigned char,48> bytes{};std::memcpy(bytes.data(),"KV13CTL1",8);
    const bool close=request.kind==static_cast<std::uint32_t>(keepvault::control_kind::close);
    const auto kind=request.kind|0x80000000u;
    put(bytes.data()+8,mode=="wrong-kind"?kind+1:kind,4);
    put(bytes.data()+12,close && mode=="close-payload"?1:0,4);
    put(bytes.data()+16,request.sequence+(mode=="wrong-sequence"?1:0),8);
    put(bytes.data()+24,close && mode=="close-field"?1:0,8);
    transfer(pipe,bytes.data(),bytes.size(),true);
    if(close && mode=="close-payload") {unsigned char payload=0x5a;transfer(pipe,&payload,1,true);}
}
void wait_for_eof(HANDLE pipe) {
    unsigned char byte=0;DWORD done=0;
    const BOOL result=ReadFile(pipe,&byte,1,&done,nullptr);
    require(!result && GetLastError()==ERROR_BROKEN_PIPE,"native client did not close its pipe after final acknowledgment");
}

void run_case(const std::string& mode,int iteration) {
    auto trace=[&](const char* stage) { if(iteration==0)std::cerr<<stage<<std::endl; };
    trace("fixture: starting case");
    const std::string address="\\\\.\\pipe\\KeepVault-control-lifecycle-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(iteration);
    const std::wstring wide(address.begin(),address.end());
    handle pipe(CreateNamedPipeW(wide.c_str(),PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,4096,4096,0,nullptr));
    handle saw_request(CreateEventW(nullptr,TRUE,FALSE,nullptr));
    handle release_response(CreateEventW(nullptr,TRUE,FALSE,nullptr));
    std::exception_ptr peer_failure;
    std::thread peer([&] {
        try {
            require(ConnectNamedPipe(pipe.value,nullptr) || GetLastError()==ERROR_PIPE_CONNECTED,"fixture connect failed");
            trace("fixture: peer connected");
            if(mode=="close-field" || mode=="close-payload") {
                const frame request=receive(pipe.value);
                require(request.kind==9,"expected final close request");respond(pipe.value,request,mode);
            } else {
                const frame request=receive(pipe.value);
                require(request.kind==5 && request.a==17 && request.b==23 && request.c==29,"fixture received wrong ordinary request");
                trace("fixture: peer received ordinary request");
                if(mode=="pending-close") {
                    require(SetEvent(saw_request.value),"fixture cannot signal request");
                    require(WaitForSingleObject(release_response.value,3000)==WAIT_OBJECT_0,"fixture was not released after pending-close check");
                }
                if(mode=="peer-drop") {require(DisconnectNamedPipe(pipe.value),"fixture disconnect failed");return;}
                respond(pipe.value,request,mode);
                if(mode!="wrong-kind" && mode!="wrong-sequence") {
                    trace("fixture: peer awaiting close");
                    const frame close=receive(pipe.value);require(close.kind==9,"expected final close request");
                    trace("fixture: peer sending close ACK");respond(pipe.value,close,mode);
                    trace("fixture: peer sent close ACK");
                }
            }
            trace("fixture: peer awaiting EOF");
            wait_for_eof(pipe.value);
        } catch(...) {peer_failure=std::current_exception();DisconnectNamedPipe(pipe.value);}
    });
    std::exception_ptr client_failure;
    try {
        trace("fixture: creating client");
        keepvault::control_channel channel(address,GetCurrentProcessId(),4);
        disconnect_on_failure cleanup{pipe.value};
        trace("fixture: client connected");
        if(mode=="close-field" || mode=="close-payload") {
            bool rejected=false;try {channel.finish();}catch(const std::runtime_error&) {rejected=true;}
            require(rejected,"malformed close acknowledgment accepted");
        } else if(mode=="pending-close") {
            std::exception_ptr requester_failure;
            std::thread requester([&] {try {channel.request(keepvault::control_kind::progress,17,23,29);}catch(...) {requester_failure=std::current_exception();}});
            bool request_seen=WaitForSingleObject(saw_request.value,3000)==WAIT_OBJECT_0;
            bool rejected=false;
            trace("fixture: ordinary request");
            if(request_seen)try {channel.finish();}catch(const std::runtime_error&) {rejected=true;}
            SetEvent(release_response.value);requester.join();
            require(request_seen && rejected,"close accepted a pending request");
            if(requester_failure)std::rethrow_exception(requester_failure);
            channel.finish();
        } else {
            bool rejected=false;
            keepvault::control_message reply;
            trace("fixture: ordinary request");
            try {reply=channel.request(keepvault::control_kind::progress,17,23,29);}
            catch(const std::runtime_error&) {rejected=true;}
            const bool must_reject=mode=="wrong-kind" || mode=="wrong-sequence" || mode=="peer-drop";
            require(rejected==must_reject,"ordinary request rejection did not match peer behavior");
            if(!must_reject) {
                require(reply.kind==(5u|0x80000000u) && reply.a==0 && reply.b==0 && reply.c==0 && reply.payload.empty(),"ordinary response changed");
                trace("fixture: ordinary request completed");
                trace("fixture: finish");
                channel.finish();channel.finish();
                trace("fixture: finish returned");
                if(mode!="close-race") {
                    bool after_close_rejected=false;
                    try {channel.request(keepvault::control_kind::progress);}catch(const std::runtime_error&) {after_close_rejected=true;}
                    require(after_close_rejected,"request was accepted after final close");
                }
            }
        }
        trace("fixture: destroying channel");
    } catch(...) {client_failure=std::current_exception();DisconnectNamedPipe(pipe.value);}
    trace("fixture: joining peer");
    peer.join();
    trace("fixture: peer joined");
    if(client_failure)std::rethrow_exception(client_failure);
    if(peer_failure)std::rethrow_exception(peer_failure);
}
}

int main(int argc,char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
    try {
        require(argc==3,"usage: control-lifecycle.exe <mode> <repetitions>");
        const std::string mode=argv[1];const int repetitions=std::stoi(argv[2]);
        require(repetitions>=1 && repetitions<=1024,"invalid fixture repetition count");
        run_case(mode,0);
        DWORD before=0,after=0;
        require(GetProcessHandleCount(GetCurrentProcess(),&before),"cannot read the initialized fixture handle count");
        for(int iteration=1;iteration<repetitions;++iteration)run_case(mode,iteration);
        require(GetProcessHandleCount(GetCurrentProcess(),&after),"cannot read the final fixture handle count");
        require(after==before,"repeated channel lifecycles leaked process handles");
        std::cout<<"PASS control-lifecycle mode="<<mode<<" repetitions="<<repetitions
            <<" handlesBefore="<<before<<" handlesAfter="<<after<<"\n";return 0;
    } catch(const std::exception& error) {std::cerr<<"FAIL control-lifecycle: "<<error.what()<<"\n";return 1;}
}
