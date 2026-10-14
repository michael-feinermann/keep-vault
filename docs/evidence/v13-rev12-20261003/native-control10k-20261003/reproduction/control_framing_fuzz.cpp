// PROPOSAL ONLY. Not compiled or run during the pinned archive matrix.
// Include the actual unmodified production parser through -I <repo>/native.
#include "zpaq_control.hpp"
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace {
struct fixture {
    unsigned index=0, action=0, kind=0, reject=0, length=0;
    std::uint64_t a=0,b=0,c=0,reply_a=0,reply_b=0,reply_c=0,pattern=0;
};
void oracle_require(bool condition,const char* label) {
    if(!condition) throw std::logic_error(label); // never an expected native rejection
}
void check_reply(const keepvault::control_message& reply,const fixture& f,unsigned variant=0) {
    oracle_require(reply.a==(f.reply_a^variant) && reply.b==f.reply_b
        && reply.c==f.reply_c,"reply fields differ from independent fixture");
    oracle_require(reply.payload.size()==f.length,"reply payload length differs from fixture");
    for(std::size_t i=0;i<reply.payload.size();++i)
        oracle_require(reply.payload[i]==static_cast<unsigned char>(f.pattern+i*73u),
            "reply payload differs from independent fixture");
}
}

int main(int argc,char** argv) {
    if(argc!=3) {std::fprintf(stderr,"usage: control_framing_fuzz socket parent-pid\n");return 64;}
    try {
        std::size_t parsed=0;
        const auto parent_pid=std::stoull(argv[2]);
        std::string line;
        while(std::getline(std::cin,line)) {
            fixture f;std::istringstream input(line);
            oracle_require(bool(input>>f.index>>f.action>>f.kind>>f.a>>f.b>>f.c
                >>f.reply_a>>f.reply_b>>f.reply_c>>f.length>>f.pattern>>f.reject),"invalid harness instruction");
            std::string extra;oracle_require(!(input>>extra),"unexpected harness instruction suffix");
            oracle_require(f.index==parsed && f.index<10000 && f.action<=3
                && f.kind>=1 && f.kind<=10 && f.reject<=1 && f.length<=1048576,
                "instruction outside fixed harness contract");
            bool rejected=false;
            {
                // Constructor failure is a fixture/platform failure, not a fuzz rejection.
                // The Python server must be the real parent and authenticated socket peer.
                keepvault::control_channel channel(argv[1],parent_pid,2);
                if(f.action==3) {
                    std::array<keepvault::control_message,2> replies;
                    std::array<std::exception_ptr,2> errors{};
                    std::array<std::thread,2> jobs;
                    try {
                        for(unsigned i=0;i<2;++i) {
                            jobs[i]=std::thread([&,i] {
                                try {replies[i]=channel.request(static_cast<keepvault::control_kind>(f.kind),f.a^(i+1),f.b,f.c);}
                                catch(...) {errors[i]=std::current_exception();}
                            });
                        }
                    } catch(...) {
                        // This is a failed test-child setup, never a fuzz rejection.
                        // Do not race the production reader by directly closing its handle.
                        // The runner records the nonzero exit and never reports PASS.
                        std::fprintf(stderr,"HARNESS_THREAD_START_FAILURE\n");
                        std::fflush(stderr);std::_Exit(92);
                    }
                    for(auto& job:jobs)job.join();
                    for(unsigned i=0;i<2;++i) {
                        if(errors[i])std::rethrow_exception(errors[i]);
                        check_reply(replies[i],f,i+1);
                    }
                } else {
                    try {
                        if(f.action==1) channel.finish();
                        else {
                            auto reply=channel.request(static_cast<keepvault::control_kind>(f.kind),f.a,f.b,f.c);
                            check_reply(reply,f);
                            // A duplicate may race the first caller. A subsequent real request
                            // must still fail; duplicate response precedes its reply on the wire.
                            if(f.action==2) {
                                auto second=channel.request(static_cast<keepvault::control_kind>(f.kind),f.a,f.b,f.c);
                                check_reply(second,f);
                            }
                        }
                    } catch(const std::runtime_error&) {rejected=true;}
                }
                oracle_require(rejected==(f.reject!=0),"native acceptance differs from independent norm oracle");
                // Semantic reply errors do not necessarily stop the transport. The parent
                // answers this cleanup close. A stopped channel may reject it normally.
                try {channel.finish();channel.finish();}
                catch(const std::runtime_error&) {oracle_require(rejected,"valid probe cleanup failed");}
            } // native reader shutdown and actual join must finish before the case marker
            std::cout<<"CONTROL_FUZZ_CASE "<<f.index<<" "<<(rejected?1:0)<<"\n"<<std::flush;
            ++parsed;
        }
        oracle_require(parsed==10000,"incomplete seeded corpus");
        std::cout<<"CONTROL_FUZZ_COMPLETE 10000\n"<<std::flush;
        return 0;
    } catch(const std::logic_error& failure) {
        std::fprintf(stderr,"HARNESS_ORACLE_FAILURE: %s\n",failure.what());return 90;
    } catch(const std::exception& failure) {
        std::fprintf(stderr,"HARNESS_PLATFORM_OR_UNEXPECTED_FAILURE: %s\n",failure.what());return 91;
    }
}
