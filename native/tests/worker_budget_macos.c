/* Synthetic differential + observed-thread-budget test for macOS native v13.
 * The observer thread is excluded; the calling thread is included in each grant.
 * Mach thread sampling complements (does not replace) review of spawn limits.
 */
#include <dlfcn.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef int (*ctr_fn)(const uint8_t*,const uint8_t*,const uint8_t*,uint8_t*,size_t,uint32_t);
typedef int (*three_fn)(const uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint8_t*,size_t,uint32_t);
typedef int (*aead_fn)(const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,uint8_t*,size_t,uint8_t*,size_t,uint32_t);
typedef int (*bounded_fn)(const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,uint8_t*,size_t,uint32_t);
typedef int (*argon_fn)(uint32_t,uint32_t,uint32_t,uint8_t*,uint32_t,uint8_t*,uint32_t,uint8_t*,uint32_t,uint8_t*,uint32_t,uint8_t*,uint32_t,uint32_t);
static _Atomic int monitoring, ready;
static _Atomic unsigned peak;
static unsigned thread_count(void) {
    thread_act_array_t threads = NULL; mach_msg_type_number_t count = 0;
    if (task_threads(mach_task_self(), &threads, &count) != KERN_SUCCESS) abort();
    unsigned live = 0;
    for (unsigned i = 0; i < count; ++i) {
        thread_basic_info_data_t info; mach_msg_type_number_t info_count = THREAD_BASIC_INFO_COUNT;
        // task_threads retains ports and may briefly include already joined
        // kernel thread objects. Halted/terminated objects do no worker work.
        if (thread_info(threads[i], THREAD_BASIC_INFO, (thread_info_t)&info, &info_count) == KERN_SUCCESS
            && info.run_state != TH_STATE_HALTED && info.run_state != TH_STATE_STOPPED) ++live;
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(thread_t));
    return live;
}
static void* observe(void* unused) {
    (void)unused; atomic_store(&ready, 1);
    while (atomic_load(&monitoring)) {
        unsigned current = thread_count(), previous = atomic_load(&peak);
        while (current > previous && !atomic_compare_exchange_weak(&peak, &previous, current)) {}
        struct timespec delay = {0, 100000}; nanosleep(&delay, NULL);
    }
    return NULL;
}
static void require(int good, const char* message) {
    if (!good) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}
static void* load(const char* root,const char* library,const char* symbol) {
    char path[4096]; require(snprintf(path,sizeof(path),"%s/%s",root,library)<(int)sizeof(path),"path");
    void* handle=dlopen(path,RTLD_NOW|RTLD_LOCAL); if(!handle)fprintf(stderr,"%s\n",dlerror());require(handle!=NULL,"dlopen");
    void* function=dlsym(handle,symbol);require(function!=NULL,"budget export");return function;
}
static int run(void* function,int kind,uint32_t budget,uint8_t* input,uint8_t* output,size_t length,uint8_t tag[16]) {
    uint8_t key[128],nonce[128],tweak[16],aad[17];
    for(unsigned i=0;i<128;++i){key[i]=(uint8_t)(i*29+7);nonce[i]=(uint8_t)(i*3);}
    memset(tweak,0x17,sizeof(tweak));memset(aad,0x52,sizeof(aad));
    if(kind==4)return ((bounded_fn)function)(key,32,nonce,16,input,length,output,length,budget);
    if(kind==1)return ((three_fn)function)(key,tweak,nonce,input,output,length,budget);
    if(kind==2)return ((aead_fn)function)(key,32,nonce,24,aad,sizeof(aad),input,length,output,length,tag,16,budget);
    if(kind==3){
        uint8_t password[128],salt[64],secret[128];memset(password,1,128);memset(salt,2,64);memset(secret,3,128);
        int result=((argon_fn)function)(4,8192,4,password,128,salt,64,secret,128,aad,17,output,64,budget);
        if(result==0){uint8_t zeros[128]={0};require(memcmp(password,zeros,128)==0&&memcmp(secret,zeros,128)==0,"Argon clear flags");}
        return result;
    }
    return ((ctr_fn)function)(key,nonce,input,output,length,budget);
}
int main(int argc,char**argv){
    require(argc==2,"usage: worker_budget_macos native-directory");
    const struct {const char*name;const char*lib;const char*symbol;int kind;} algorithms[]={
        {"AES","libaes_ref.dylib","aes_256_ctr_xcrypt_v13_with_workers",0},
        {"MARS","libmars_ref.dylib","mars_448_ctr_xcrypt_v13_with_workers",0},
        {"Camellia","libcamellia_v13.dylib","keepvault_v13_camellia_256_ctr_xcrypt",4},
        {"Serpent","libserpent_v13.dylib","keepvault_v13_serpent_256_ctr_xcrypt",4},
        {"SHACAL-2","libshacal2_ref.dylib","shacal2_512_ctr_xcrypt_v13_with_workers",0},
        {"Kalyna","libkalyna_v13.dylib","keepvault_v13_kalyna_512_512_ctr_xcrypt_with_workers",0},
        {"Threefish","libthreefish_ref.dylib","threefish_1024_ctr_xcrypt_v13_with_workers",1},
        {"XChaCha20-Poly1305","libxchachapoly_v13.dylib","keepvault_xchacha20poly1305_v13_encrypt_with_budget",2},
        {"Argon2id","libargon2_ref.dylib","keepvault_argon2id_v13_kat_with_budget",3}};
    const uint32_t budgets[]={1,2,3,4,5,8,16,32,64};
    size_t length=16*1024*1024;uint8_t*input=malloc(length),*output=malloc(length),*expected=malloc(length);
    require(input&&output&&expected,"allocations");for(size_t i=0;i<length;++i)input[i]=(uint8_t)(i*13);
    printf("{\"status\":\"PASS\",\"sampling_interval_microseconds\":100,\"maximum_payload_bytes\":16777216,\"results\":[");int first=1;
    for(unsigned a=0;a<sizeof(algorithms)/sizeof(algorithms[0]);++a){
        void*function=load(argv[1],algorithms[a].lib,algorithms[a].symbol);int kind=algorithms[a].kind;
        size_t used=kind==3?64:length;uint8_t expected_tag[16]={0},tag[16];
        require(run(function,kind,1,input,expected,used,expected_tag)==0,"serial baseline");
        for(unsigned b=0;b<sizeof(budgets)/sizeof(budgets[0]);++b){
            uint32_t budget=budgets[b];pthread_t observer;atomic_store(&peak,0);atomic_store(&ready,0);atomic_store(&monitoring,1);
            require(pthread_create(&observer,NULL,observe,NULL)==0,"observer create");while(!atomic_load(&ready))sched_yield();
            for(int repeat=0;repeat<3;++repeat){
                memset(output,0xa5,used);memset(tag,0,16);require(run(function,kind,budget,input,output,used,tag)==0,"budget status");
                require(memcmp(output,expected,used)==0,"budget ciphertext/KDF equality");
                if(kind==2)require(memcmp(tag,expected_tag,16)==0,"budget tag equality");
            }
            atomic_store(&monitoring,0);require(pthread_join(observer,NULL)==0,"observer join");unsigned measured=atomic_load(&peak)-1;
            if(measured>budget){fprintf(stderr,"%s budget %u observed %u\n",algorithms[a].name,budget,measured);exit(1);}
            printf("%s{\"algorithm\":\"%s\",\"grant_including_caller\":%u,\"observed_threads_excluding_observer\":%u}",first?"":",",algorithms[a].name,budget,measured);first=0;
        }
        for(uint32_t budget=0;budget<1;++budget){memset(output,0xa5,used);memset(tag,0xa7,16);require(run(function,kind,budget,input,output,used,tag)!=0,"invalid budget rejected");for(size_t i=0;i<used;++i)require(output[i]==0xa5,"rejection leaves output untouched");for(int i=0;i<16;++i)require(tag[i]==0xa7,"rejection leaves tag untouched");}
    }
    printf("]}\n");free(input);free(output);free(expected);return 0;
}
