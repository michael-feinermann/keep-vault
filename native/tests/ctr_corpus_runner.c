/* Public-fixture runner for production ABI on either architecture and separately
 * instrumented wrappers. This bypasses product loader trust only in this harness. */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
typedef int (*ctr_fn)(const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,uint8_t*,size_t,uint32_t);
static void require(int ok, const char* label) { if(!ok){fprintf(stderr,"FAIL %s\n",label);exit(1);} }
static void read_exact(FILE* f,void* p,size_t n) {require(fread(p,1,n,f)==n,"fixture read");}
static uint32_t u32(FILE* f) {uint8_t b[4];read_exact(f,b,4);return (uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;}
struct context { ctr_fn fn;const uint8_t *key,*nonce,*input,*expected;size_t length;uint8_t* output; };
static void* concurrent(void* raw) {struct context* c=raw;require(c->fn(c->key,32,c->nonce,16,c->input,c->length,c->output,c->length,5)==0,"concurrent status");require(memcmp(c->output,c->expected,c->length)==0,"concurrent equality");return NULL;}
int main(int argc,char**argv) {
 require(argc==3,"directory and corpus arguments");ctr_fn functions[2];const char* names[]={"camellia","serpent"};
 for(int k=0;k<2;++k){char path[4096],symbol[128];require(snprintf(path,sizeof(path),"%s/lib%s_v13.dylib",argv[1],names[k])<(int)sizeof(path),"path length");void* h=dlopen(path,RTLD_NOW|RTLD_LOCAL);if(!h)fprintf(stderr,"%s\n",dlerror());require(h!=NULL,"dlopen");snprintf(symbol,sizeof(symbol),"keepvault_v13_%s_256_ctr_xcrypt",names[k]);void* f=dlsym(h,symbol);require(f!=NULL,"dlsym");memcpy(&functions[k],&f,sizeof(f));}
 FILE* f=fopen(argv[2],"rb");require(f!=NULL,"fixture open");char magic[8];read_exact(f,magic,8);require(memcmp(magic,"KV13CTR1",8)==0,"fixture version");uint32_t count=u32(f);require(count<1000,"fixture bound");unsigned checks=0;
 for(uint32_t item=0;item<count;++item){uint8_t algorithm,key[32],nonce[16];read_exact(f,&algorithm,1);require(algorithm<2,"algorithm");uint32_t length=u32(f);require(length<=16*1024*1024,"payload bound");read_exact(f,key,32);read_exact(f,nonce,16);size_t capacity=length?length:1;uint8_t *input=malloc(capacity),*expected=malloc(capacity),*output=malloc(capacity),*second=malloc(capacity);require(input&&expected&&output&&second,"allocation");read_exact(f,input,length);read_exact(f,expected,length);
  const uint32_t budgets[]={1,2,3,5,10,4096};for(size_t b=0;b<sizeof(budgets)/sizeof(budgets[0]);++b){if(length>=1048576&&budgets[b]==4096)continue;require(functions[algorithm](key,32,nonce,16,input,length,output,length,budgets[b])==0,"CTR status");require(memcmp(output,expected,length)==0,"BC exact bytes");require(functions[algorithm](key,32,nonce,16,output,length,output,length,budgets[b])==0,"inplace status");require(memcmp(output,input,length)==0,"inplace bytes");checks+=4;}
  if(length>=1048576){struct context c1={functions[algorithm],key,nonce,input,expected,length,output},c2={functions[algorithm],key,nonce,input,expected,length,second};pthread_t worker;require(pthread_create(&worker,NULL,concurrent,&c1)==0,"outer worker create");concurrent(&c2);require(pthread_join(worker,NULL)==0,"outer worker join");checks+=4;}
  free(second);free(output);free(expected);free(input);
 }
 require(fgetc(f)==EOF,"fixture trailing bytes");fclose(f);printf("{\"status\":\"PASS\",\"records\":%u,\"checks\":%u,\"maximum_payload\":16777216}\n",count,checks);return 0;
}
