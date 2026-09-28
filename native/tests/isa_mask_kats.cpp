// Isolated test executable only. Runtime feature masking can only disable
// detected instructions; no feature setter is included in any product library.
#include "../../native/aes_ref_export.cpp"
#include "../../native/xchachapoly_ref_export.cpp"
#include "cpu.h"
#include "sha.h"
#include <cstdio>
#include <string>
int main(int argc,char**argv) {
    if(argc!=2)return 2;std::string mode=argv[1];
    const int initial=aes_get_runtime_provider();
    CryptoPP::ChaChaTLS::Encryption chacha;
    std::string before=static_cast<const CryptoPP::StreamTransformation&>(chacha).AlgorithmProvider();
    if(mode!="auto") {
#if CRYPTOPP_BOOL_ARMV8
        CryptoPP::g_hasAES=false;CryptoPP::g_hasNEON=false;CryptoPP::g_hasARMv7=false;
#elif CRYPTOPP_BOOL_X64
        CryptoPP::g_hasAVX2=false;CryptoPP::g_hasAVX=false;
        if(mode=="baseline"){CryptoPP::g_hasAESNI=false;CryptoPP::g_hasSSSE3=false;CryptoPP::g_hasSSE41=false;CryptoPP::g_hasSSE42=false;CryptoPP::g_hasSSE2=false;}
#endif
    }
    std::uint8_t key[32],nonce[24],aad[36],tag[16];for(size_t i=0;i<32;i++)key[i]=static_cast<uint8_t>(i);for(size_t i=0;i<24;i++)nonce[i]=static_cast<uint8_t>(i*3);for(size_t i=0;i<36;i++)aad[i]=static_cast<uint8_t>(i*11);
    const std::uint8_t plain[16]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const std::uint8_t expected[16]={0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89};std::uint8_t block[16];
    if(aes_encrypt_block(key,32,plain,block)!=0||std::memcmp(block,expected,16)!=0)return 3;
    CryptoPP::SHA256 hash;std::vector<std::uint8_t> input(16u*1024u*1024u),output(input.size());for(size_t i=0;i<input.size();++i)input[i]=static_cast<uint8_t>(i*7+1);
    for(size_t length:{size_t(0),size_t(1),size_t(64),size_t(1024),input.size()}){
        if(aes_256_ctr_xcrypt_v13_with_workers(key,nonce,input.data(),output.data(),length,5)!=0)return 4;hash.Update(output.data(),length);
        if(keepvault_xchacha20poly1305_v13_encrypt_with_budget(key,32,nonce,24,aad,36,input.data(),length,output.data(),length,tag,16,5)!=0)return 5;hash.Update(output.data(),length);hash.Update(tag,16);
    }
    std::uint8_t digest[32];hash.Final(digest);std::printf("{\"mode\":\"%s\",\"aes_detected\":%d,\"aes_selected\":%d,\"chacha_detected\":\"%s\",\"chacha_selected\":\"%s\",\"output_sha256\":\"",mode.c_str(),initial,aes_get_runtime_provider(),before.c_str(),static_cast<const CryptoPP::StreamTransformation&>(chacha).AlgorithmProvider().c_str());for(auto value:digest)std::printf("%02x",value);std::puts("\",\"aes_fips197_kat\":\"PASS\"}");return 0;
}
