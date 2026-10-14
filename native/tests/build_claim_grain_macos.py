#!/usr/bin/env python3
"""Build isolated candidates; never edits the product helper or release tree."""
import pathlib,subprocess
root=pathlib.Path.cwd();out=root/'work/v13-native/claim-grain';out.mkdir(parents=True,exist_ok=True)
sdk=subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip()
source='''#include "cryptopp_ctr_common.hpp"
#include "rijndael.h"
#include "mars.h"
#include "camellia_fixed_access.hpp"
#include "serpent.h"
#include "shacal2.h"
extern "C" __attribute__((visibility("default"))) int grain_xcrypt(int algorithm,const uint8_t* key,const uint8_t* nonce,const uint8_t* input,uint8_t* output,size_t length,uint32_t workers) {
 switch(algorithm) {
 case 0:return keepvault::xcrypt_ctr<CryptoPP::Rijndael::Encryption>(key,32,nonce,input,output,length,workers);
 case 1:return keepvault::xcrypt_ctr<CryptoPP::MARS::Encryption>(key,56,nonce,input,output,length,workers);
 case 2:return keepvault::xcrypt_ctr<CryptoPP::CamelliaFixedAccess>(key,32,nonce,input,output,length,workers);
 case 3:return keepvault::xcrypt_ctr<CryptoPP::Serpent::Encryption>(key,32,nonce,input,output,length,workers);
 case 4:return keepvault::xcrypt_ctr<CryptoPP::SHACAL2::Encryption>(key,64,nonce,input,output,length,workers);
 default:return 1;
 }
}
'''
for grain in [64,128,256,512,1024]:
 d=out/str(grain);d.mkdir(exist_ok=True)
 header=(root/'native/cryptopp_ctr_common.hpp').read_text();needle='kChunkBytes = 256u * 1024u';assert needle in header
 (d/'cryptopp_ctr_common.hpp').write_text(header.replace(needle,f'kChunkBytes = {grain}u * 1024u'));(d/'grain.cpp').write_text(source)
 subprocess.run(['clang++','-std=c++17','-O2','-DNDEBUG','-fstack-protector-strong','-fvisibility=hidden','-fno-common','-arch','arm64','-isysroot',sdk,'-mmacosx-version-min=14.0','-dynamiclib','-pthread','-Inative','-Iexternal/cryptopp',str(d/'grain.cpp'),'KeepVaultMac/Native/osx-arm64/libcryptopp.a','-o',str(out/f'libgrain{grain}.dylib')],check=True)
