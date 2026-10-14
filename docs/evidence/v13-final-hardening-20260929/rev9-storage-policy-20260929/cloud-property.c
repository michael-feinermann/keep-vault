#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
int main(void){const char *p="/Users/michael"; CFURLRef u=CFURLCreateFromFileSystemRepresentation(NULL,(const UInt8*)p,14,true); CFTypeRef v=NULL; CFErrorRef e=NULL; Boolean ok=CFURLCopyResourcePropertyForKey(u,kCFURLIsUbiquitousItemKey,&v,&e); printf("ok=%d value=%p type=%lu booleanType=%lu error=%ld\n",ok,v,v?CFGetTypeID(v):0,CFBooleanGetTypeID(),e?CFErrorGetCode(e):0); if(v){CFShow(v);CFRelease(v);}if(e){CFShow(e);CFRelease(e);}CFRelease(u);}
