#ifndef __MPC_LIB_PORT_H__
#define __MPC_LIB_PORT_H__

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#if HAVE_BYTESWAP_H
#include <byteswap.h>
#else
    // bswap_xx macros
    #if defined(__APPLE__)
        #include <libkern/OSByteOrder.h>
        #define bswap_16(x) OSSwapInt16(x)
        #define bswap_32(x) OSSwapInt32(x)
        #define bswap_64(x) OSSwapInt64(x)
    #else
        #error bswap_xx macros should be defined
    #endif
#endif

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __MPC_LIB_PORT_H__
