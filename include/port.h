#ifndef __MPC_LIB_PORT_H__
#define __MPC_LIB_PORT_H__

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

// byteswap
#if defined(__APPLE__)
  // Mac OS X / Darwin
  #include <libkern/OSByteOrder.h>
  #define bswap_16(x) OSSwapInt16(x)
  #define bswap_32(x) OSSwapInt32(x)
  #define bswap_64(x) OSSwapInt64(x)
#else
  #include <byteswap.h>
#endif

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __MPC_LIB_PORT_H__
