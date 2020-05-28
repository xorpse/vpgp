
#ifndef _VPGP_BYTEOPS_H_
#define _VPGP_BYTEOPS_H_

#ifdef __GNUC__
#define bswap32 __builtin_bswap32
#define bswap16 __builtin_bswap16
#else
#define bswap32 c_bswap32
#define bswap16 c_bswap16
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define be32(X) bswap32(X)
#define be16(X) bswap16(X)
#else
#define be32(X) (X)
#define be16(X) (X)
#endif

#include <stdint.h>

static inline uint16_t c_bswap16(uint16_t v) {
  return (v << 8) | (v >> 8);
}

static inline uint32_t c_bswap32(uint32_t v) {
  return (v << 24) | (v >> 24) | \
    ((v & 0x0000FF00) << 8) | ((v & 0x00FF0000) >> 8);
}

#endif
