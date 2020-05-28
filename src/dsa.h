
#ifndef _VPGP_DSA_H_
#define _VPGP_DSA_H_

#include <stdint.h>
#include <openssl/dsa.h>

#include "global.h"

struct dsak {
  DSA *key;
  uint32_t timestamp;
};

typedef struct dsak DSAk;

extern result_t DSAk_new(DSAk *dsak, unsigned int bits);
extern void DSAk_free(DSAk *dsak);

#endif
