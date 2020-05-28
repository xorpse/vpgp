
#ifndef _VPGP_RSA_H_
#define _VPGP_RSA_H_

#include <stdint.h>
#include <openssl/rsa.h>

#include "global.h"

struct rsak {
  RSA *key;
  uint32_t timestamp;
};

typedef struct rsak RSAk;

extern result_t RSAk_new(RSAk *rsak, unsigned int bits, \
    unsigned int exponent);
extern void RSAk_free(RSAk *rsak);

#endif
