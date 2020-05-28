
#include <stdint.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/dsa.h>

#include "global.h"
#include "dsa.h"

result_t DSAk_new(DSAk *dsak, unsigned int bits)
{
  DSA *key = DSA_new();

  if (!DSA_generate_parameters_ex(key, bits, NULL, 0, NULL, NULL, NULL)) {
    DSA_free(key);
    return R_ERROR;
  }

  if (!DSA_generate_key(key)) {
    DSA_free(key);
    return R_ERROR;
  }

  dsak->key = key;
  dsak->timestamp = (uint32_t)time(NULL);

  return R_OK;
}

void DSAk_free(DSAk *dsak)
{
  DSA_free(dsak->key);
}
