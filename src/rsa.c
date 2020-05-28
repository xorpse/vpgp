
#include <stdint.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "global.h"
#include "rsa.h"

result_t RSAk_new(RSAk *rsak, unsigned int bits, unsigned int exponent)
{
  BIGNUM *e = BN_new();
  BN_set_word(e, exponent);

  RSA *key = RSA_new();

  if (RSA_generate_key_ex(key, bits, e, NULL) == -1) {
    RSA_free(key);
    BN_free(e);
    return R_ERROR;
  }

  rsak->key = key;
  rsak->timestamp = (uint32_t)time(NULL);

  BN_free(e); /* Should we BN_clear_free(e) ? */
  return R_OK;
}

void RSAk_free(RSAk *rsak)
{
  RSA_free(rsak->key);
}
