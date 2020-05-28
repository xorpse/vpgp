
#include <openssl/rand.h>

#include "global.h"

result_t Rng_seed_from(const char *file, int bytes)
{
  if (RAND_load_file(file, bytes) != bytes) {
    return R_ERROR;
  }
  return R_OK;
}
