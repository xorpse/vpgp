
#ifndef _VPGP_SEQ_H_
#define _VPGP_SEQ_H_

#include <stdbool.h>

#include "global.h"
#include "key.h"
#include "buffer.h"
#include "pattern.h"
#include "rsa.h"

/* Returns with RSAk set to RSA key with given fingerprint */
static inline void Seq_RSA_with_keyid(RSAk *rsak, uint32_t pat)
{
  RSAk key;
  uint32_t max_age = 0;
  unsigned char fp[KEY_FINGERPRINT_LEN];
  bool found = false;

  while (!found) {
    RSAk_new(&key, g_key_bits, DEF_RSA_E);
    Buffer *fpm = Key_RSA_fingerprint_material(&key);

    max_age = key.timestamp - g_max_age;

    while (key.timestamp > max_age) {
      Key_fingerprint_from(fpm, key.timestamp, fp);

      if (Pattern_match_keyid(fp, pat)) {
        fprintf(stderr, "[i] First-preimage found.\n");
        Buffer_free(fpm);
        rsak->key = key.key;
        rsak->timestamp = key.timestamp;
        found = true;
        break;
      }

      key.timestamp--;
    }

    if (!found) {
      Buffer_free(fpm);
      RSAk_free(&key);
    }
  }
}

extern void Seq_init(void);
extern void Seq_terminate(void);

#endif
