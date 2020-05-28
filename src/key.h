
#ifndef _VPGP_KEY_H_
#define _VPGP_KEY_H_

#include "buffer.h"
#include "byteops.h"
#include "dsa.h"
#include "rsa.h"

#include <openssl/sha.h>

#define KEY_FINGERPRINT_LEN SHA_DIGEST_LENGTH

extern Buffer *Key_RSA_public_body(RSAk *key);
extern Buffer *Key_RSA_private_body(RSAk *key);

extern Buffer *Key_DSA_public_body(DSAk *key);
extern Buffer *Key_DSA_private_body(DSAk *key);

extern Buffer *Key_RSA_fingerprint_material(RSAk *key);
extern void Key_RSA_fingerprint(RSAk *key, unsigned char *hash);
extern Buffer *Key_DSA_fingerprint_material(DSAk *key);
extern void Key_DSA_fingerprint(DSAk *key, unsigned char *hash);
extern void Key_fingerprint_from(Buffer *buf, uint32_t timestamp, \
    unsigned char *hash);

#endif
