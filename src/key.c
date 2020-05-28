
#include <openssl/bn.h>
#include <openssl/sha.h>

#include "global.h"
#include "buffer.h"
#include "dsa.h"
#include "packet.h"
#include "rsa.h"
#include "byteops.h"

#define KEY_VERSION       4
#define KEY_NO_ENCRYPTION 0

enum { ALG_RSA = 1, ALG_DSA = 17 };

static inline BIGNUM *Key_multiplicative_inverse(const BIGNUM *a, const BIGNUM *n)
{
  BIGNUM *t = BN_new(), \
         *r = BN_dup(n), \
         *newt = BN_new(), \
         *newr = BN_dup(a);

  BN_zero(t);
  BN_one(newt);

  BIGNUM *x = BN_new(), *y = BN_new();
  BN_CTX *ctx = BN_CTX_new();

  while (!BN_is_zero(newr)) {
    /* x -> quotient, y -> remainder */
    BN_div(x, y, r, newr, ctx);

    BN_copy(r, newr);
    BN_copy(newr, y);

    BN_mul(y, x, newt, ctx);
    BN_sub(x, t, y);
    BN_copy(t, newt);
    BN_copy(newt, x);
  }

  BN_free(x); BN_free(y); BN_free(newt); BN_free(newr); BN_CTX_free(ctx);

  if (BN_cmp(r, BN_value_one()) == 1) {
    BN_free(t); BN_free(r);
    return NULL;
  } else {
    BN_free(r);
    if (BN_is_negative(t)) {
      BN_add(t, t, n);
    }
    return t;
  }
}

static inline uint16_t Key_private_checksum(Buffer *algmat, size_t off)
{
  uint16_t checksum = 0;

  for (size_t i = off; i < Buffer_size(algmat); i++) {
    checksum += algmat->buf[i];
  }

  return checksum;
}

Buffer *Key_RSA_public_body(RSAk *key)
{
  Buffer *buf = Buffer_new(1024);
  const BIGNUM *n = RSA_get0_n(key->key);
  const BIGNUM *e = RSA_get0_e(key->key);

  Buffer_add_byte(buf, KEY_VERSION);
  Buffer_add_be32(buf, key->timestamp);
  Buffer_add_byte(buf, ALG_RSA);
  Buffer_add_mpi(buf, n);
  Buffer_add_mpi(buf, e);

  return buf;
}

Buffer *Key_DSA_public_body(DSAk *key)
{
  Buffer *buf = Buffer_new(1024);
  const BIGNUM *p = DSA_get0_p(key->key);
  const BIGNUM *q = DSA_get0_q(key->key);
  const BIGNUM *g = DSA_get0_g(key->key);
  const BIGNUM *pub_key = DSA_get0_pub_key(key->key);

  Buffer_add_byte(buf, KEY_VERSION);
  Buffer_add_be32(buf, key->timestamp);
  Buffer_add_byte(buf, ALG_DSA);
  Buffer_add_mpi(buf, p);
  Buffer_add_mpi(buf, q);
  Buffer_add_mpi(buf, g);
  Buffer_add_mpi(buf, pub_key);

  return buf;
}

Buffer *Key_RSA_private_body(RSAk *key)
{
  Buffer *buf = Key_RSA_public_body(key);
  size_t off = Buffer_size(buf);
  const BIGNUM *d = RSA_get0_d(key->key);
  const BIGNUM *p = RSA_get0_p(key->key);
  const BIGNUM *q = RSA_get0_q(key->key);

  Buffer_add_byte(buf, KEY_NO_ENCRYPTION);
  Buffer_add_mpi(buf, d);
  Buffer_add_mpi(buf, p);
  Buffer_add_mpi(buf, q);

  BIGNUM *mi = Key_multiplicative_inverse(p, q);

  if (!mi) {
    Buffer_free(buf);
    return NULL;
  }

  Buffer_add_mpi(buf, mi);
  Buffer_add_be16(buf, Key_private_checksum(buf, off));
  BN_free(mi);

  return buf;
}

Buffer *Key_DSA_private_body(DSAk *key)
{
  Buffer *buf = Key_DSA_public_body(key);
  size_t off = Buffer_size(buf);
  const BIGNUM *priv_key = DSA_get0_priv_key(key->key);

  Buffer_add_byte(buf, KEY_NO_ENCRYPTION);
  Buffer_add_mpi(buf, priv_key);

  Buffer_add_be16(buf, Key_private_checksum(buf, off));

  return buf;
}

Buffer *Key_RSA_fingerprint_material(RSAk *key)
{
  Buffer *buf = Key_RSA_public_body(key);
  Buffer *fpp = Packet_add_fingerprint_header(buf);
  Buffer_free(buf);

  return fpp;
}

void Key_RSA_fingerprint(RSAk *key, unsigned char *hash)
{
  Buffer *fpp = Key_RSA_fingerprint_material(key);
  SHA1(fpp->buf, Buffer_size(fpp), hash);
  Buffer_free(fpp);
}

Buffer *Key_DSA_fingerprint_material(DSAk *key)
{
  Buffer *buf = Key_DSA_public_body(key);
  Buffer *fpp = Packet_add_fingerprint_header(buf);
  Buffer_free(buf);

  return fpp;
}

void Key_DSA_fingerprint(DSAk *key, unsigned char *hash)
{
  Buffer *fpp = Key_DSA_fingerprint_material(key);
  SHA1(fpp->buf, Buffer_size(fpp), hash);
  Buffer_free(fpp);
}

void Key_fingerprint_from(Buffer *buf, uint32_t timestamp, \
    unsigned char *hash)
{
  *((uint32_t *)(buf->buf + 4)) = be32(timestamp);
  SHA1(buf->buf, Buffer_size(buf), hash);
}
