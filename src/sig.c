
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "global.h"
#include "buffer.h"
#include "byteops.h"
#include "key.h"
#include "packet.h"
#include "rsa.h"
#include "sig.h"

#define SIG_VERSION    4
#define SIG_TYPE       0x13 /* Positive certification of User ID & Public Key */
#define SIG_ISSUER_LEN 8

typedef enum {
  Sig_creation_time = 2, \
  Sig_expiration_time = 3, \
  Sig_exportable_certification = 4, \
  Sig_trust_signature = 5, \
  Sig_regular_expression = 6, \
  Sig_revocable = 7, \
  Sig_key_expiration_time = 9, \
  Sig_pref_symmetric_algs = 11, \
  Sig_revocation_key = 12, \
  Sig_issuer = 16, \
  Sig_notation_data = 20, \
  Sig_pref_hash_algs = 21, \
  Sig_pref_compression_algs = 22, \
  Sig_key_server_prefs = 23, \
  Sig_pref_key_server = 24, \
  Sig_primary_user_id = 25, \
  Sig_policy_uri = 26, \
  Sig_key_flags = 27, \
  Sig_signer_user_id = 28, \
  Sig_reason_for_revocation = 29, \
  Sig_features = 30, \
  Sig_signature_target = 31, \
  Sig_embedded_signature = 32, \
} Sig_subpacket_type;

#define UPDATE_1OCT_SIZE(BUF, OFF, SIZE) \
  *((uint8_t *)(BUF->buf + (OFF))) = ((SIZE) + 1)

static inline uint16_t encode_v4_2octet(uint16_t x)
{
  x -= 192;
  x = be16(x);
  *((uint8_t *)&x) += 192;
  return x;
}

Buffer *Sig_subpacket_add_header(Buffer *buf, Sig_subpacket_type type)
{
  Buffer *spkt;
  uint32_t size = Buffer_size(buf) + 1;

  if (size <= 191) {
    spkt = Buffer_new(size + 1);
    Buffer_add_byte(spkt, size);
  } else if (size <= 8383) {
    spkt = Buffer_new(size + 2);
    Buffer_add_bytes(spkt, \
        (unsigned char *)&(uint16_t){ encode_v4_2octet(size) }, 2);
  } else {
    spkt = Buffer_new(size + 5);
    Buffer_add_byte(spkt, 255);
    Buffer_add_be32(spkt, size);
  }

  Buffer_add_byte(spkt, type);
  Buffer_add_buffer(spkt, buf);

  return spkt;
}

size_t Sig_subpacket_add_rheader(Buffer *buf, Sig_subpacket_type type, \
    size_t max_size)
{
  size_t offset = buf->pos;
  max_size++; /* account for subpacket type */

  if (max_size <= 191) {
    Buffer_reserve(buf, 1);
  } else if (max_size <= 8383) {
    Buffer_reserve(buf, 2);
  } else {
    Buffer_reserve(buf, 5);
  }

  Buffer_add_byte(buf, type);
  return offset;
}

void Sig_add_creation_time(Buffer *buf, uint32_t timestamp)
{
  size_t off = Sig_subpacket_add_rheader(buf, Sig_creation_time, sizeof(uint32_t));
  Buffer_add_be32(buf, timestamp);
  UPDATE_1OCT_SIZE(buf, off, sizeof(uint32_t));
}

void Sig_add_expiration_time(Buffer *buf, uint32_t seconds)
{
  size_t off = Sig_subpacket_add_rheader(buf, Sig_expiration_time, sizeof(uint32_t));
  Buffer_add_be32(buf, seconds);
  UPDATE_1OCT_SIZE(buf, off, sizeof(uint32_t));
}

void Sig_add_pref_symmetric_algs(Buffer *buf)
{
  size_t off = Sig_subpacket_add_rheader(buf, Sig_pref_symmetric_algs, 7);
  Buffer_add_byte(buf, Sig_symmetric_AES256);
  Buffer_add_byte(buf, Sig_symmetric_AES192);
  Buffer_add_byte(buf, Sig_symmetric_AES128);
  Buffer_add_byte(buf, Sig_symmetric_Twofish);
  Buffer_add_byte(buf, Sig_symmetric_Blowfish);
  Buffer_add_byte(buf, Sig_symmetric_CAST5);
  Buffer_add_byte(buf, Sig_symmetric_3DES);
  UPDATE_1OCT_SIZE(buf, off, 7);
}

void Sig_add_pref_hash_algs(Buffer *buf)
{
  size_t off = Sig_subpacket_add_rheader(buf, Sig_pref_hash_algs, 6);
  Buffer_add_byte(buf, Sig_hash_SHA512);
  Buffer_add_byte(buf, Sig_hash_SHA384);
  Buffer_add_byte(buf, Sig_hash_SHA256);
  Buffer_add_byte(buf, Sig_hash_SHA224);
  Buffer_add_byte(buf, Sig_hash_RIPEMD);
  Buffer_add_byte(buf, Sig_hash_SHA1);
  UPDATE_1OCT_SIZE(buf, off, 6);
}

void Sig_add_pref_compression_algs(Buffer *buf)
{
  size_t off = Sig_subpacket_add_rheader(buf, Sig_pref_compression_algs, 3);
  Buffer_add_byte(buf, Sig_compression_ZLIB);
  Buffer_add_byte(buf, Sig_compression_BZip2);
  Buffer_add_byte(buf, Sig_compression_ZIP);
  UPDATE_1OCT_SIZE(buf, off, 3);
}

void Sig_add_key_server_prefs(Buffer *buf)
{
  size_t off = Sig_subpacket_add_rheader(buf, Sig_key_server_prefs, 1);
  Buffer_add_byte(buf, 0x80); /* No modify */
  UPDATE_1OCT_SIZE(buf, off, 1);
}

void Sig_add_key_flags(Buffer *buf, uint8_t fs)
{
  size_t off = Sig_subpacket_add_rheader(buf, Sig_key_flags, 1);
  Buffer_add_byte(buf, fs);
  UPDATE_1OCT_SIZE(buf, off, 1);
}

void Sig_add_features(Buffer *buf)
{
  size_t off = Sig_subpacket_add_rheader(buf, Sig_features, 1);
  Buffer_add_byte(buf, 0x01);
  UPDATE_1OCT_SIZE(buf, off, 1);
}

void Sig_add_issuer(Buffer *buf, unsigned char *keyid)
{
  size_t off = Sig_subpacket_add_rheader(buf, Sig_issuer, 8);
  Buffer_add_bytes(buf, keyid, 8);
  UPDATE_1OCT_SIZE(buf, off, 8);
}

Buffer *Sig_RSA_packet(RSAk *key, unsigned char *userid, size_t userid_len)
{
  Buffer *buf = Buffer_new(1024), *tmp0;
  unsigned char hash[SHA512_DIGEST_LENGTH]; /* Maximum possible size */
  unsigned char fingerprint[SHA_DIGEST_LENGTH];
  unsigned int sig_len = 0;
  int key_size = RSA_size(key->key);
  unsigned char *sig = (unsigned char *)malloc(key_size);

  if (!sig) {
    puts("[e] Insufficient memory available.");
    exit(EXIT_FAILURE);
  }

  Buffer_add_byte(buf, SIG_VERSION);
  Buffer_add_byte(buf, SIG_TYPE);

  Buffer_add_byte(buf, Sig_pubkey_RSA_encrypt_sign);
  Buffer_add_byte(buf, Sig_hash_SHA512);

  size_t off = buf->pos;
  Buffer_reserve(buf, 2); /* Size of the hashed subpacket data */

  Sig_add_creation_time(buf, key->timestamp);
  Sig_add_key_flags(buf, Sig_key_flag_certify_others | Sig_key_flag_sign | Sig_key_flag_authentication);
  Sig_add_pref_symmetric_algs(buf);
  Sig_add_pref_hash_algs(buf);
  Sig_add_pref_compression_algs(buf);
  Sig_add_features(buf);
  Sig_add_key_server_prefs(buf);

  /* Take additional 2 bytes off for the length field */
  *((uint16_t *)(buf->buf + off)) = be16(Buffer_size(buf) - off - 2);

  size_t hash_data_size = Buffer_size(buf);

  Buffer *sbuf = Buffer_new(hash_data_size + 1024);

  Buffer_add_byte(sbuf, 0x99);
  tmp0 = Key_RSA_public_body(key);

  Buffer_add_be16(sbuf, Buffer_size(tmp0));
  Buffer_add_buffer(sbuf, tmp0);
  Buffer_free(tmp0);

  Buffer_add_byte(sbuf, 0xB4);
  Buffer_add_be32(sbuf, userid_len);
  Buffer_add_bytes(sbuf, userid, userid_len);

  Buffer_add_buffer(sbuf, buf);

  Buffer_add_byte(sbuf, SIG_VERSION);
  Buffer_add_byte(sbuf, 0xFF);
  Buffer_add_be32(sbuf, hash_data_size);

  SHA512(sbuf->buf, Buffer_size(sbuf), hash);
  Buffer_free(sbuf);

  RSA_sign(NID_sha512, hash, SHA512_DIGEST_LENGTH, sig, &sig_len, key->key);

  BIGNUM *bn = BN_new();
  BN_bin2bn(sig, sig_len, bn);

  /* Unhashed data length */
  off = buf->pos;
  Buffer_reserve(buf, 2);

  Key_RSA_fingerprint(key, fingerprint);
  Sig_add_issuer(buf, fingerprint + (SHA_DIGEST_LENGTH - SIG_ISSUER_LEN));

  *((uint16_t *)(buf->buf + off)) = be16(Buffer_size(buf) - off - 2);

  //Buffer_add_bytes(buf, hash, 2);
  Buffer_add_bytes(buf, hash, 2);

  Buffer_add_mpi(buf, bn);
  BN_clear_free(bn);

  Buffer *sigpkt = Packet_add_header(buf, Packet_type_signature);
  Buffer_free(buf);

  return sigpkt;
}
