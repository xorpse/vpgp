
#ifndef _VPGP_SIG_H_
#define _VPGP_SIG_H_

#include "buffer.h"
#include "rsa.h"

typedef enum {
  Sig_symmetric_plain    = 0, \
  Sig_symmetric_IDEA     = 1, \
  Sig_symmetric_3DES     = 2, \
  Sig_symmetric_CAST5    = 3, \
  Sig_symmetric_Blowfish = 4, \
  Sig_symmetric_AES128   = 7, \
  Sig_symmetric_AES192   = 8, \
  Sig_symmetric_AES256   = 9, \
  Sig_symmetric_Twofish  = 10, \
} Sig_symmetric;

typedef enum {
  Sig_compression_none  = 0, \
  Sig_compression_ZIP   = 1, \
  Sig_compression_ZLIB  = 2, \
  Sig_compression_BZip2 = 3, \
} Sig_compression;

typedef enum {
  Sig_hash_MD5     = 1, \
  Sig_hash_SHA1    = 2, \
  Sig_hash_RIPEMD  = 3, \
  Sig_hash_SHA256  = 8, \
  Sig_hash_SHA384  = 9, \
  Sig_hash_SHA512  = 10, \
  Sig_hash_SHA224  = 11, \
} Sig_hash;

typedef enum {
  Sig_pubkey_RSA_encrypt_sign = 1, \
  Sig_pubkey_RSA_encrypt_only = 2, \
  Sig_pubkey_RSA_sign_only    = 3, \
  Sig_pubkey_DSA              = 17, \
} Sig_pubkey;

typedef enum {
  Sig_key_flag_certify_others  = 0x01, \
  Sig_key_flag_sign            = 0x02, \
  Sig_key_flag_encrypt_comms   = 0x04, \
  Sig_key_flag_encrypt_storage = 0x08, \
  Sig_key_flag_private_split   = 0x10, \
  Sig_key_flag_authentication  = 0x20, \
  Sig_key_flag_multiple_owners = 0x40, \
} Sig_key_flag;

extern Buffer *Sig_RSA_packet(RSAk *key, unsigned char *userid, \
    size_t userid_len);

#endif
