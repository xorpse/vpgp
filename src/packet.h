
#ifndef _VPGP_PACKET_H_
#define _VPGP_PACKET_H_

#include "buffer.h"

typedef enum {
  Packet_type_reserved = 0,
  Packet_type_public_key_encrypted_session_key,
  Packet_type_signature,
  Packet_type_symmetric_key_encrypted_session_key,
  Packet_type_one_pass_signature,
  Packet_type_secret_key,
  Packet_type_public_key,
  Packet_type_secret_subkey,
  Packet_type_compressed_data,
  Packet_type_symmetrically_encrypted_data,
  Packet_type_marker_packet,
  Packet_type_literal_data,
  Packet_type_trust,
  Packet_type_user_id,
  Packet_type_public_subkey,
} Packet_tag;

#define PACKET_FP_TIMESTAMP(FPP) *((uint32_t *)(FPP + 4))

extern Buffer *Packet_add_header(Buffer *body, Packet_tag tag);
extern Buffer *Packet_add_fingerprint_header(Buffer *body);
extern Buffer *Packet_user_id(unsigned char *uid, size_t len);

#endif
