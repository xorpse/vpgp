
#include <stdio.h>
#include <stdint.h>

#include "global.h"
#include "buffer.h"
#include "packet.h"

Buffer *Packet_add_header(Buffer *body, Packet_tag tag)
{
  uint8_t ptag = 0x80 | ((tag & 0x0F) << 2);
  size_t size = Buffer_size(body);
  Buffer *buf;

  if (size <= 0xFF) {
    buf = Buffer_new(size + 2);
    Buffer_add_byte(buf, ptag);
    Buffer_add_byte(buf, size);
    Buffer_add_buffer(buf, body);
  } else if (size <= 0xFFFF) {
    buf = Buffer_new(size + 3);
    ptag |= 0x01;
    Buffer_add_byte(buf, ptag);
    Buffer_add_be16(buf, (uint16_t)size);
    Buffer_add_buffer(buf, body);
  } else {
    buf = Buffer_new(size + 4);
    ptag |= 0x02;
    Buffer_add_byte(buf, ptag);
    Buffer_add_be32(buf, (uint32_t)size);
    Buffer_add_buffer(buf, body);
  }

  return buf;
}

Buffer *Packet_add_fingerprint_header(Buffer *body)
{
  size_t size = Buffer_size(body);
  Buffer *buf = Buffer_new(size + 3);

  Buffer_add_byte(buf, 0x99);
  Buffer_add_be16(buf, size);
  Buffer_add_buffer(buf, body);

  return buf;
}

Buffer *Packet_user_id(unsigned char *uid, size_t len)
{
  Buffer *buf = Buffer_new(len);
  Buffer_add_bytes(buf, uid, len);

  Buffer *uidpkt = Packet_add_header(buf, Packet_type_user_id);
  Buffer_free(buf);

  return uidpkt;
}
