
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <openssl/bn.h>

#include "global.h"
#include "buffer.h"
#include "byteops.h"

Buffer *Buffer_new(size_t initial_size)
{
  Buffer *buf = (Buffer *)malloc(sizeof(Buffer));

  if (!buf) {
    return NULL;
  }

  buf->buf = (unsigned char *)malloc(initial_size);

  if (!buf->buf) {
    free(buf);
    return NULL;
  }

  buf->size = initial_size;
  buf->pos = 0;

  return buf;
}

void Buffer_free(Buffer *buf)
{
  free(buf->buf);
  free(buf);
}

size_t Buffer_size(Buffer *buf)
{
  return buf->pos;
}

static inline size_t Buffer_expand(Buffer *buf, size_t extra)
{
  if (buf->pos + extra > buf->size) {
    if ((buf->buf = realloc(buf->buf, buf->pos + extra))) {
      buf->size = buf->pos + extra;
      return extra;
    } else {
      return 0;
    }
  }
  return extra;
}
;
static inline size_t Buffer_store(Buffer *buf, unsigned char *src, size_t n)
{
  if (!Buffer_expand(buf, n)) {
    return 0;
  }

  memcpy(buf->buf + buf->pos, src, n);
  buf->pos += n;

  return n;
}

size_t Buffer_reserve(Buffer *buf, size_t n)
{
  if (!Buffer_expand(buf, n)) {
    return 0;
  }

  buf->pos += n;
  return n;
}

size_t Buffer_add_byte(Buffer *buf, unsigned char b)
{
  return Buffer_store(buf, &b, sizeof(b));
}

size_t Buffer_add_bytes(Buffer *buf, unsigned char *bytes, size_t n)
{
  return Buffer_store(buf, bytes, n);
}

size_t Buffer_add_be16(Buffer *buf, uint16_t n)
{
  return Buffer_store(buf, (unsigned char *)&(uint16_t){ be16(n) }, sizeof(n));
}

size_t Buffer_add_be32(Buffer *buf, uint32_t n)
{
  return Buffer_store(buf, (unsigned char *)&(uint32_t){ be32(n) }, sizeof(n));
}

size_t Buffer_add_mpi(Buffer *buf, const BIGNUM *bn)
{
  size_t size = BN_num_bytes(bn);
  size_t mpi_size = size + sizeof(uint16_t);

  /* Ensure enough space in buffer */
  if (!Buffer_expand(buf, mpi_size)) {
    return 0;
  }

  /* Write the binary representation of the BN into the buffer
   * at the offset following its size */
  BN_bn2bin(bn, buf->buf + buf->pos + sizeof(uint16_t));
  *((uint16_t *)(buf->buf + buf->pos)) = be16(BN_num_bits(bn));

  buf->pos += mpi_size;

  return mpi_size;
}

size_t Buffer_add_buffer(Buffer *buf, Buffer *src)
{
  return Buffer_add_bytes(buf, src->buf, Buffer_size(src));
}
