
#ifndef _VPGP_BUFFER_H_
#define _VPGP_BUFFER_H_

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#include <openssl/bn.h>

/* Note that pos is the index of the _next_ byte to write to not the last byte
 * written */
struct buffer {
  unsigned char *buf;
  off_t pos;
  size_t size;
};

typedef struct buffer Buffer;

extern Buffer *Buffer_new(size_t initial_size);
extern void Buffer_free(Buffer *buffer);

/* The number of bytes occupied by the stored elements (not the amount of
 * memory taken by the buffer) */
extern size_t Buffer_size(Buffer *buffer);

/* Allocates space for a given amount of bytes (changes the size of the
 * buffer). The space reserved will be uninitialised (so should be set
 * as needed to avoid unexpected results) */
extern size_t Buffer_reserve(Buffer *buffer, size_t n);

/* Functions return the size in bytes of the item appended to the buffer
 * they return 0 on failure */

extern size_t Buffer_add_byte(Buffer *buffer, unsigned char b);
extern size_t Buffer_add_bytes(Buffer *buffer, unsigned char *bytes, \
    size_t n);
extern size_t Buffer_add_buffer(Buffer *buf, Buffer *src);

/* Encodes the given integer into big-endian and then stores it */
extern size_t Buffer_add_be16(Buffer *buffer, uint16_t n);
extern size_t Buffer_add_be32(Buffer *buffer, uint32_t n);

/* Encodes the given BIGNUM into an OpenPGP Message Format (RFC4880) MPI and
 * stores it */
extern size_t Buffer_add_mpi(Buffer *buffer, const BIGNUM *bn);

#endif
