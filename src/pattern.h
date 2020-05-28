
#ifndef _VPGP_PATTERN_H_
#define _VPGP_PATTERN_H_

#include "key.h"

static inline int Pattern_match_keyid(unsigned char *fp, uint32_t pat)
{
  return *((uint32_t *)(fp + (KEY_FINGERPRINT_LEN - sizeof(uint32_t)))) == pat;
}

#endif
