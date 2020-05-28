
#ifndef _VPGP_GLOBAL_
#define _VPGP_GLOBAL_

#define FALSE 0
#define TRUE  !FALSE

#define DEF_KEY_BITS  4096
#define DEF_RSA_E     65537

#define DEF_PRG_BYTES (DEF_KEY_BITS >> 3)
#define DEF_PRG_SRC   "/dev/random"

#define DEF_NTHREADS  2

#define DEF_SECS_IN_DAY  (60 * 60 * 24)
#define DEF_SECS_IN_YEAR (365 * DEF_SECS_IN_DAY)
#define DEF_MAX_AGE      DEF_SECS_IN_YEAR

#define min(X, Y) (X <= Y ? X : Y)
#define max(X, Y) (X >= Y ? X : Y)

typedef enum _result_t { R_OK, R_ERROR } result_t;

extern char *g_entropy_src;
extern unsigned int g_thread_count;
extern unsigned int g_key_bits;
extern unsigned int g_max_age;

#endif
