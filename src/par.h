
#ifndef _VPGP_PAR_H_
#define _VPGP_PAR_H_

#include <stdint.h>
#include <pthread.h>

#include "rsa.h"

struct par_state {
  uint32_t tid;
  uint32_t pattern;

  pthread_t *threads;

  pthread_barrier_t *iter_barrier;

  pthread_mutex_t *key_mutex;
  RSAk *key;
};

typedef struct par_state Par_state;

extern void Par_init(void);
extern void Par_terminate(void);

extern void *Par_worker(void *state);

#endif
