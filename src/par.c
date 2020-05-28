
#include <stdint.h>
#include <stdbool.h>

#include <openssl/crypto.h>
#include <pthread.h>

#include "global.h"
#include "key.h"
#include "par.h"
#include "rsa.h"
#include "seq.h"

static pthread_mutex_t *locks;

/* pthread callbacks for OpenSSL */
struct CRYPTO_dynlock_value {
  pthread_mutex_t mutex;
};

static void locking_function(int mode, int n, const char *file, int line)
{
  (void)file;
  (void)line;

  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(locks[n]));
  } else {
    pthread_mutex_unlock(&(locks[n]));
  }
}

static void threadid_func(CRYPTO_THREADID *id)
{
  CRYPTO_THREADID_set_numeric(id, (unsigned long)pthread_self());
}

static struct CRYPTO_dynlock_value *dyn_create_function(const char *file, \
    int line)
{
  (void)file;
  (void)line;

  struct CRYPTO_dynlock_value *dv = NULL;

  if (!(dv = (struct CRYPTO_dynlock_value *)malloc(sizeof(struct CRYPTO_dynlock_value)))) {
    return NULL;
  } else {
    pthread_mutex_init(&(dv->mutex), NULL);
    return dv;
  }
}

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l, const char *file, \
    int line)
{
  (void)file;
  (void)line;

  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(l->mutex));
  } else {
    pthread_mutex_unlock(&(l->mutex));
  }
}

static void dyn_destroy_function(struct CRYPTO_dynlock_value *l, const char *file, \
    int line)
{
  (void)file;
  (void)line;
  pthread_mutex_destroy(&(l->mutex));
  free(l);
}

void Par_init(void)
{
  Seq_init();

  locks = (pthread_mutex_t *)malloc(CRYPTO_num_locks() * \
      sizeof(pthread_mutex_t));

  if (!locks) {
    fprintf(stderr, "[e] Cannot allocate memory for OpenSSL lock array.\n");
    exit(EXIT_FAILURE);
  }

  for (int i = 0; i < CRYPTO_num_locks(); i++) {
    pthread_mutex_init(&(locks[i]), NULL);
  }

  CRYPTO_THREADID_set_callback(&threadid_func);
  CRYPTO_set_locking_callback(&locking_function);

  CRYPTO_set_dynlock_create_callback(&dyn_create_function);
  CRYPTO_set_dynlock_lock_callback(&dyn_lock_function);
  CRYPTO_set_dynlock_destroy_callback(&dyn_destroy_function);
}

void Par_terminate(void)
{
  Seq_terminate();

  for (int i = 0; i < CRYPTO_num_locks(); i++) {
    pthread_mutex_destroy(&(locks[i]));
  }
  free(locks);
}

void Par_worker_buf_cleanup(void *buffer)
{
  Buffer_free((Buffer *)buffer);
}

void Par_worker_st_cleanup(void *state)
{
  free(state);
}

void *Par_worker(void *state)
{
  Par_state *st = (Par_state *)state;
  uint32_t max_age = 0, timestamp = 0;
  unsigned char fp[KEY_FINGERPRINT_LEN];

  pthread_cleanup_push(Par_worker_st_cleanup, state);

  while (true) {
    pthread_testcancel();
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_barrier_wait(st->iter_barrier);

    if (st->tid == 0) {
      pthread_mutex_lock(st->key_mutex);
      RSAk_new(st->key, g_key_bits, DEF_RSA_E);
      pthread_mutex_unlock(st->key_mutex);
    }

    pthread_barrier_wait(st->iter_barrier);
    Buffer *fpm = Key_RSA_fingerprint_material(st->key);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

    pthread_cleanup_push(Par_worker_buf_cleanup, (void *)fpm);

    max_age = st->key->timestamp - g_max_age;
    timestamp = st->key->timestamp - st->tid;

    while (timestamp > max_age) {
      pthread_testcancel();
      pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
      Key_fingerprint_from(fpm, timestamp, fp);

      if (Pattern_match_keyid(fp, st->pattern)) {
        pthread_mutex_lock(st->key_mutex);
        fprintf(stderr, "[i] First-preimage found by (tid = %u).\n", st->tid);

        st->key->timestamp = timestamp;

        pthread_t self = pthread_self();

        fprintf(stderr, "[i] Stopping sibling threads... ");
        for (size_t i = 0; i < g_thread_count; i++) {
          if (self != st->threads[i]) {
            pthread_cancel(st->threads[i]);
          }
        }
        fprintf(stderr, "done.\n");

        pthread_mutex_unlock(st->key_mutex);
        pthread_exit(NULL);
      }
      timestamp -= g_thread_count;
      pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    }
    pthread_cleanup_pop(0);
    free(fpm);
  }

  /* Never reached */
  pthread_cleanup_pop(0);
  pthread_exit(NULL);
}
