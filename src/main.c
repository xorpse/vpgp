
#include <string.h>
#include <time.h>

#include <errno.h>
#include <limits.h>
#include <getopt.h>

#include <pthread.h>

#include "global.h"
#include "key.h"
#include "packet.h"
#include "rng.h"
#include "rsa.h"
#include "sig.h"
#include "par.h"
#include "seq.h"

char *g_entropy_src         = NULL;
unsigned int g_thread_count = DEF_NTHREADS;
unsigned int g_key_bits     = DEF_KEY_BITS;
unsigned int g_max_age      = DEF_MAX_AGE;

#define DEF_MIN_KEY_BITS 2048
#define DEF_MAX_KEY_BITS 8192

#define DEF_MIN_THREADS 1
#define DEF_MAX_THREADS 64

#define DEF_MIN_DAYS 1
#define DEF_MAX_DAYS 3650 /* 10 years */

static inline long get_boundedl(const char *from, long lower, long upper, \
    const char *err, long def)
{
  errno = 0;
  long tmp = strtol(from, NULL, 10);

  if (tmp < lower || tmp > upper || errno == ERANGE) {
    fprintf(stderr, "[e] %s Value should be: (%ld, %ld).\n", err, lower, upper);
    fprintf(stderr, "[!] Reverting to original value: %ld.\n", def);
    return def;
  } else {
    return tmp;
  }
}

static inline uint32_t get_keyid(const char *from)
{
  errno = 0;
  char *endptr = NULL;

  if (strlen(from) != 8) {
    fprintf(stderr, "[e] given keyid is not of the correct length (8).\n");
    exit(EXIT_FAILURE);
  }

  unsigned long tmp = strtoul(from, &endptr, 16);

  if (errno != ERANGE && *endptr == '\0') {
    return be32((uint32_t)tmp);
  } else {
    fprintf(stderr, "[e] given keyid is in an invalid format.\n");
    exit(EXIT_FAILURE);
  }
}

static inline void display_help()
{
  puts("[VPGP v0.1.0]\n\n" \
       "[commands] :\n" \
       "\t [-h | --help]        : display this help screen\n\n" \
       "[compulsory arguments] :\n" \
       "\t [-k | --keyid] [s]   : 8 character hexadecimal keyid to generate\n" \
       "\t [-u | --userid] [s]  : user identification string (Name <email@addre.ss>)\n\n" \
       "[optional arguments] :\n" \
       "\t [-a | --age] [n]     : maximum age <n> (in days) of generated key\n" \
       "\t [-b | --bits] [n]    : generate key with length of <n> bits\n" \
       "\t [-e | --entropy] [f] : use the file <f> as the entropy source\n" \
       "\t [-o | --output] [f]  : write generated key to <f> upon completion\n" \
       "\t [-t | --threads] [n] : use <n> threads to perform generation");
}

int main(int argc, char **argv)
{
  int opt_idx = 0, c = 0;
  static struct option opts[] = {
    {"help",    no_argument,       NULL,       'h'},
    {"output",  required_argument, NULL,       'o'},

    {"age",     required_argument, NULL,       'a'},
    {"bits",    required_argument, NULL,       'b'},
    {"entropy", required_argument, NULL,       'e'},
    {"threads", required_argument, NULL,       't'},

    {"keyid",   required_argument, NULL,       'k'},
    {"userid",  required_argument, NULL,       'u'},
    {NULL,      0,                 NULL,        0},
  };
  char *output_file = NULL;
  char *user_id = NULL;
  uint32_t pattern = 0;
  bool pattern_given = false;

  if (argc == 1) {
    display_help();
    exit(EXIT_SUCCESS);
  }

  while(c != -1) {
    c = getopt_long(argc, argv, "ho:t:a:b:e:k:u:", opts, &opt_idx);

    switch (c) {
      case 'a':
        g_max_age = get_boundedl(optarg, DEF_MIN_DAYS, DEF_MAX_DAYS, \
            "Invalid number of days as maximum age.", \
            g_max_age);
        g_max_age *= DEF_SECS_IN_DAY;
        break;
      case 'b':
        g_key_bits = get_boundedl(optarg, DEF_MIN_KEY_BITS, DEF_MAX_KEY_BITS, \
            "Invalid number of bits provided.", \
            g_key_bits);
        break;
      case 'e':
        g_entropy_src = strdup(optarg);
        break;
      case 'h':
        display_help();
        exit(EXIT_SUCCESS);
        break;
      case 'k':
        pattern_given = true;
        pattern = get_keyid(optarg);
        break;
      case 'o':
        output_file = strdup(optarg);
        break;
      case 't':
        g_thread_count = get_boundedl(optarg, DEF_MIN_THREADS, DEF_MAX_THREADS, \
            "Invalid number of threads provided.", \
            g_thread_count);
        break;
      case 'u':
        user_id = strdup(optarg);
        break;
      case '?':
        /* Unrecognised option */
        break;
      default:
        break;
    }
  }

  if (!user_id || !pattern_given) {
    fprintf(stderr, "[e] Both user ID and key ID must be provided.\n");
    exit(EXIT_FAILURE);
  }

  if (g_thread_count > 1) {
    Par_init();
  } else {
    Seq_init();
  }

  fprintf(stderr, "[i] Seeding PRG for key generation... ");
  if (Rng_seed_from(g_entropy_src ? g_entropy_src : DEF_PRG_SRC, \
        g_key_bits >> 3) != R_OK) {
    fprintf(stderr, "[e] Failed to supply the PRG with sufficient entropy.");
    exit(EXIT_FAILURE);
  }

  if (g_entropy_src) {
    free(g_entropy_src);
  }

  fprintf(stderr, "done.\n[i] Attempting to find a first-preimage for keyid...\n");

  RSAk key;
  time_t before = time(NULL);

  if (g_thread_count > 1) {
    uint32_t i = 0;
    void *tret = NULL;
    pthread_t *threads = (pthread_t *)malloc(sizeof(pthread_t) * g_thread_count);

    if (!threads) {
      fprintf(stderr, "\n[e] Cannot allocate memory for threads.\n");
      exit(EXIT_FAILURE);
    }

    pthread_mutex_t key_mutex;
    pthread_barrier_t iter_barrier;

    pthread_mutex_init(&key_mutex, NULL);
    pthread_barrier_init(&iter_barrier, NULL, g_thread_count);

    for (i = 0; i < g_thread_count; i++) {
      /* Will be freed in the cleanup of each thread */
      Par_state *st = (Par_state *)malloc(sizeof(Par_state));

      if (!st) {
        fprintf(stderr, "\n[e] Cannot allocate memory for thread state.\n");
      }

      st->tid = i;
      st->pattern = pattern;
      st->threads = threads;
      st->iter_barrier = &iter_barrier;
      st->key_mutex = &key_mutex;
      st->key = &key;

      pthread_create(&(threads[i]), NULL, Par_worker, (void *)st);
    }

    for (i = 0; i < g_thread_count; i++) {
      pthread_join(threads[i], &tret);
    }

    pthread_mutex_destroy(&key_mutex);
    pthread_barrier_destroy(&iter_barrier);

  } else {
    Seq_RSA_with_keyid(&key, pattern);
  }

  FILE *fp = NULL;

  if (output_file) {
    if (!(fp = fopen(output_file, "wb"))) {
      fprintf(stderr, "[e] Could not open `%s' for writing.\n", output_file);
      exit(EXIT_FAILURE);
    }
  } else {
    fp = stdout;
  }

  fprintf(stderr, "[i] Key found in %ld seconds.\n", (time(NULL) - before));

  fprintf(stderr, "[i] Outputting key... ");

  Buffer *body = Key_RSA_private_body(&key);
  Buffer *packet = Packet_add_header(body, Packet_type_secret_key);

  Buffer *uidp = Packet_user_id((unsigned char *)user_id, strlen(user_id));
  Buffer *sigp = Sig_RSA_packet(&key, (unsigned char *)user_id, strlen(user_id));

  fwrite(packet->buf, sizeof(uint8_t), Buffer_size(packet), fp);
  fwrite(uidp->buf, sizeof(uint8_t), Buffer_size(uidp), fp);
  fwrite(sigp->buf, sizeof(uint8_t), Buffer_size(sigp), fp);

  fprintf(stderr, "done.\n");

  if (output_file) {
    free(output_file);
    fclose(fp);
  }

  free(user_id);

  Buffer_free(packet);
  Buffer_free(body);
  Buffer_free(sigp);

  RSAk_free(&key);
  exit(EXIT_SUCCESS);
}
