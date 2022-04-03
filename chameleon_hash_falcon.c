#include "chameleon_hash.h"
#include "natural.h"
#include "group.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include "raptor/raptor.h"

/*
DIM: 512
PARAM_Q: 12289 (14 bits)
Digest: 7168 bits (896 bytes)

CH.KeyGen:: 0.008028s ± 0.002044s
CH.Hash:: 0.000197s ± 0.000022s
CH.Preimage:: 0.000386s ± 0.000044s
*/

struct eval_key{
  int64_t *h;
};

struct trap_key{
  unsigned char falcon_sk[CRYPTO_SECRETKEYBYTES];
};


struct message{
  int64_t *d;
};

struct randomness{
    int64_t *r0;
    int64_t *r1;
};

struct digest{
  int64_t *c;
};


struct ch_sys_params{
  int message_bits;
  int64_t *H;
};

static unsigned char nonce[PARAM_NONCE];

/* Initialization functions */
void chameleon_hash_init_sysparams(const unsigned int security_bits,
                                   struct ch_sys_params *sys){
  unsigned char   *seedH;
  int i;
  sys -> message_bits = security_bits * 2;
  if(security_bits != 128)
    fprintf(stderr, "ERROR: Unsupported security bits.\n");
  seedH = malloc(SEEDLEN);
  sys -> H = (int64_t *) malloc(sizeof(int64_t)*DIM);
  randombytes(seedH,SEEDLEN);
  pol_unidrnd_with_seed(sys -> H, DIM, PARAM_Q, seedH, SEEDLEN);
  free(seedH);
  for(i = 0; i < PARAM_NONCE; i ++)
      nonce[i] = 0;
  printf("PARAM_Q: %d\n", PARAM_Q);
}

void chameleon_hash_init_message(const struct ch_sys_params *sys,
                                 struct message *msg){
  msg -> d   =   malloc(sizeof(int64_t)*DIM);
}

void chameleon_hash_init_randomness(const struct ch_sys_params *sys,
                                    struct randomness *rnd){
  rnd -> r0 = malloc(sizeof(int64_t)*DIM);
  rnd -> r1 = malloc(sizeof(int64_t)*DIM);
}

void chameleon_hash_init_digest(const struct ch_sys_params *sys,
                                struct digest *dgt){
  dgt -> c = malloc(sizeof(int64_t)*DIM);
}

/* Finalization functions */
void chameleon_hash_destroy_sysparams(struct ch_sys_params *sys){
  free(sys -> H);
  return;
}

void chameleon_hash_destroy_keys(struct ch_sys_params *sys,
                                 struct eval_key *ek,
                                 struct trap_key *tk){
  free(ek -> h);
}

void chameleon_hash_destroy_message(struct message *msg){
  free(msg -> d);
}

void chameleon_hash_destroy_randomness(struct randomness *rnd){
  free(rnd -> r0);
  free(rnd -> r1);
}

void chameleon_hash_destroy_digest(struct digest *dgt){
  free(dgt -> c);
}

/* Print functions */
void chameleon_hash_print_sysparams(const struct ch_sys_params *sys){

}

void chameleon_hash_print_keys(const struct eval_key *ek,
                               const struct trap_key *tk){

}

void chameleon_hash_print_message(const struct message *msg){

}

void chameleon_hash_print_randomness(const struct randomness *rnd){

}


void chameleon_hash_print_digest(const struct digest *dgt){

}


/* Base Functions */
void chameleon_hash_keygen(const struct ch_sys_params *sys,
                           struct eval_key *ek,
                           struct trap_key *tk){
  int ret_val;
  unsigned char       falcon_pk[CRYPTO_PUBLICKEYBYTES];
  if((ret_val = crypto_sign_keypair(falcon_pk, tk -> falcon_sk)) != 0)
    printf("crypto_sign_keypair returned <%d>\n", ret_val);
  ek -> h = malloc(sizeof(int64_t)*DIM);
  extract_pkey(falcon_pk, ek -> h);
}

void chameleon_hash_hash(const struct ch_sys_params *sys,
                         const struct eval_key *ek,
                         const struct message *msg,
                         const struct randomness *rnd,
                         struct digest *dgt){
    int64_t *tmp1, *tmp2;
    int j;
    tmp1    = malloc(sizeof(int64_t)*DIM);
    tmp2    = malloc(sizeof(int64_t)*DIM);
    ring_mul(tmp1, msg -> d, sys -> H, DIM);
    ring_mul(tmp2, ek -> h, rnd -> r1, DIM);
    for (j=0;j<DIM;j++)
        dgt -> c[j] = (tmp1[j]+tmp2[j]+rnd -> r0[j])%PARAM_Q;
    free(tmp1);
  free(tmp2);
}

void chameleon_hash_preimage(const struct ch_sys_params *sys,
                             const struct trap_key *tk,
                             const struct message *msg,
                             const struct digest *dgt,
                             struct randomness *rnd){
  falcon_sign *fs;
  int64_t *u;
  unsigned char   *seed;
  int i;
  seed    = malloc(SEEDLEN);
  u = malloc(sizeof(int64_t)*DIM);
  ring_mul(u, msg -> d, sys -> H, DIM);
  for(i=0;i<DIM;i++)
    u[i] = (dgt -> c[i] - u[i])%PARAM_Q;
  fs = falcon_sign_new();
  if (fs == NULL)
    fprintf(stderr, "ERROR: fs == NULL\n");
  randombytes(seed, SEEDLEN);
  falcon_sign_set_seed(fs, seed, SEEDLEN, 1);
  if (!falcon_sign_set_private_key(fs, tk -> falcon_sk,
                                   CRYPTO_SECRETKEYBYTES))
    fprintf(stderr, "ERROR: falcon_sign_set_private_key failed.\n");
  if (!falcon_sign_start(fs, nonce))
    fprintf(stderr, "ERROR: falcon_sign_start failed.\n");
  if(falcon_sign_with_u(fs, u, rnd -> r0, rnd -> r1)!=0)
    fprintf(stderr, "ERROR: falcon_sign_with_u failed.\n");
  falcon_sign_free(fs);
  free(seed);
  free(u);
}

/* Sampling Functions */
void chameleon_hash_sample_randomness(const struct ch_sys_params *sys,
                                      const struct eval_key *ek,
                                      struct randomness *rnd){
  DGS(rnd -> r0, DIM, SIGMA);
  DGS(rnd -> r1, DIM, SIGMA);
}

void chameleon_hash_sample_message(const struct ch_sys_params *sys,
                                   const struct eval_key *ek,
                                   struct message *msg){
  binary_poly_gen(msg -> d, DIM);
}

void chameleon_hash_sample_digest(const struct ch_sys_params *sys,
                                  const struct eval_key *ek,
                                  struct digest *dgt){
  unsigned char   *seed;
  seed    = malloc(SEEDLEN);
  randombytes(seed, SEEDLEN);
  pol_unidrnd_with_seed(dgt -> c, DIM, PARAM_Q, seed, SEEDLEN);
  free(seed);
}


bool compare_digest(struct digest *dgt1, struct digest *dgt2){
  int i;
  /*for(i=0; i < DIM; i++)
    printf("(%lx)", dgt1->c[i] % PARAM_Q);
  printf("\n");
  for(i=0; i < DIM; i++)
    printf("(%lx)",  dgt2->c[i] % PARAM_Q);
  printf("\n");
  printf("{%d}\n", PARAM_Q);*/

  for(i=0; i < DIM; i++)
    if(((dgt1 -> c[i] - dgt2 -> c[i]) % PARAM_Q) != 0)
      return false;
  return true;
}
