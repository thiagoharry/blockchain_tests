#include "preimage_chameleon_hash.h"
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define NTESTS 1000 // Number of times we measure each function
#include "timer.h"

// Computing hash on 1MB Block:: 0.005405s ± 0.001014s
// Redacting block:              0.016025s ± 0.000497s

#define NTESTS 1000 // Number of times we measure each function
#include "timer.h"

// COmpile with -lcrypto

#define BLOCK_SIZE (1024 * 1024)

static unsigned int shake_digest_size = 373; // In bytes

void hash(unsigned char *string, size_t size, unsigned char *digest){
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, string, size);
  SHA256_Final(digest, &sha256);
}

void shake(unsigned char *string, size_t size, unsigned char *digest){
  EVP_MD_CTX *mdctx;
  if((mdctx = EVP_MD_CTX_new()) == NULL)
    exit(1);
  if(1 != EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL))
    exit(1);
  if(1 != EVP_DigestUpdate(mdctx, string, size))
    exit(1);
  if(1 != EVP_DigestFinalXOF(mdctx, digest, shake_digest_size))
    exit(1);
  EVP_MD_CTX_free(mdctx);
}

int main(int argc, char **argv){
  int i, j;
  ssize_t ret, ret2;
  struct eval_key ek;
  struct trap_key tk;
  unsigned char blockchain_block[BLOCK_SIZE], second_block[BLOCK_SIZE];
  unsigned char digest[SHA256_DIGEST_LENGTH],  digest2[SHA256_DIGEST_LENGTH];
  unsigned char shake_msg[1024];
  unsigned char *shake_digest;
  size_t count = 0, count2 = 0;
  struct ch_sys_params sys;
  struct message msg, msg2;
  struct randomness rnd1;
  struct digest dgt, dgt2;
  shake_digest = (unsigned char *) malloc(shake_digest_size);
  msg.size = SHA256_DIGEST_LENGTH;
  msg2.size = SHA256_DIGEST_LENGTH;
  chameleon_hash_init_sysparams(128, &sys);
  chameleon_hash_keygen(&sys, &ek, &tk);
  chameleon_hash_init_randomness(&sys, &rnd1);
  chameleon_hash_init_digest(&sys, &dgt);
  chameleon_hash_init_digest(&sys, &dgt2);
  /* TIMER */
  for(i = 0; i < NTESTS; i ++){
    do{
      ret = getrandom(blockchain_block, BLOCK_SIZE, 0);
    } while(ret != BLOCK_SIZE);
    TIMER_BEGIN();
    hash(blockchain_block, BLOCK_SIZE, digest); // SHA256 over the 1MB block
    msg.msg = digest;
    chameleon_hash_sample_randomness(&sys, &ek, &rnd1); // Sample randomness rnd
    chameleon_hash_hash(&sys, &ek, &msg, &rnd1, &dgt); // Now compute CH.Hash(ek, ., rnd) over the result
    mpz_export (shake_msg, &count, 1, 1, 0, 0, dgt.value); // Pass this to a buffer
    mpz_export (&(shake_msg[count]), &count2, 1, 1, 0, 0, rnd1.value); // Concatenate rnd to the result
    shake(shake_msg, count + count2, shake_digest); // And compute the final digest 
    TIMER_END();
    for(j =0; j < shake_digest_size; j ++)
      printf("%04x", shake_digest[j]);
    printf("\n");
  }
  TIMER_RESULT("Computing hash on 1MB Block:");
  /* TIMER */
  for(i = 0; i < NTESTS; i ++){
    do{
      ret = getrandom(blockchain_block, BLOCK_SIZE, 0); // Original block
      ret2 = getrandom(second_block, BLOCK_SIZE, 0); // New block
    } while(ret != BLOCK_SIZE || ret2 != BLOCK_SIZE);
    hash(blockchain_block, BLOCK_SIZE, digest); // SHA256 over original block
    chameleon_hash_sample_randomness(&sys, &ek, &rnd1); // Sample original randomness
    chameleon_hash_hash(&sys, &ek, &msg, &rnd1, &dgt);
    mpz_export (shake_msg, &count, 1, 1, 0, 0, dgt.value);
    mpz_export (&(shake_msg[count]), &count2, 1, 1, 0, 0, rnd1.value);
    shake(shake_msg, count + count2, shake_digest); // Compute original digest
    TIMER_BEGIN();
    hash(second_block, BLOCK_SIZE, digest2); // SHA256 over new block
    msg2.msg = digest;
    mpz_import(dgt2.value, shake_digest_size, 1, 1, 0, 0, shake_digest);
    mpz_powm_ui(dgt2.value, dgt2.value, 2, tk.n); // Target digest
    chameleon_hash_preimage(&sys, &tk, &msg2, &dgt2, &rnd1); // Compute new rnd
    TIMER_END();
    // Checking the result:
    chameleon_hash_hash(&sys, &ek, &msg2, &rnd1, &dgt);
    if(mpz_cmp(dgt.value, dgt2.value) != 0)
      fprintf(stderr, "ERROR: Incorrect value!!!!!!!!!!!\n");
  }
  TIMER_RESULT("Redacting  1MB Block:");
  free(shake_digest);
  return 0;
}
