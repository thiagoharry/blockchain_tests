#include "preimage_chameleon_hash.h"
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

/*
128 bits in CH:
Computing hash on 1MB Block:: 0.004150s ± 0.000312s
Redacting  1MB Block:: 0.004418s ± 0.000553s

(Weierstrass curve - appear to be slower)
146 bits 
Computing hash on 1MB Block:: 0.005953s ± 0.000714s
Redacting  1MB Block:: 0.005066s ± 0.000386s


192 bits in CH:
Computing hash on 1MB Block:: 0.004849s ± 0.000376s
Redacting  1MB Block:: 0.005488s ± 0.000739s
*/

#define NTESTS 1000 // Number of times we measure each function
#include "timer.h"


#define NTESTS 1000 // Number of times we measure each function
#include "timer.h"

// COmpile with -lcrypto

#define BLOCK_SIZE (1024 * 1024)

/*void hash(unsigned char *string, size_t size, unsigned char *digest){
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, string, size);
  SHA256_Final(digest, &sha256);
  }*/

/*void shake256(unsigned char *string, size_t size, unsigned char *digest,
	      size_t digest_size){
  EVP_MD_CTX *mdctx;
  if((mdctx = EVP_MD_CTX_new()) == NULL)
    exit(1);
  if(1 != EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL))
    exit(1);
  if(1 != EVP_DigestUpdate(mdctx, string, size))
    exit(1);
  if(1 != EVP_DigestFinalXOF(mdctx, digest, digest_size))
    exit(1);
  EVP_MD_CTX_free(mdctx);
  }*/

int main(int argc, char **argv){
  int i;
  ssize_t ret, ret2;
  struct eval_key ek;
  struct trap_key tk;
  unsigned char blockchain_block[BLOCK_SIZE], second_block[BLOCK_SIZE];
  unsigned char digest[SHA256_DIGEST_LENGTH + 1];
  unsigned char buffer[1024];
  //unsigned char *shake_digest;
  struct ch_sys_params sys;
  struct message msg1, msg2;
  struct randomness rnd1, rnd2;
  struct digest dgt, dgt2;
  //shake_digest = (unsigned char *) malloc(shake_digest_size);
  chameleon_hash_init_sysparams(142, &sys);
  //chameleon_hash_init_message(&sys, &msg1);
  //chameleon_hash_init_message(&sys, &msg2);
  chameleon_hash_keygen(&sys, &ek, &tk);
  chameleon_hash_init_randomness(&sys, &rnd1);
  chameleon_hash_init_randomness(&sys, &rnd2);
  chameleon_hash_init_digest(&sys, &dgt);
  chameleon_hash_init_digest(&sys, &dgt2);
  /* TIMER */
  for(i = 0; i < NTESTS; i ++){
    size_t size;
    do{
      ret = getrandom(&blockchain_block, BLOCK_SIZE, 0);
    } while(ret != BLOCK_SIZE);
    msg1.msg = blockchain_block;
    msg1.size = BLOCK_SIZE;
    TIMER_BEGIN();
    chameleon_hash_sample_randomness(&sys, &ek, &rnd1);
    chameleon_hash_hash(&sys, &ek, &msg1, &rnd1, &dgt);
    BN_bn2bin(dgt.value, buffer);
    size = BN_num_bytes(dgt.value);
    hash(buffer, size, digest);
    TIMER_END();
    //for(j =0; j < shake_digest_size; j ++)
    //  printf("%04x", shake_digest[j]);
    //printf("\n");
  }
  TIMER_RESULT("Computing hash on 1MB Block:");
  
  
  for(i = 0; i < NTESTS; i ++){
    do{
      ret = getrandom(blockchain_block, BLOCK_SIZE, 0); // Original block
      ret2 = getrandom(second_block, BLOCK_SIZE, 0); // New block
    } while(ret != BLOCK_SIZE || ret2 != BLOCK_SIZE);
    msg1.msg = blockchain_block;
    msg1.size = BLOCK_SIZE;
    msg2.msg = second_block;
    msg2.size = BLOCK_SIZE;
    chameleon_hash_sample_randomness(&sys, &ek, &rnd1);
    chameleon_hash_hash(&sys, &ek, &msg1, &rnd1, &dgt);
    TIMER_BEGIN();
    chameleon_hash_preimage(&sys, &tk, &msg2, &dgt, &rnd2);
    TIMER_END();
    // Checking the result:
    chameleon_hash_hash(&sys, &ek, &msg1, &rnd1, &dgt2);
    if(!compare_digest(&dgt, &dgt2))
      fprintf(stderr, "ERROR: Incorrect value!!!!!!!!!!!\n");
  }
  TIMER_RESULT("Redacting  1MB Block:");
  return 0;
}
