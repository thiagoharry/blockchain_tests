#include "secret_coin_chameleon_hash.h"
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

// Computing hash on 1MB Block:: 0.011589s ± 0.000597s
// Verifying 1MB Block::         0.010889s ± 0.000307s
// Redacting  1MB Block::        0.010345s ± 0.000718s

#define NTESTS 1000 // Number of times we measure each function
#include "timer.h"


#define NTESTS 1000 // Number of times we measure each function
#include "timer.h"

// COmpile with -lcrypto

#define BLOCK_SIZE (1024 * 1024)

void hash(unsigned char *string, size_t size, unsigned char *digest){
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, string, size);
  SHA256_Final(digest, &sha256);
}

void shake256(unsigned char *string, size_t size, unsigned char *digest,
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
}

int main(int argc, char **argv){
  int i;
  ssize_t ret, ret2;
  struct eval_key ek;
  struct trap_key tk;
  unsigned char blockchain_block[BLOCK_SIZE], second_block[BLOCK_SIZE];
  unsigned char digest0[SHA256_DIGEST_LENGTH + 1],
    digest00[SHA256_DIGEST_LENGTH + 1],
    digest[SHA256_DIGEST_LENGTH],
    digest2[SHA256_DIGEST_LENGTH];
  unsigned char buffer[640];
  //unsigned char *shake_digest;
  size_t count = 0, count2;
  struct ch_sys_params sys;
  struct message msg1, msg2;
  struct verification str1, str2;
  struct digest dgt, dgt2;
  //shake_digest = (unsigned char *) malloc(shake_digest_size);
  chameleon_hash_init_sysparams(128, &sys);
  chameleon_hash_init_message(&sys, &msg1);
  chameleon_hash_init_message(&sys, &msg2);
  chameleon_hash_keygen(&sys, &ek, &tk);
  chameleon_hash_init_verification(&sys, &str1);
  chameleon_hash_init_verification(&sys, &str2);
  chameleon_hash_init_digest(&sys, &dgt);
  chameleon_hash_init_digest(&sys, &dgt2);
  /* TIMER */
  for(i = 0; i < NTESTS; i ++){
    do{
      ret = getrandom(blockchain_block, BLOCK_SIZE, 0);
    } while(ret != BLOCK_SIZE);
    TIMER_BEGIN();
    shake256(blockchain_block, BLOCK_SIZE, digest0, SHA256_DIGEST_LENGTH + 1); // SHA256 over the block
    mpz_import(msg1.value, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, digest0); // Convert to an integer
    mpz_powm_ui(msg1.value, msg1.value, 2, sys.prime); // Should be quadratic residue
    chameleon_hash_hash(&sys, &ek, &msg1, &dgt, &str1); // Now compute CH.Hash(ek, .) over the result
    mpz_export(buffer, &count, 1, 1, 0, 0, dgt.c1); 
    mpz_export(&(buffer[count]), &count2, 1, 1, 0, 0, dgt.c2); // Pass this to a buffer
    hash(buffer, count+count2, digest);  // And compute the final digest 
    TIMER_END();
    //for(j =0; j < shake_digest_size; j ++)
    //  printf("%04x", shake_digest[j]);
    //printf("\n");
  }
  TIMER_RESULT("Computing hash on 1MB Block:");


  /* TIMER */
  for(i = 0; i < NTESTS; i ++){
    int j;
    bool ok = true;
    do{
      ret = getrandom(blockchain_block, BLOCK_SIZE, 0);
    } while(ret != BLOCK_SIZE);
    shake256(blockchain_block, BLOCK_SIZE, digest0, SHA256_DIGEST_LENGTH + 1); // Shake256 over the block
    mpz_import(msg1.value, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, digest0); // Convert to an integer
    mpz_powm_ui(msg1.value, msg1.value, 2, sys.prime); // Should be quadratic residue
    chameleon_hash_hash(&sys, &ek, &msg1, &dgt, &str1); // Now compute CH.Hash(ek, .) over the result
    mpz_export(buffer, &count, 1, 1, 0, 0, dgt.c1); 
    mpz_export(&(buffer[count]), &count2, 1, 1, 0, 0, dgt.c2); // Pass this to a buffer
    hash(buffer, count+count2, digest);  // And compute the final digest 
    TIMER_BEGIN();
    // Verifying:
    shake256(blockchain_block, BLOCK_SIZE, digest0, SHA256_DIGEST_LENGTH + 1); // SHA256 over the block
    mpz_import(msg1.value, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, digest0); // Convert to an integer
    mpz_powm_ui(msg1.value, msg1.value, 2, sys.prime); // Should be quadratic residue
    if(!chameleon_hash_verify(&sys, &ek, &msg1, &dgt, &str1))
      ok = false;
    mpz_export(buffer, &count, 1, 1, 0, 0, dgt.c1); 
    mpz_export(&(buffer[count]), &count2, 1, 1, 0, 0, dgt.c2); // Pass this to a buffer
    hash(buffer, count+count2, digest2);  // And compute the final digest 
    for(j = 0; j < SHA256_DIGEST_LENGTH; j ++)
      if(digest[j] != digest2[j])
	ok = false;
    TIMER_END();
    if(!ok)
      printf("ERROR VERIFYING...\n");
  }
  TIMER_RESULT("Verifying 1MB Block:");


  /* TIMER */
  for(i = 0; i < NTESTS; i ++){
    do{
      ret = getrandom(blockchain_block, BLOCK_SIZE, 0); // Original block
      ret2 = getrandom(second_block, BLOCK_SIZE, 0); // New block
    } while(ret != BLOCK_SIZE || ret2 != BLOCK_SIZE);
    shake256(blockchain_block, BLOCK_SIZE, digest0, SHA256_DIGEST_LENGTH + 1); // Shake256 over the block
    mpz_import(msg1.value, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, digest0); // Convert to an integer
    mpz_powm_ui(msg1.value, msg1.value, 2, sys.prime); // Should be quadratic residue
    chameleon_hash_hash(&sys, &ek, &msg1, &dgt, &str1); // Compute initial CH.Hash
    TIMER_BEGIN();
    shake256(second_block, BLOCK_SIZE, digest00, SHA256_DIGEST_LENGTH + 1); // Shake256 over second block
    mpz_import(msg2.value, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, digest00); // Convert to an integer
    mpz_powm_ui(msg2.value, msg2.value, 2, sys.prime); // Should be quadratic residue
    chameleon_hash_collision(&sys, &tk, &msg1, &dgt, &str1, &msg2, &str2); // COmpute collision
    TIMER_END();
    // Checking the result:
    if(!chameleon_hash_verify(&sys, &ek, &msg2, &dgt, &str2))
      fprintf(stderr, "ERROR: Incorrect value!!!!!!!!!!!\n");
  }
  TIMER_RESULT("Redacting  1MB Block:");
  return 0;
}
