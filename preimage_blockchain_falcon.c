#include "preimage_chameleon_hash.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <gmp.h>

#define NTESTS 1000 // Number of times we measure each function
#include "timer.h"

/*
 *
Computing hash on 1MB Block:: 0.004208s ± 0.000588s
Redacting  1MB Block:: 0.004514s ± 0.000463s
*/


#define NTESTS 1000 // Number of times we measure each function
#include "timer.h"

// COmpile with -lcrypto

#define BLOCK_SIZE (1024 * 1024)

static unsigned int shake_digest_size = 896; // In bytes

void hash(unsigned char *string, size_t size, unsigned char *digest){
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, string, size);
  SHA256_Final(digest, &sha256);
}

/*void sha512(unsigned char *string, size_t size, unsigned char *digest){
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, string, size);
    SHA512_Final(digest, &sha512);
}*/


void shake(unsigned char *string, size_t size, unsigned char *digest,
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
    int i, j;
    ssize_t ret, ret2;
    struct eval_key ek;
    struct trap_key tk;
    unsigned char blockchain_block[BLOCK_SIZE], second_block[BLOCK_SIZE];
    unsigned char block_first_hash[SHA512_DIGEST_LENGTH],
        block_first_hash2[SHA512_DIGEST_LENGTH];
    unsigned char shake_msg[13000];
    unsigned char *shake_digest;
    size_t elements_size = sizeof(int64_t)*512;
    struct ch_sys_params sys;
    struct message msg, msg2;
    struct randomness rnd1;
    struct digest dgt, dgt2;
    shake_digest = (unsigned char *) malloc(shake_digest_size);
    chameleon_hash_init_sysparams(128, &sys);
    chameleon_hash_keygen(&sys, &ek, &tk);
    chameleon_hash_init_randomness(&sys, &rnd1);
    chameleon_hash_init_digest(&sys, &dgt);
    chameleon_hash_init_message(&sys, &msg);
    chameleon_hash_init_message(&sys, &msg2);
    chameleon_hash_init_digest(&sys, &dgt2);
    /* TIMER */
    for(i = 0; i < NTESTS; i ++){
        do{
            ret = getrandom(blockchain_block, BLOCK_SIZE, 0);
        } while(ret != BLOCK_SIZE);
        TIMER_BEGIN();
        shake(blockchain_block, BLOCK_SIZE, block_first_hash,
              SHA512_DIGEST_LENGTH);
        //sha512(blockchain_block, BLOCK_SIZE, block_first_hash);
        for(j = 0; j < SHA512_DIGEST_LENGTH; j ++){
            int k, pos = 0;
            for(k = 0; k < 8; k ++){
                msg.d[pos] = block_first_hash[j] % 2;
                block_first_hash[j] >>= 1;
                pos ++;
            }
        }

        chameleon_hash_sample_randomness(&sys, &ek, &rnd1); // Sample randomness rnd
        chameleon_hash_hash(&sys, &ek, &msg, &rnd1, &dgt); // Now compute CH.Hash(ek, ., rnd) over the result
        memcpy(shake_msg, dgt.c, elements_size);
        memcpy(&(shake_msg[elements_size]), rnd1.r0, elements_size);
        memcpy(&(shake_msg[elements_size*2]), rnd1.r1, elements_size);
        shake(shake_msg, elements_size * 3, shake_digest, shake_digest_size); // And compute the final digest
        TIMER_END();
        //for(j =0; j < shake_digest_size; j ++)
        //    printf("%02x", shake_digest[j]);
        //printf("\n\n");
    }
    TIMER_RESULT("Computing hash on 1MB Block:");
    /* TIMER */
   for(i = 0; i < NTESTS; i ++){
       do{
           ret = getrandom(blockchain_block, BLOCK_SIZE, 0); // Original block
           ret2 = getrandom(second_block, BLOCK_SIZE, 0); // New block
       } while(ret != BLOCK_SIZE || ret2 != BLOCK_SIZE);
       shake(blockchain_block, BLOCK_SIZE, block_first_hash,
             SHA512_DIGEST_LENGTH);
       //sha512(blockchain_block, BLOCK_SIZE, block_first_hash);
       for(j = 0; j < SHA512_DIGEST_LENGTH; j ++){
           int k, pos = 0;
           for(k = 0; k < 8; k ++){
               msg.d[pos] = block_first_hash[j] % 2;
               block_first_hash[j] >>= 1;
               pos ++;
           }
       }
       chameleon_hash_sample_randomness(&sys, &ek, &rnd1); // Sample original randomness
       chameleon_hash_hash(&sys, &ek, &msg, &rnd1, &dgt);
       memcpy(shake_msg, dgt.c, elements_size);
       memcpy(&(shake_msg[elements_size]), rnd1.r0, elements_size);
       memcpy(&(shake_msg[elements_size*2]), rnd1.r1, elements_size);
       shake(shake_msg, elements_size * 3, shake_digest, shake_digest_size); // And compute original digest
       TIMER_BEGIN();
       // Hash over new block
       shake(second_block, BLOCK_SIZE, block_first_hash2,
             SHA512_DIGEST_LENGTH);
       //sha512(second_block, BLOCK_SIZE, block_first_hash2);
       for(j = 0; j < SHA512_DIGEST_LENGTH; j ++){
           int k, pos = 0;
           for(k = 0; k < 8; k ++){
               msg2.d[pos] = block_first_hash[j] % 2;
               block_first_hash[j] >>= 1;
               pos ++;
           }
       }
       // Converting the digest
       {
           mpz_t intermediate;
           mpz_init(intermediate);
           mpz_import(intermediate, shake_digest_size, 1, 1, 1, 0, shake_digest);
           for(j = 0; j < 512; j ++){
               dgt2.c[j] = mpz_fdiv_ui(intermediate, 12289);
               mpz_fdiv_q_ui(intermediate, intermediate, 12289);
           }
           mpz_clear(intermediate);
       }
        chameleon_hash_preimage(&sys, &tk, &msg2, &dgt2, &rnd1); // Compute new rnd
        TIMER_END();
        // Checking the result:
        chameleon_hash_hash(&sys, &ek, &msg2, &rnd1, &dgt);
        if(!compare_digest(&dgt, &dgt2))
            fprintf(stderr, "ERROR: Incorrect value!!!!!!!!!!!\n");
    }
   TIMER_RESULT("Redacting  1MB Block:");
    free(shake_digest);
    return 0;}
