#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/sha.h>

// Double SHA256 on 1MB Block:: 0.003491s ± 0.000367s
// 1o hash: 0.003551s
// 2o hash: 0s

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


int main(int argc, char **argv){
  int i;
  ssize_t ret;
  unsigned char blockchain_block[BLOCK_SIZE];
  unsigned char digest[SHA256_DIGEST_LENGTH],
    final_digest[SHA256_DIGEST_LENGTH];
  /* TIMER */
  for(i = 0; i < NTESTS; i ++){
    do{
      ret = getrandom(blockchain_block, BLOCK_SIZE, 0);
    } while(ret != BLOCK_SIZE);
    TIMER_BEGIN();
    hash(blockchain_block, BLOCK_SIZE, digest);
    hash(digest, SHA256_DIGEST_LENGTH, final_digest);
    TIMER_END();
  }
  TIMER_RESULT("Double SHA256 on 1MB Block:");
  return 0;
}
