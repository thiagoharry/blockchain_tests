#include "ring_sis/chameleon_hash_ring_sis.h"
#include "ring_sis/context.h"
#include <cereal/archives/binary.hpp>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sstream>
#include <sys/random.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <gmp.h>

#define NTESTS 1000 // Number of times we measure each function
#include "timer.h"

using namespace lbcrypto;
using namespace std;

/*
 *
Computing hash on 1MB Block:: 0.011479s ± 0.000693s
Redacting  1MB Block:: 0.032208s ± 0.001784s
*/


#define NTESTS 1000 // Number of times we measure each function
#include "timer.h"



#define BLOCK_SIZE (1024 * 1024)

static unsigned int shake_digest_size = 4191; // In bytes (same size than CH.Hash() digest)

void shake(const char *string, size_t size, unsigned char *digest,
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
  ChameleonHashContext<NativePoly> context;
  GPVVerificationKey<NativePoly> vk;
  GPVSignKey<NativePoly> sk;
  GPVSignature<NativePoly> r, r2;
  NativePoly digest1, digest2;
  int i;//, j;
  ssize_t ret, ret2;
  char blockchain_block[BLOCK_SIZE], second_block[BLOCK_SIZE];
  unsigned char *shake_digest;
  shake_digest = (unsigned char *) malloc(shake_digest_size);
  context.GenerateGPVContext(512, 27, 2);
  context.KeyGen(&sk,&vk);

  // TIMER
  for(i = 0; i < NTESTS; i ++){
    do{
      ret = getrandom(blockchain_block, BLOCK_SIZE, 0);
    } while(ret != BLOCK_SIZE);
    string block(blockchain_block, BLOCK_SIZE);
    GPVPlaintext<NativePoly> plaintext(block);
    TIMER_BEGIN();
    context.GetRandomParameter(sk,vk,&r); // Sample randomness
    context.Hash(plaintext,r,vk, &digest1);
    // Copy digest and randomness to compute final hash
    std::stringstream ss;
    Matrix<NativePoly> mat = r.GetSignature();
    Serial::Serialize(digest1, ss, SerType::BINARY);
    //printf("%lu\n", ss.str().size()); // 4191
    Serial::Serialize(mat, ss, SerType::BINARY);
    //printf("%lu\n", ss.str().size()); // 128383
    const string tmp = ss.str();
    const char* cstr = tmp.c_str();
    shake(cstr, tmp.size(), shake_digest, shake_digest_size);
    TIMER_END();
  }
  TIMER_RESULT("Computing hash on 1MB Block:");
    
  // TIMER
  for(i = 0; i < NTESTS; i ++){
    do{
      ret = getrandom(blockchain_block, BLOCK_SIZE, 0); // Original block
      ret2 = getrandom(second_block, BLOCK_SIZE, 0); // New block
    } while(ret != BLOCK_SIZE || ret2 != BLOCK_SIZE);
    string block1(blockchain_block, BLOCK_SIZE);
    string block2(blockchain_block, BLOCK_SIZE);
    GPVPlaintext<NativePoly> plaintext1(block1);
    context.GetRandomParameter(sk,vk,&r); // Sample randomness
    context.Hash(plaintext1,r,vk, &digest1);
    std::stringstream ss;
    Matrix<NativePoly> mat = r.GetSignature();
    Serial::Serialize(digest1, ss, SerType::BINARY);
    Serial::Serialize(mat, ss, SerType::BINARY);
    const string tmp = ss.str();
    const char* cstr = tmp.c_str();
    shake(cstr, tmp.size(), shake_digest, shake_digest_size); // Digest of first block
    {
      GPVPlaintext<NativePoly> plaintext2;
      TIMER_BEGIN();
      plaintext2 = GPVPlaintext<NativePoly>(block2);
      string s2(reinterpret_cast<char*>(shake_digest), shake_digest_size);
      std::stringstream ss2(s2);
      Serial::Deserialize(digest1, ss, SerType::BINARY);
      context.Preimage(plaintext2, digest1, sk, vk, &r2);
      TIMER_END();
      // Checking the result:
      context.Hash(plaintext2, r2, vk, &digest2);
      if(digest1 != digest2)
	fprintf(stderr, "ERROR: Incorrect value!!!!!!!!!!!\n");
    }
  }
  TIMER_RESULT("Redacting  1MB Block:");
  free(shake_digest);
  return 0;
}
