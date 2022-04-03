#include "secret_coin_chameleon_hash.h"
#include <stdio.h>

#define NTESTS 1000 // Number of times we measure each function
#include "timer.h"

int main(int argc, char **argv){
  int i;
  struct eval_key ek;
  struct trap_key tk;
  struct message msg1, msg2;
  struct verification str1, str2;
  struct digest dgt;
  struct ch_sys_params sys;

  chameleon_hash_init_sysparams(128, &sys);
  chameleon_hash_print_sysparams(&sys);
  chameleon_hash_init_message(&sys, &msg1);
  chameleon_hash_init_message(&sys, &msg2);
  chameleon_hash_init_verification(&sys, &str1);
  chameleon_hash_init_verification(&sys, &str2);
  chameleon_hash_init_digest(&sys, &dgt);
  /* TIMER */
  for(i = 0; i < NTESTS; i ++){
    TIMER_BEGIN();
    chameleon_hash_keygen(&sys, &ek, &tk);
    TIMER_END();
  }
  TIMER_RESULT("CH.KeyGen:");

  chameleon_hash_keygen(&sys, &ek, &tk);
  chameleon_hash_print_keys(&ek, &tk);  
  /* TIMER */
  for(i = 0; i < NTESTS; i ++){
    bool ret;
    chameleon_hash_sample_message(&sys, &ek, &msg1);
    TIMER_BEGIN();
    chameleon_hash_hash(&sys, &ek, &msg1, &dgt, &str1);
    TIMER_END();
    ret = chameleon_hash_verify(&sys, &ek, &msg1, &dgt, &str1);
    if(!ret){
      printf("ERROR: HASH NOT VERIFIED!!!!!!!!!!\n");
    }
  }
  TIMER_RESULT("CH.Hash:");

  /* TIMER */
  for(i = 0; i < NTESTS; i ++){
    bool ret;
    chameleon_hash_sample_message(&sys, &ek, &msg1);
    chameleon_hash_hash(&sys, &ek, &msg1, &dgt, &str1);
    TIMER_BEGIN();
    ret = chameleon_hash_verify(&sys, &ek, &msg1, &dgt, &str1);
    TIMER_END();
    if(!ret){
      printf("ERROR: HASH NOT VERIFIED!!!!!!!!!!\n");
    }
  }
  TIMER_RESULT("CH.Verify:");

  
  for(i = 0; i < NTESTS; i ++){
    bool ret;
    chameleon_hash_sample_message(&sys, &ek, &msg1);
    chameleon_hash_sample_message(&sys, &ek, &msg2);
    chameleon_hash_hash(&sys, &ek, &msg1, &dgt, &str1);
    TIMER_BEGIN();
    chameleon_hash_collision(&sys, &tk, &msg1, &dgt, &str1, &msg2, &str2);
    TIMER_END();
    ret = chameleon_hash_verify(&sys, &ek, &msg2, &dgt, &str2);
    if(!ret){
      printf("ERROR: HASH NOT VERIFIED!!!!!!!!!!\n");
    }
  }
  TIMER_RESULT("CH.Collision:");

  /*chameleon_hash_sample_randomness(&sys, &ek, &rnd1);
  chameleon_hash_sample_message(&sys, &ek, &msg1);
  printf("Computing hash: ");
  chameleon_hash_print_message(&msg1);
  printf(",");
  chameleon_hash_print_randomness(&rnd1);
  printf("\n");
  chameleon_hash_hash(&sys, &ek, &msg1, &rnd1, &dgt);
  printf("Digest: ");
  chameleon_hash_print_digest(&dgt);
  printf("\n");
  
  chameleon_hash_sample_message(&sys, &ek, &msg2);
  chameleon_hash_preimage(&sys, &tk, &msg2, &dgt, &rnd2);
  printf("Computing hash: ");
  chameleon_hash_print_message(&msg2);
  printf(",");
  chameleon_hash_print_randomness(&rnd2);
  printf("\n");
  chameleon_hash_hash(&sys, &ek, &msg2, &rnd2, &dgt);
  printf("Digest: ");
  chameleon_hash_print_digest(&dgt);
  printf("\n");*/
  
  chameleon_hash_destroy_message(&msg1);
  chameleon_hash_destroy_message(&msg2);
  chameleon_hash_destroy_verification(&str1);
  chameleon_hash_destroy_verification(&str2);
  chameleon_hash_destroy_digest(&dgt);
  chameleon_hash_destroy_keys(&sys, &ek, &tk);
  chameleon_hash_destroy_sysparams(&sys);
}

