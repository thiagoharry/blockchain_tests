#include "secret_coin_chameleon_hash.h"
#include "natural.h"
#include "group.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

// CH.KeyGen::    0.001462s ± 0.000190s
// CH.Hash::      0.008039s ± 0.000662s
// CH.Verify::    0.007146s ± 0.000446s
// CH.Collision:: 0.006611s ± 0.000423s

struct message{
  mpz_t value;
};

struct verification{
  mpz_t e1, e2, s1, s2;
};

struct digest{
  mpz_t c1, c2;
};

struct eval_key{
  mpz_t y;
};

struct trap_key{
  mpz_t x, y;
};

struct ch_sys_params{
  unsigned modulus_bits, message_bits;
  mpz_t g, q, prime;
};


void shake(unsigned char *string, size_t size, unsigned char *digest){
  EVP_MD_CTX *mdctx;
  if((mdctx = EVP_MD_CTX_new()) == NULL)
    exit(1);
  if(1 != EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL))
    exit(1);
  if(1 != EVP_DigestUpdate(mdctx, string, size))
    exit(1);
  if(1 != EVP_DigestFinalXOF(mdctx, digest, 314))
    exit(1);
  EVP_MD_CTX_free(mdctx);
}


/* Initialization functions */
void chameleon_hash_init_sysparams(const unsigned int security_bits,
				   struct ch_sys_params *sys){
  unsigned min, max = 1;
  double resulting_bits;
  mpz_t tmp;
  mpz_init(tmp);
  // Checking the number of bits for our modulus
  do{
    double a, b;
    max *= 2;
    mpz_ui_pow_ui(tmp, 2, max);
    a = log(tmp->_mp_d[abs(tmp->_mp_size) - 1]);
    a += (abs(tmp->_mp_size)-1) * log(ULONG_MAX);;
    b = log(a);
    a = pow(a, 0.333333333333333333);
    b = pow(b, 0.666666666666666666);
    resulting_bits = (2.77430173708 * a * b);
  }while(resulting_bits < security_bits);
  min = max / 2;
  while(max - min > 1){
    double a, b;
    unsigned half = (max + min) / 2;
    mpz_ui_pow_ui(tmp, 2, half);
    a = log(tmp->_mp_d[abs(tmp->_mp_size) - 1]);
    a += (abs(tmp->_mp_size)-1) * log(ULONG_MAX);;
    b = log(a);
    a = pow(a, 0.333333333333333333);
    b = pow(b, 0.666666666666666666);
    resulting_bits = (2.77430173708 * a * b);
    if(resulting_bits < security_bits)
      min = half;
    else
      max = half;
  }
  mpz_clear(tmp);
  sys -> modulus_bits = max;
  sys -> message_bits = 2 * security_bits;
  mpz_init(sys -> prime);
  mpz_init(sys -> g);
  mpz_init(sys -> q);
  sample_safe_prime(sys -> modulus_bits, sys -> prime);
  mpz_set(sys -> q, sys -> prime);
  mpz_sub_ui(sys -> q, sys -> q, 1);
  mpz_divexact_ui(sys -> q, sys -> q, 2);
  random_sample(sys -> prime, sys -> g);
  mpz_powm_ui(sys -> g, sys -> g, 2, sys -> prime); // quadratic resid.
}

void chameleon_hash_init_message(const struct ch_sys_params *sys,
				 struct message *msg){
  mpz_init(msg -> value);
}

void chameleon_hash_init_verification(const struct ch_sys_params *sys,
				      struct verification *str){
  mpz_init(str -> e1);
  mpz_init(str -> e2);
  mpz_init(str -> s1);
  mpz_init(str -> s2);
}

void chameleon_hash_init_digest(const struct ch_sys_params *sys,
				struct digest *dgt){
  mpz_init(dgt -> c1);
  mpz_init(dgt -> c2);
}

/* Finalization functions */
void chameleon_hash_destroy_sysparams(struct ch_sys_params *sys){
  mpz_clear(sys -> prime);
  mpz_clear(sys -> g);
  mpz_clear(sys -> q);
  return;
}

void chameleon_hash_destroy_keys(struct ch_sys_params *sys,
				 struct eval_key *ek,
				 struct trap_key *tk){
  mpz_clear(ek -> y);
  mpz_clear(tk -> x);
  mpz_clear(tk -> y);
}

void chameleon_hash_destroy_message(struct message *msg){
  mpz_clear(msg -> value);
}

void chameleon_hash_destroy_verification(struct verification *str){
  mpz_clear(str -> e1);
  mpz_clear(str -> e2);
  mpz_clear(str -> s1);
  mpz_clear(str -> s2);
}

void chameleon_hash_destroy_digest(struct digest *dgt){
  mpz_clear(dgt -> c1);
  mpz_clear(dgt -> c2);
}

/* Print functions */
void chameleon_hash_print_sysparams(const struct ch_sys_params *sys){
  printf("{\"system_parameters\": {\"modulus_bits\": %d, \"message_bits\": %d}}\n", sys -> modulus_bits, sys -> message_bits);
}

void chameleon_hash_print_keys(const struct eval_key *ek,
			       const struct trap_key *tk){
  gmp_printf("{\"keys\": {\"x\": %Zd, \"y\": %Zd}}\n",
	     tk -> x, ek -> y);
}

void chameleon_hash_print_message(const struct message *msg){
  gmp_printf("{\"msg\": %Zd\"}\n", msg -> value);
}

void chameleon_hash_print_verification(const struct verification *str){
  gmp_printf("{\"rnd\": %Zd %Zd %Zd %Zd}\n", str -> e1, str -> e2,
	     str -> s1, str -> s2);
}


void chameleon_hash_print_digest(const struct digest *dgt){
  gmp_printf("{\"dgt\": %Zd %Zd}\n", dgt -> c1, dgt -> c2);
}


/* Base Functions */
void chameleon_hash_keygen(const struct ch_sys_params *sys,
			   struct eval_key *ek,
			   struct trap_key *tk){
  random_sample(sys -> q, tk -> x);
  mpz_powm(ek -> y, sys -> g, tk -> x, sys -> prime);
  mpz_set(tk -> y, ek -> y);
}

void chameleon_hash_hash(const struct ch_sys_params *sys,
			 const struct eval_key *ek,
			 const struct message *msg,
			 struct digest *dgt,
			 struct verification *str){
  mpz_t E, k1, u11, u12, u2, tmp, e;
  unsigned char buffer[2500];
  unsigned char shake_digest[314];
  size_t count = 0, count2;
  mpz_init(E);
  mpz_init(k1);
  mpz_init(u11);
  mpz_init(u12);
  mpz_init(u2);
  mpz_init(tmp);
  mpz_init(e);
  random_sample(sys -> q, E); // E
  random_sample(sys -> q, k1); // k1
  random_sample(sys -> q, str -> e2); // e2
  random_sample(sys -> q, str -> s2); // s2
  mpz_powm(u11, sys -> g, k1, sys -> prime); // u11
  mpz_powm(u12, ek -> y, k1, sys -> prime); // u12
  mpz_powm(u2, sys -> g, str -> s2, sys -> prime);
  mpz_sub(tmp, sys -> q, str -> e2);
  mpz_powm(tmp, ek -> y, tmp, sys -> prime);
  mpz_mul(u2, u2, tmp);
  mpz_mod(u2, u2, sys -> prime);  // u2
  mpz_powm(dgt -> c1, sys -> g, E, sys -> prime); // c1
  mpz_powm(dgt -> c2, ek -> y, E, sys -> prime);
  mpz_mul(dgt -> c2, dgt -> c2, msg -> value); // c2
  mpz_export(buffer, &count, 1, 1, 0, 0, ek -> y);
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, dgt -> c1);
  count += count2;
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, dgt -> c2);
  count += count2;
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, msg -> value);
  count += count2;
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, u11);
  count += count2;
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, u12);
  count += count2;
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, u2);
  count += count2;
  shake(buffer, count, shake_digest);
  mpz_import(e, 314, 1, 1, 0, 0, shake_digest);
  mpz_mod(e, e, sys -> q);
  mpz_sub(str -> e1, e, str -> e2);
  mpz_mod(str -> e1, str -> e1, sys -> q);
  mpz_mul(str -> s1, str -> e1, E);
  mpz_add(str -> s1, str -> s1, k1);
  mpz_mod(str -> s1, str -> s1, sys -> q);
  mpz_clear(E);
  mpz_clear(k1);
  mpz_clear(u11);
  mpz_clear(u12);
  mpz_clear(u2);
  mpz_clear(tmp);
  mpz_clear(e);
}

bool chameleon_hash_verify(const struct ch_sys_params *sys,
			   const struct eval_key *ek,
			   const struct message *msg,
			   const struct digest *dgt,
			   const struct verification *str){
  bool ret;
  mpz_t u11, u12, tmp, exp, u2, e;
  unsigned char buffer[2500];
  unsigned char shake_digest[314];
  size_t count = 0, count2;
  mpz_init(u11);
  mpz_init(u12);
  mpz_init(tmp);
  mpz_init(exp);
  mpz_init(u2);
  mpz_init(e);
  mpz_powm(u11, sys -> g, str -> s1, sys -> prime);
  mpz_sub(exp, sys -> q, str -> e1);
  mpz_powm(tmp, dgt -> c1, exp, sys -> prime);
  mpz_mul(u11, u11, tmp);
  mpz_mod(u11, u11, sys -> prime);
  mpz_invert(u12, msg -> value, sys -> prime);
  mpz_mul(u12, u12, dgt -> c2);
  mpz_powm(u12, u12, exp, sys -> prime);
  mpz_powm(tmp, ek -> y, str -> s1, sys -> prime);
  mpz_mul(u12, tmp, u12);
  mpz_mod(u12, u12, sys -> prime);
  mpz_powm(u2, sys -> g, str -> s2, sys -> prime);
  mpz_sub(exp, sys -> q, str -> e2);
  mpz_powm(tmp, ek -> y, exp, sys -> prime);
  mpz_mul(u2, tmp, u2);
  mpz_mod(u2, u2, sys -> prime);
  mpz_export(buffer, &count, 1, 1, 0, 0, ek -> y);
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, dgt -> c1);
  count += count2;
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, dgt -> c2);
  count += count2;
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, msg -> value);
  count += count2;
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, u11);
  count += count2;
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, u12);
  count += count2;
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, u2);
  count += count2;
  shake(buffer, count, shake_digest);
  mpz_import(e, 314, 1, 1, 0, 0, shake_digest);
  mpz_mod(e, e, sys -> q);
  mpz_add(tmp, str -> e1, str -> e2);
  mpz_mod(tmp, tmp, sys -> q);
  ret = (mpz_cmp(tmp, e) == 0);
  mpz_clear(u11);
  mpz_clear(u12);
  mpz_clear(tmp);
  mpz_clear(exp);
  mpz_clear(u2);
  mpz_clear(e);
  return ret;
}


void chameleon_hash_collision(const struct ch_sys_params *sys,
			      const struct trap_key *tk,
			      const struct message *msg1,
			      const struct digest *dgt,
			      const struct verification *str1,
			      const struct message *msg2,
			      struct verification *str2){
  mpz_t k2, u11, u12, tmp, exp, u2, e;
  unsigned char buffer[2500];
  unsigned char shake_digest[314];
  size_t count = 0, count2;
  mpz_init(k2);
  mpz_init(u11);
  mpz_init(u12);
  mpz_init(tmp);
  mpz_init(exp);
  mpz_init(u2);
  mpz_init(e);
  random_sample(sys -> q, k2); // k2
  random_sample(sys -> q, str2 -> e1); //e1
  random_sample(sys -> q, str2 -> s1); // s1
  mpz_sub(exp, sys -> q, str2 -> e1);
  mpz_powm(tmp, dgt -> c1, exp, sys -> prime);  
  mpz_powm(u11, sys -> g, str2 -> s1, sys -> prime);  
  mpz_mul(u11, u11, tmp);
  mpz_mod(u11, u11, sys -> prime); // u11
  mpz_invert(u12, msg2 -> value, sys -> prime);
  mpz_mul(u12, u12, dgt -> c2);
  mpz_powm(u12, u12, exp, sys -> prime);
  mpz_powm(tmp, tk -> y, str2 -> s1, sys -> prime);
  mpz_mul(u12, u12, tmp);
  mpz_mod(u12, u12, sys -> prime); // u12
  mpz_powm(u2, sys -> g, k2, sys -> prime); // u2
  mpz_export(buffer, &count, 1, 1, 0, 0, tk -> y);
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, dgt -> c1);
  count += count2;
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, dgt -> c2);
  count += count2;
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, msg2 -> value);
  count += count2;
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, u11);
  count += count2;
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, u12);
  count += count2;
  mpz_export(&buffer[count], &count2, 1, 1, 0, 0, u2);
  count += count2;
  shake(buffer, count, shake_digest);
  mpz_import(e, 314, 1, 1, 0, 0, shake_digest);
  mpz_mod(e, e, sys -> q); // e
  mpz_sub(str2 -> e2, e, str2 -> e1);
  mpz_mod(str2 -> e2, str2 -> e2, sys -> q); // e2
  mpz_mul(str2 -> s2, str2 -> e2, tk -> x);
  mpz_add(str2 -> s2, str2 -> s2, k2);
  mpz_mod(str2 -> s2, str2 -> s2, sys -> q); // s2
  mpz_clear(k2);
  mpz_clear(u11);
  mpz_clear(u12);
  mpz_clear(tmp);
  mpz_clear(exp);
  mpz_clear(u2);
  mpz_clear(e);
}



void chameleon_hash_sample_message(const struct ch_sys_params *sys,
				   const struct eval_key *ek,
				   struct message *msg){
  random_sample(sys -> prime, msg -> value);
  mpz_powm_ui(msg -> value, msg -> value, 2, sys -> prime);
}

