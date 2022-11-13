#include "chameleon_hash.h"
#include "natural.h"
#include "group.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>

/*
CH.KeyGen:: 0.147141s ± 0.119992s
CH.Hash:: 0.000281s ± 0.000007s
CH.Preimage:: 0.164906s ± 0.111932s
*/

struct message{
  int size;
  char *msg;
};

struct randomness{
  mpz_t value;
};

struct digest{
  mpz_t value;
};

struct eval_key{
  mpz_t n;
};

struct trap_key{
  mpz_t p, q, n, sqrt4_1;
};

struct ch_sys_params{
  unsigned modulus_bits, message_bits;
};


static void func0(const struct eval_key *ek,
		  const mpz_t input, mpz_t output){
  mpz_mul(output, input, input);
  mpz_mod(output, output, ek -> n);
}

static void func1(const struct eval_key *ek, const mpz_t input,
		  mpz_t output){
  mpz_mul(output, input, input);
  mpz_mul_ui(output, output, 4);
  mpz_mod(output, output, ek -> n);
}

static void inverse_func0(const struct trap_key *tk, const mpz_t input,
			  mpz_t output){
  //gmp_printf("sqrt(%Zd) = ", input);
  modular_square_root(input, tk -> n, tk -> p, tk -> q, output);
  //gmp_printf("%Zd\n ", output);
}

static void inverse_func1(const struct trap_key *tk, const mpz_t input,
			  mpz_t output){
  inverse_func0(tk, input, output);
  mpz_mul(output, output, tk -> sqrt4_1);
  mpz_mod(output, output, tk -> n);
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
  // Done. We will try use at least 'max' bits
  sys -> modulus_bits = max;
  sys -> message_bits = 2 * security_bits;
}

void chameleon_hash_init_message(const struct ch_sys_params *sys,
				 struct message *msg){
  msg -> size = sys -> message_bits;
  if(sys -> message_bits % 8 == 0)
    msg -> msg = (char *) malloc(sys -> message_bits / 8);
  else
    msg -> msg = (char *) malloc(sys -> message_bits / 8 + 1);
}

void chameleon_hash_init_randomness(const struct ch_sys_params *sys,
				    struct randomness *rnd){
  mpz_init(rnd -> value);
}

void chameleon_hash_init_digest(const struct ch_sys_params *sys,
				struct digest *dgt){
  mpz_init(dgt -> value);
}

/* Finalization functions */
void chameleon_hash_destroy_sysparams(struct ch_sys_params *sys){
  return;
}

void chameleon_hash_destroy_keys(struct eval_key *ek,
				 struct trap_key *tk){
  mpz_clear(ek -> n);
  mpz_clear(tk -> n);
  mpz_clear(tk -> p);
  mpz_clear(tk -> q);
  mpz_clear(tk -> sqrt4_1);
}

void chameleon_hash_destroy_message(struct message *msg){
  free(msg -> msg);
}

void chameleon_hash_destroy_randomness(struct randomness *rnd){
  mpz_clear(rnd -> value);
}

void chameleon_hash_destroy_digest(struct digest *dgt){
  mpz_clear(dgt -> value);
}

/* Print functions */
void chameleon_hash_print_sysparams(const struct ch_sys_params *sys){
  printf("{\"system_parameters\": {\"modulus_bits\": %d, \"message_bits\": %d}}\n", sys -> modulus_bits, sys -> message_bits);
}

void chameleon_hash_print_keys(const struct eval_key *ek,
			       const struct trap_key *tk){
  gmp_printf("{\"keys\": {\"n\": %Zd, \"p\": %Zd, \"q\": %Zd}}\n",
	     ek -> n, tk -> p, tk -> q);
}

void chameleon_hash_print_message(const struct message *msg){
  int i;
  unsigned char current_byte = 0;
  printf("{\"msg\": \"");
  for(i = 0; i < msg -> size; i ++){
    if(i % 8 == 0)
      current_byte = msg -> msg[i / 8];
    if(current_byte / 128)
      printf("1");
    else
      printf("0");
    current_byte = current_byte << 1;
  }
  printf("\"}\n");
}

void chameleon_hash_print_randomness(const struct randomness *rnd){
  gmp_printf("{\"rnd\": %Zd}\n", rnd -> value);
}


void chameleon_hash_print_digest(const struct digest *dgt){
  gmp_printf("{\"dgt\": %Zd}\n", dgt -> value);
}


/* Base Functions */
void chameleon_hash_keygen(const struct ch_sys_params *sys,
			   struct eval_key *ek,
			   struct trap_key *tk){
  int p_mod8, q_mod8;
  mpz_init(ek -> n);
  mpz_init(tk -> n);
  mpz_init(tk -> p);
  mpz_init(tk -> q);
  mpz_init(tk -> sqrt4_1);
  do{
    sample_semiprime(sys -> modulus_bits, tk -> p, tk -> q, tk -> n);
    p_mod8 = mpz_fdiv_ui(tk -> p, 8);
    q_mod8 = mpz_fdiv_ui(tk -> q, 8);
    //printf("(%d, %d)\n", p_mod8, q_mod8);
  } while(p_mod8 != 3 && q_mod8 != 7);
  mpz_set(ek -> n, tk -> n);
  { // Store the inverse of the modular squar root of 4:
    mpz_t four;
    mpz_init_set_ui(four, 4);
    modular_square_root(four, tk -> n, tk -> p, tk -> q, tk -> sqrt4_1);
    mpz_invert(tk -> sqrt4_1, tk -> sqrt4_1, tk -> n);
    mpz_clear(four);
  }
}

void chameleon_hash_hash(const struct ch_sys_params *sys,
			 const struct eval_key *ek,
			 const struct message *msg,
			 const struct randomness *rnd,
			 struct digest *dgt){
  int i;
  unsigned char current_bit = 0;
  mpz_set(dgt -> value, rnd -> value);
  for(i = 0; i < sys -> message_bits; i ++){
    if(i % 8 == 0){
      current_bit = msg -> msg[i / 8];
    }
    if(current_bit / 128){
      func1(ek, dgt -> value, dgt -> value);
    }
    else{
      func0(ek, dgt -> value, dgt -> value);
    }
    current_bit = current_bit << 1;
  }
}

void chameleon_hash_preimage(const struct ch_sys_params *sys,
			      const struct trap_key *tk,
			      const struct message *msg,
			     const struct digest *dgt,
			     struct randomness *rnd){
  int i;
  unsigned char current_bit = msg -> msg[(msg -> size - 1)/ 8];
  if(msg -> size % 8 != 0)
    current_bit = current_bit >> (8 - msg -> size % 8);
  mpz_set(rnd -> value, dgt -> value);
  for(i = sys -> message_bits - 1; i >= 0; i --){
    if(i % 8 == 7){
      current_bit = msg -> msg[i / 8];
    }
    if(current_bit % 2 == 1){
      inverse_func1(tk, rnd -> value, rnd -> value);
    }
    else{
      inverse_func0(tk, rnd -> value, rnd -> value);
    }
    current_bit = current_bit >> 1;
  }
}

/* Sampling Functions */
void chameleon_hash_sample_randomness(const struct ch_sys_params *sys,
				      const struct eval_key *ek,
				      struct randomness *rnd){
  mpz_t gcd;
  mpz_init(gcd);
  do{
    random_sample(ek -> n, rnd -> value);
    mpz_mul(rnd -> value, rnd -> value, rnd -> value);
    mpz_mod(rnd -> value, rnd -> value, ek -> n);
    mpz_gcd (gcd, rnd -> value, ek -> n);
  } while(mpz_cmp_ui(rnd -> value, 0) == 0 ||
	  mpz_cmp_ui(gcd, 1) != 0);
  mpz_clear(gcd);
}

void chameleon_hash_sample_message(const struct ch_sys_params *sys,
				   const struct eval_key *ek,
				   struct message *msg){
  unsigned bytes;
  int ret;
  if(sys -> message_bits % 8 == 0)
    bytes = sys -> message_bits / 8;
  else
    bytes = sys -> message_bits / 8 + 1;
  do{
    ret = getrandom(msg -> msg, bytes, 0);
  }while(ret != bytes);
}

void chameleon_hash_sample_digest(const struct ch_sys_params *sys,
				  const struct eval_key *ek,
				  struct digest *dgt){
  do{
    random_sample(ek -> n, dgt -> value);
  } while(mpz_cmp_ui(dgt -> value, 0) == 0);
}
