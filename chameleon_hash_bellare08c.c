#include "chameleon_hash.h"
#include "natural.h"
#include "group.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>

/*
CH.Hash:: 0.000523s ± 0.000097s
CH.Preimage:: 0.003953s ± 0.002642s
*/

/* Small primes:
CH.KeyGen:: 4.561135s ± 0.853407s
CH.Hash:: 0.000033s ± 0.000002s
CH.Preimage:: 0.003999s ± 0.002678s
*/

struct message{
  int size;
  unsigned char *msg;
};

struct randomness{
  mpz_t value;
};

struct digest{
  mpz_t value;
};

struct eval_key{
  mpz_t n;
  mpz_t *E;
};

struct trap_key{
  mpz_t p, q, n;
  mpz_t *sqrt_E;
};

struct ch_sys_params{
  unsigned modulus_bits, message_bits;
};

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
  }while(resulting_bits < security_bits + 9);
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
    if(resulting_bits < security_bits + 9)
      min = half;
    else
      max = half;
  }
  mpz_clear(tmp);
  // At first, we should set 'max' bits
  // But this construction do not have a very tight security
  // reduction: it is at least 512 times faster to find a collision
  // than factorate 'n'. Therefore, we add 9 bits (2^9=512) to
  // compensate:
  sys -> modulus_bits = max;
  sys -> message_bits = 2 * security_bits;
}

void chameleon_hash_init_message(const struct ch_sys_params *sys,
				 struct message *msg){
  msg -> size = sys -> message_bits;
  if(sys -> message_bits % 8 == 0)
    msg -> msg = (unsigned char *) malloc(sys -> message_bits / 8);
  else
    msg -> msg = (unsigned char *) malloc(sys -> message_bits / 8 + 1);
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

void chameleon_hash_destroy_keys(struct ch_sys_params *sys,
				 struct eval_key *ek,
				 struct trap_key *tk){
  int i;
  mpz_clear(ek -> n);
  mpz_clear(tk -> n);
  mpz_clear(tk -> p);
  mpz_clear(tk -> q);
  for(i = 0; i < sys -> message_bits; i ++){
    mpz_clear(ek -> E[i]);
    mpz_clear(tk -> sqrt_E[i]);
  }
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
  int p_mod8, q_mod8, new_value;
  int i;
  mpz_init(ek -> n);
  mpz_init(tk -> n);
  mpz_init(tk -> p);
  mpz_init(tk -> q);
  do{
    sample_semiprime(sys -> modulus_bits, tk -> p, tk -> q, tk -> n);
    p_mod8 = mpz_fdiv_ui(tk -> p, 8);
    q_mod8 = mpz_fdiv_ui(tk -> q, 8);
    //printf("(%d, %d)\n", p_mod8, q_mod8);
  } while(p_mod8 != 3 && q_mod8 != 7);
  mpz_set(ek -> n, tk -> n);
  ek -> E = (mpz_t *) malloc(sizeof(mpz_t) * sys -> message_bits);
  tk -> sqrt_E = (mpz_t *) malloc(sizeof(mpz_t) * sys -> message_bits);
  for(i = 0; i < sys -> message_bits; i ++){
    mpz_init(ek -> E[i]);
    mpz_init(tk -> sqrt_E[i]);
  }
  // Now we sample 'sys -> message_bits' distinct random primes which
  // are quadractic residue modulus 'n':
  for(i = 0; i < sys -> message_bits; i ++){
    do{
      int j;
      new_value = 1;
      random_sample(ek -> n, ek -> E[i]);
      for(j = 0; j < i; j ++){
	if(mpz_cmp(ek -> E[i], ek -> E[j]) == 0)
	  new_value = 0;
      }
    } while(mpz_probab_prime_p(ek -> E[i], 50) == 0 ||
	    !is_quadratic_residue(ek -> E[i], tk -> p) ||
	    !is_quadratic_residue(ek -> E[i], tk -> q) ||
	    !new_value);
    mpz_invert(tk -> sqrt_E[i], ek -> E[i], tk -> n);
    modular_square_root(tk -> sqrt_E[i], tk -> n, tk -> p, tk -> q,
			tk -> sqrt_E[i]);
  }
}

void chameleon_hash_hash(const struct ch_sys_params *sys,
			 const struct eval_key *ek,
			 const struct message *msg,
			 const struct randomness *rnd,
			 struct digest *dgt){
  int i;
  unsigned char current_bit = 0;
  mpz_mul(dgt -> value, rnd -> value, rnd -> value);
  mpz_mod(dgt -> value, dgt -> value, ek -> n);
  for(i = 0; i < sys -> message_bits; i ++){
    if(i % 8 == 0){
      current_bit = msg -> msg[i / 8];
    }
    if(current_bit / 128){
      mpz_mul(dgt -> value, dgt -> value, ek -> E[i]);
      mpz_mod(dgt -> value, dgt -> value, ek -> n);
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
  unsigned char current_bit = 0;
  modular_square_root(dgt -> value, tk -> n, tk -> p, tk -> q,
		      rnd -> value);
  for(i = 0; i < sys -> message_bits; i ++){
    if(i % 8 == 0){
      current_bit = msg -> msg[i / 8];
    }
    if(current_bit / 128){
      mpz_mul(rnd -> value, rnd -> value, tk -> sqrt_E[i]);
      mpz_mod(rnd -> value, rnd -> value, tk -> n);
    }
    current_bit = current_bit << 1;
  }
}

/* Sampling Functions */
void chameleon_hash_sample_randomness(const struct ch_sys_params *sys,
				      const struct eval_key *ek,
				      struct randomness *rnd){
  random_sample(ek -> n, rnd -> value);
  mpz_mul(rnd -> value, rnd -> value, rnd -> value);
  mpz_mod(rnd -> value, rnd -> value, ek -> n);
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


bool compare_digest(struct digest *dgt1, struct digest *dgt2){

}
