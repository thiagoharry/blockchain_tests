#include "natural.h"

#include <math.h>
#include <stdlib.h>
#include <sys/random.h>

void random_sample(const mpz_t modulus, mpz_t result){
  unsigned long bits = 0;
  unsigned long bytes;
  mpz_t tmp;
  unsigned char *buffer;
  ssize_t ret;
  mpz_init(tmp);
  mpz_set(tmp, modulus);
  mpz_sub_ui(tmp, tmp, 1);
  while(mpz_cmp_ui(tmp, 0) != 0){
    mpz_tdiv_q_ui(tmp, tmp, 2);
    bits ++;
  }
  bytes = (bits / 8) + 1;
  buffer = (unsigned char *) malloc(bytes);
  // Getting a random integer:
  do{
    int i;
    do{
      ret = getrandom(buffer, bytes, 0);
    }while(ret != bytes);
    buffer[0] = buffer[0] >> (bytes * 8 - bits);
    mpz_set_ui(tmp, 0);
    for(i = bytes - 1; i >= 0; i --){
      mpz_mul_ui(tmp, tmp, 256);
      mpz_add_ui(tmp, tmp, buffer[i]);
    }
  }while(mpz_cmp(tmp, modulus) >= 0);
  free(buffer);
  mpz_set(result, tmp);
  mpz_clear(tmp);
}

void sample_safe_prime(const int bits, mpz_t p){
 int minor_bits;
  int bytes;
  mpz_t half;
  unsigned char *buffer;
  mpz_init(half);
  minor_bits = bits / 2;
  if(minor_bits % 8 == 0)
    bytes = minor_bits / 8;
  else
    bytes = minor_bits / 8 + 1;
  buffer = (unsigned char *) malloc(bits / 8 + 1);
  do{
    int i, ret;
    do{
      ret = getrandom(buffer, bytes, 0);
    }while(ret != bytes);
    buffer[0] |= 0x80;
    buffer[0] = buffer[0] >> (bytes * 8 - (minor_bits));
    buffer[bytes - 1] |= 0x01;
    mpz_set_ui(p, 0);
    for(i = 0; i < bytes; i ++){
      mpz_mul_ui(p, p, 256);
      mpz_add_ui(p, p, buffer[i]);
    }
    mpz_set(half, p);
    mpz_sub_ui(half, half, 1);
    mpz_divexact_ui(half, half, 2);
  }while(mpz_probab_prime_p(p, 50) == 0 ||
	 mpz_probab_prime_p(half, 50) == 0);
  mpz_clear(half);
  free(buffer);

}

void sample_semiprime(const int bits, mpz_t p, mpz_t q, mpz_t n){
  int minor_bits;
  int bytes;
  mpz_t min;
  unsigned char *buffer;
  mpz_init(min);
  mpz_ui_pow_ui(min, 2, bits - 1);
  buffer = (unsigned char *) malloc(bits / 8 + 1);
  do{
    minor_bits = bits / 2;
    if(minor_bits % 8 == 0)
      bytes = minor_bits / 8;
    else
      bytes = minor_bits / 8 + 1;
    do{
      int i, ret;
      do{
	ret = getrandom(buffer, bytes, 0);
      }while(ret != bytes);
      buffer[0] |= 0x80;
      buffer[0] = buffer[0] >> (bytes * 8 - (minor_bits));
      buffer[bytes - 1] |= 0x01;
      mpz_set_ui(p, 0);
      for(i = 0; i < bytes; i ++){
	mpz_mul_ui(p, p, 256);
	mpz_add_ui(p, p, buffer[i]);
      }
    }while(mpz_probab_prime_p(p, 50) == 0);
    if(bits % 2 == 1){
      minor_bits ++;
      if(minor_bits % 8 == 0)
	bytes = minor_bits / 8;
      else
	bytes = minor_bits / 8 + 1;
    }
    do{
      int i, ret;
      do{
	ret = getrandom(buffer, bytes, 0);
      }while(ret != bytes);
      buffer[0] |= 0x80;
      buffer[0] = buffer[0] >> (bytes * 8 - (minor_bits));
      buffer[bytes - 1] |= 0x01;
      mpz_set_ui(q, 0);
      for(i = 0; i < bytes; i ++){
	mpz_mul_ui(q, q, 256);
	mpz_add_ui(q, q, buffer[i]);
      }
    }while(mpz_probab_prime_p(q, 50) == 0);
    mpz_mul(n, p, q);
  } while(mpz_cmp(min, n) > 0);
  mpz_clear(min);
  free(buffer);
}

#define mpz_rshift(A,B,l) mpz_tdiv_q_2exp(A, B, l)

static int root_mod(mpz_t result, const mpz_t arg, const mpz_t prime){
  mpz_t y, b, t;
  unsigned int r, m;
  if (mpz_divisible_p(arg, prime)) {
    mpz_set_ui(result, 0);
    return 1;
  }
  if (mpz_legendre(arg, prime) == -1)
    return -1;
  mpz_init(b);
  mpz_init(t);     
  mpz_init_set_ui(y, 2);
  while(mpz_legendre(y, prime) != -1)
    mpz_add_ui(y, y, 1);
  mpz_sub_ui(result, prime, 1);
  r = mpz_scan1(result, 0);
  mpz_rshift(result, result, r); 
  mpz_powm(y, y, result, prime);   
  mpz_rshift(result, result, 1);
  mpz_powm(b, arg, result, prime); 
  mpz_mul(result, arg, b);
  mpz_mod(result, result, prime);  
  mpz_mul(b, result, b);
  mpz_mod(b, b, prime);  
  while(mpz_cmp_ui(b, 1)){   
    mpz_mul(t, b, b);
    mpz_mod(t, t, prime);
    for(m = 1; mpz_cmp_ui(t, 1); m++){
      mpz_mul(t, t, t);
      mpz_mod(t, t, prime);
    }
    mpz_set_ui(t, 0);
    mpz_setbit(t, r - m - 1);
    mpz_powm(t, y, t, prime); 
    mpz_mul(y, t, t);
    r = m;
    mpz_mul(result, result, t);
    mpz_mod(result, result, prime);
    mpz_mul(b, b, y);
    mpz_mod(b, b, prime);
  }
  mpz_clear(y);
  mpz_clear(b);
  mpz_clear(t);
  return 1;
}

// Compute square root of arg modulo n, when n=pq
void modular_square_root(const mpz_t arg, const mpz_t n, const mpz_t p,
			 const mpz_t q, mpz_t result){
  mpz_t exp, tmp;
  mpz_t root0, root1;
  mpz_init(exp);
  mpz_init(tmp);
  mpz_init(root0);
  mpz_init(root1);
  root_mod(root0, arg, p);
  // If root0 is a quadratic residue, ok. Otherwise, choose -root0:
  {
    mpz_set(exp, p);
    mpz_sub_ui(exp, exp, 1);
    mpz_divexact_ui(exp, exp, 2);
    mpz_powm(tmp, root0, exp, p);
    if(mpz_cmp_ui(tmp, 1) != 0){
      mpz_sub(root0, p, root0);
    }
  }
  root_mod(root1, arg, q);
  // If root1 is a quadratic residue, ok. Otherwise, choose -root1:
  {
    mpz_set(exp, q);
    mpz_sub_ui(exp, exp, 1);
    mpz_divexact_ui(exp, exp, 2);
    mpz_powm(tmp, root1, exp, q);
    if(mpz_cmp_ui(tmp, 1) != 0){
      mpz_sub(root1, q, root1);
      // set root1 = -root1
    }
    mpz_clear(exp);
    mpz_clear(tmp);
  }
  // Combining the results with the chinese remainder theorem
  {
    mpz_t prod, sum, r, inv;
    mpz_init(sum);
    mpz_init(r);
    mpz_init(inv);
    mpz_init_set(prod, n);
    
    mpz_divexact(r, prod, p);
    mpz_invert(inv, r, p);
    mpz_mul(r, r, inv);
    mpz_mul(r, r, root0);
    mpz_add(sum, sum, r);

    mpz_divexact(r, prod, q);
    mpz_invert(inv, r, q);
    mpz_mul(r, r, inv);
    mpz_mul(r, r, root1);
    mpz_add(sum, sum, r);

    mpz_mod(result, sum, prod);
    mpz_clear(r);
    mpz_clear(sum);
    mpz_clear(prod);
    mpz_clear(inv);
    mpz_clear(root0);
    mpz_clear(root1);
  }
}

int is_quadratic_residue(const mpz_t x, const mpz_t n){
  // Is a quadratic residue if x^{(n-1)/2} mod n = 1 if n is prime:
  mpz_t exp;
  int result;
  mpz_init(exp);
  mpz_set(exp, n);
  mpz_sub_ui(exp, exp, 1);
  mpz_divexact_ui(exp, exp, 2);
  mpz_powm(exp, x, exp, n);
  result = mpz_cmp_ui(exp, 1);
  mpz_clear(exp);
  return (result == 0);
}
