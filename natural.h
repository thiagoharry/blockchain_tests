#ifndef __NATURAL_H_
#define __NATURAL_H_

#include <gmp.h>

void random_sample(const mpz_t modulus, mpz_t result);
void sample_semiprime(const int bits, mpz_t p, mpz_t q, mpz_t n);
void sample_safe_prime(const int bits, mpz_t p);
void modular_square_root(const mpz_t arg, const mpz_t n, const mpz_t p,
			 const mpz_t q, mpz_t result);
int is_quadratic_residue(const mpz_t x, const mpz_t prime_modulus);
#endif
