#ifndef __GROUP_H_
#define __GROUP_H_

#include <gmp.h>
#include <stdbool.h>

struct element;
struct group;

void group_init(const unsigned int security_bits, struct group *G);
void group_destroy(struct group *G);
void group_clone(const struct group *G1, struct group *G2);
void group_element_clone(const struct element *e1, struct element *e2);
void group_element_init(struct element *el);
void group_element_print(const struct element *el);
void group_print(const struct group *G);
void group_element_destroy(struct element *el);
bool group_element_equal(const struct element *a,
			 const struct element *b);
void group_identity(struct element *identity);
void group_sample(const struct group *G, struct element *sample);
void group_inverse(const struct group *G, const struct element *element,
		   struct element *inverse);
void group_op(const struct group *G, const struct element *a,
	      const struct element *b,
	      struct element *c);
void group_order(const struct group *G, mpz_t order);
void group_sample_with_order(const struct group *G,
			     const mpz_t order,
			     struct element *sample);
void group_pow(const struct group *G, const struct element *el,
	       const mpz_t exp, struct element *result);

#endif
