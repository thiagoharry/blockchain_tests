#ifndef __PREIMAGE_CHAMELEON_HASH_H_
#define __PREIMAGE_CHAMELEON_HASH_H_

#include <stdbool.h>

struct message;
struct randomness;
struct digest;
struct eval_key;
struct trap_key;
struct ch_sys_params;

/* Initialization functions */
void chameleon_hash_init_sysparams(const unsigned int security_bits,
				   struct ch_sys_params *sys);
void chameleon_hash_init_message(const struct ch_sys_params *sys,
				 struct message *msg);
void chameleon_hash_init_randomness(const struct ch_sys_params *sys,
				    struct randomness *rnd);
void chameleon_hash_init_digest(const struct ch_sys_params *sys,
				struct digest *dgt);

/* Finalization functions */
void chameleon_hash_destroy_sysparams(struct ch_sys_params *);
void chameleon_hash_destroy_keys(struct ch_sys_params *,
				 struct eval_key *, struct trap_key *);
void chameleon_hash_destroy_message(struct message *msg);
void chameleon_hash_destroy_randomness(struct randomness *rnd);
void chameleon_hash_destroy_digest(struct digest *dgt);

/* Print functions */
void chameleon_hash_print_sysparams(const struct ch_sys_params *);
void chameleon_hash_print_keys(const struct eval_key *,
			       const struct trap_key *);
void chameleon_hash_print_message(const struct message *msg);
void chameleon_hash_print_randomness(const struct randomness *rnd);
void chameleon_hash_print_digest(const struct digest *dgt);


/* Base Functions */
void chameleon_hash_keygen(const struct ch_sys_params *sys,
			   struct eval_key *ek,
			   struct trap_key *tk);
void chameleon_hash_hash(const struct ch_sys_params *sys,
			 const struct eval_key *,
			 const struct message *msg,
			 const struct randomness *rnd,
			 struct digest *dgt);
void chameleon_hash_preimage(const struct ch_sys_params *sys,
			      const struct trap_key *,
			      const struct message *msg,
			     const struct digest *dgt,
			      struct randomness *rnd);
/* Sampling Functions */
void chameleon_hash_sample_randomness(const struct ch_sys_params *sys,
				      const struct eval_key *ek,
				      struct randomness *rnd);
void chameleon_hash_sample_message(const struct ch_sys_params *sys,
				   const struct eval_key *ek,
				   struct message *msg);
void chameleon_hash_sample_digest(const struct ch_sys_params *sys,
				  const struct eval_key *ek,
				  struct digest *dgt);


/* Comparison*/
bool compare_digest(struct digest *, struct digest *);

#endif
