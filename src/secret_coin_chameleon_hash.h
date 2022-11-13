#ifndef __SECRET_COIN_CHAMELEON_HASH_H_
#define __SECRET_COIN_CHAMELEON_HASH_H_

#include <stdbool.h>

struct message;
struct verification;
struct digest;
struct eval_key;
struct trap_key;
struct ch_sys_params;

/* Initialization functions */
void chameleon_hash_init_sysparams(const unsigned int security_bits,
				   struct ch_sys_params *sys);
void chameleon_hash_init_message(const struct ch_sys_params *sys,
				 struct message *msg);
void chameleon_hash_init_verification(const struct ch_sys_params *sys,
				    struct verification *str);
void chameleon_hash_init_digest(const struct ch_sys_params *sys,
				struct digest *dgt);

/* Finalization functions */
void chameleon_hash_destroy_sysparams(struct ch_sys_params *);
void chameleon_hash_destroy_keys(struct ch_sys_params *,
				 struct eval_key *, struct trap_key *);
void chameleon_hash_destroy_message(struct message *msg);
void chameleon_hash_destroy_verification(struct verification *str);
void chameleon_hash_destroy_digest(struct digest *dgt);

/* Print functions */
void chameleon_hash_print_sysparams(const struct ch_sys_params *);
void chameleon_hash_print_keys(const struct eval_key *,
			       const struct trap_key *);
void chameleon_hash_print_message(const struct message *msg);
void chameleon_hash_print_verification(const struct verification *str);
void chameleon_hash_print_digest(const struct digest *dgt);


/* Base Functions */
void chameleon_hash_keygen(const struct ch_sys_params *sys,
			   struct eval_key *ek,
			   struct trap_key *tk);
void chameleon_hash_hash(const struct ch_sys_params *sys,
			 const struct eval_key *ek,
			 const struct message *msg,
			 struct digest *dgt,
			 struct verification *str);
bool chameleon_hash_verify(const struct ch_sys_params *sys,
			   const struct eval_key *ek,
			   const struct message *msg,
			   const struct digest *dgt,
			   const struct verification *str);
void chameleon_hash_collision(const struct ch_sys_params *sys,
			      const struct trap_key *tk,
			      const struct message *msg1,
			      const struct digest *dgt,
			      const struct verification *str1,
			      const struct message *msg2,
			      struct verification *str2);

/* Sampling Functions */
void chameleon_hash_sample_message(const struct ch_sys_params *sys,
				   const struct eval_key *ek,
				   struct message *msg);


#endif
