#include "preimage_chameleon_hash.h"
#include <sys/random.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

// The security proof for this construction is not tight. We have that
// for all adversaries A that try to find collisions, exist
// adversaries B1 (that solve discrete logarithm problem) and B2 (that
// find a collision in SHA256) such that:

// Adv(A) <= O(q^2) Adv(B1) + Adv(B2).

// The value 'q' is the number of queries for preimages or collisions.
// But here we assume that they are low and we ignore them

/*
128 bits:
CH.KeyGen:: 0.000635s ± 0.000136s
CH.Hash:: 0.000495s ± 0.000025s
CH.Preimage:: 0.000610s ± 0.000084s

166 bits:
CH.KeyGen:: 0.001293s ± 0.000218s
CH.Hash:: 0.000941s ± 0.000116s
CH.Preimage:: 0.001292s ± 0.000058s
*/


struct message{
  int size;
  unsigned char *msg;
};


struct randomness{
  BIGNUM *r, *s;
};


struct digest{
    BIGNUM *value;
};


struct eval_key{
  EC_KEY *key;
};

struct trap_key{
  EC_KEY *key;
};


struct ch_sys_params{
  int security_bits, internal_digest_size, curve_name;
  BN_CTX *ctx;
  EC_GROUP *curve;
  BIGNUM *order;
};


// Initialization functions
void chameleon_hash_init_sysparams(const unsigned int security_bits,
				   struct ch_sys_params *sys){
  //if(security_bits != 128 && security_bits != 192){
  //  fprintf(stderr, "Non-supported security bits.\n");
  //}
  sys -> ctx = BN_CTX_new();
  sys -> order = BN_new();
  if(security_bits == 128){
    sys -> curve_name = NID_secp256k1;
    sys -> internal_digest_size = SHA256_DIGEST_LENGTH;
  }
  else if(security_bits == 166){
    sys -> curve_name = NID_secp384r1;
    sys -> internal_digest_size = 48;
  }
  sys -> curve = EC_GROUP_new_by_curve_name(sys -> curve_name);
  sys -> security_bits = security_bits;
  if(sys -> curve == NULL)
    fprintf(stderr, "ERROR: Failed to generate curve.\n");
  EC_GROUP_get_order(sys -> curve, sys -> order, sys -> ctx);
}



void chameleon_hash_init_message(const struct ch_sys_params *sys,
				 struct message *msg){
  msg -> size = sys -> security_bits / 4;
  msg -> msg = (unsigned char *) malloc(msg -> size);
}


void chameleon_hash_init_randomness(const struct ch_sys_params *sys,
				    struct randomness *rnd){
  rnd -> r = BN_new();
  rnd -> s = BN_new();
}


void chameleon_hash_init_digest(const struct ch_sys_params *sys,
				struct digest *dgt){
  dgt -> value = BN_new();
}


// Finalization functions
void chameleon_hash_destroy_sysparams(struct ch_sys_params *sys){
  BN_CTX_free(sys -> ctx);
  BN_free(sys -> order);
  EC_GROUP_free(sys -> curve);
  return;
}


void chameleon_hash_destroy_keys(struct ch_sys_params *sys,
				 struct eval_key *ek,
				 struct trap_key *tk){
  EC_KEY_free(ek -> key);
  EC_KEY_free(tk -> key);
}

void chameleon_hash_destroy_message(struct message *msg){
  free(msg -> msg);
}


void chameleon_hash_destroy_randomness(struct randomness *rnd){
  BN_free(rnd -> r);
  BN_free(rnd -> s);
}


void chameleon_hash_destroy_digest(struct digest *dgt){
  BN_free(dgt -> value);
}


// Print functions
void chameleon_hash_print_sysparams(const struct ch_sys_params *sys){

}

void chameleon_hash_print_keys(const struct eval_key *ek,
			       const struct trap_key *tk){
}

void chameleon_hash_print_message(const struct message *msg){
}

void chameleon_hash_print_randomness(const struct randomness *rnd){

}


void chameleon_hash_print_digest(const struct digest *dgt){

}


// Base Functions
void chameleon_hash_keygen(const struct ch_sys_params *sys,
			   struct eval_key *ek,
			   struct trap_key *tk){
  const EC_POINT *p;
  tk -> key = EC_KEY_new_by_curve_name(sys -> curve_name);
  ek -> key = EC_KEY_new_by_curve_name(sys -> curve_name);
  EC_KEY_generate_key(tk -> key);
  p = EC_KEY_get0_public_key(tk -> key);
  EC_KEY_set_public_key(ek -> key, p);
}

void hash(unsigned char *string, size_t size, unsigned char *digest){
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, string, size);
  SHA256_Final(digest, &sha256);
}

void shake256(unsigned char *string, size_t size, unsigned char *digest,
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


void chameleon_hash_hash(const struct ch_sys_params *sys,
			 const struct eval_key *ek,
			 const struct message *msg,
			 const struct randomness *rnd,
			 struct digest *dgt){
  unsigned char *buffer;
  BIGNUM *exp;
  EC_POINT *tmp;
  const EC_POINT *y;
  unsigned char *digest;
  size_t ret;
  buffer = (unsigned char *) malloc(msg -> size + BN_num_bytes(rnd -> r));
  digest = (unsigned char *) malloc(sys -> internal_digest_size);
  tmp = EC_POINT_new(sys -> curve);
  memcpy(buffer, msg -> msg, msg -> size);
  BN_bn2bin(rnd -> r, &(buffer[msg -> size]));
  if(sys -> security_bits == 128)
    hash(buffer, msg -> size + BN_num_bytes(rnd -> r), digest);
  else
    shake256(buffer, msg -> size + BN_num_bytes(rnd -> r), digest,
    	     sys -> internal_digest_size);
  exp = BN_bin2bn(digest, sys -> internal_digest_size, NULL);
  y = EC_KEY_get0_public_key(ek -> key);
  EC_POINT_mul(sys -> curve, tmp, rnd -> s, y, exp, sys -> ctx);
  ret = EC_POINT_point2oct(sys -> curve, tmp, POINT_CONVERSION_COMPRESSED,
			   buffer, msg -> size + BN_num_bytes(rnd -> r),
			   sys -> ctx);
  BN_bin2bn(buffer, ret, dgt -> value);
  BN_mod_sub(dgt -> value, rnd -> r, dgt -> value, sys -> order,
	     sys -> ctx);
  BN_free(exp);
  free(buffer);
  free(digest);
  EC_POINT_free(tmp);
}


void chameleon_hash_preimage(const struct ch_sys_params *sys,
			      const struct trap_key *tk,
			      const struct message *msg,
			     const struct digest *dgt,
			     struct randomness *rnd){
  unsigned char buffer[2 * 1024 * 1024];
  BIGNUM *k = BN_new();
  EC_POINT *tmp;
  const BIGNUM *x;
  size_t ret;
  unsigned char *digest;
  digest = (unsigned char *) malloc(sys -> internal_digest_size);
  tmp = EC_POINT_new(sys -> curve);
  BN_rand(k, 256, -1, 0);
  EC_POINT_mul(sys -> curve, tmp, k, NULL, NULL, sys -> ctx);
  ret = EC_POINT_point2oct(sys -> curve, tmp, POINT_CONVERSION_COMPRESSED,
			   buffer, 1024, sys -> ctx);
  BN_bin2bn(buffer, ret, rnd -> r);
  //printf("A\n");
  BN_mod_add(rnd -> r, rnd -> r, dgt -> value, sys -> order,
	     sys -> ctx);
  memcpy(buffer, msg -> msg, msg -> size);
  //printf("B\n");
  BN_bn2bin(rnd -> r, &(buffer[msg -> size]));
  if(sys -> security_bits == 128)
    hash(buffer, msg -> size + BN_num_bytes(rnd -> r), digest);
  else
    shake256(buffer, msg -> size + BN_num_bytes(rnd -> r), digest,
    	     sys -> internal_digest_size);
  BN_bin2bn(digest, sys -> internal_digest_size, rnd -> s);
  x = EC_KEY_get0_private_key(tk -> key);
  BN_mod_mul(rnd -> s, rnd -> s, x, sys -> order, sys -> ctx); //SEG
  BN_mod_sub(rnd -> s, k, rnd -> s, sys -> order, sys -> ctx);
  BN_free(k);
  free(digest);
  EC_POINT_free(tmp);
}


// Sampling Functions
void chameleon_hash_sample_randomness(const struct ch_sys_params *sys,
				      const struct eval_key *ek,
				      struct randomness *rnd){
  BN_rand(rnd -> r, 256, -1, 0);
  BN_rand(rnd -> s, 256, -1, 0);
}


void chameleon_hash_sample_message(const struct ch_sys_params *sys,
				   const struct eval_key *ek,
				   struct message *msg){
  ssize_t ret;
  do{
    ret = getrandom(msg -> msg, msg -> size, 0);
  }while(ret != msg -> size);
}

void chameleon_hash_sample_digest(const struct ch_sys_params *sys,
				  const struct eval_key *ek,
				  struct digest *dgt){
  BN_rand(dgt -> value, 256, -1, 0);
}


bool compare_digest(struct digest *dgt1, struct digest *dgt2){
  return (BN_cmp(dgt1 -> value, dgt2 -> value) == 0);
}
