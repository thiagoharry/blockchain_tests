preimage_blockchain_falcon: chameleon_hash_falcon.c preimage_blockchain_falcon.c
	$(CC) -g -Wall -O2 -c -include chameleon_hash_falcon.c preimage_blockchain_falcon.c
	$(CC) -g -Wall -O2 -c raptor/falcon/nist.c
	$(CC) -g -Wall -O2 -c raptor/falcon/falcon-keygen.c
	$(CC) -g -Wall -O2 -c raptor/rng/rng.c
	$(CC) -g -Wall -O2 -c raptor/falcon/falcon-sign.c
	$(CC) -g -Wall -O2 -c raptor/falcon/falcon-vrfy.c
	$(CC) -g -Wall -O2 -c raptor/falcon/shake.c
	$(CC) -g -Wall -O2 -c raptor/falcon/falcon-fft.c
	$(CC) -g -Wall -O2 -c ./raptor/falcon/falcon-enc.c
	$(CC) -g -Wall -O2 -c raptor/falcon/frng.c
	$(CC) -g -Wall -O2 -c raptor/poly.c
	$(CC) -g -Wall -O2 -c raptor/rng/fastrandombytes.c
	$(CC) -g -Wall -O2 -c raptor/rng/crypto_hash_sha512.c
	$(CC) -g -Wall -O2 -c raptor/falcon/crypto_stream.c
	$(CC) -g -Wall -O2 -c raptor/rng/shred.c
	$(CC) -g -Wall -O2 -c raptor/raptor.c
	$(CC) -g -Wall -O2 preimage_blockchain_falcon.o rng.o nist.o falcon-keygen.o falcon-sign.o falcon-vrfy.o shake.o falcon-fft.o falcon-enc.o frng.o poly.o fastrandombytes.o crypto_hash_sha512.o shred.o raptor.o crypto_stream.o -o preimage_blockchain_falcon -lgmp -lm -lcrypto
ch_falcon:
	$(CC) -g -Wall -O2 -c -include chameleon_hash_falcon.c test_preimage_chameleon_hash.c
	$(CC) -g -Wall -O2 -c raptor/falcon/nist.c
	$(CC) -g -Wall -O2 -c raptor/falcon/falcon-keygen.c
	$(CC) -g -Wall -O2 -c raptor/rng/rng.c
	$(CC) -g -Wall -O2 -c raptor/falcon/falcon-sign.c
	$(CC) -g -Wall -O2 -c raptor/falcon/falcon-vrfy.c
	$(CC) -g -Wall -O2 -c raptor/falcon/shake.c
	$(CC) -g -Wall -O2 -c raptor/falcon/falcon-fft.c
	$(CC) -g -Wall -O2 -c ./raptor/falcon/falcon-enc.c
	$(CC) -g -Wall -O2 -c raptor/falcon/frng.c
	$(CC) -g -Wall -O2 -c raptor/poly.c
	$(CC) -g -Wall -O2 -c raptor/rng/fastrandombytes.c
	$(CC) -g -Wall -O2 -c raptor/rng/crypto_hash_sha512.c
	$(CC) -g -Wall -O2 -c raptor/falcon/crypto_stream.c
	$(CC) -g -Wall -O2 -c raptor/rng/shred.c
	$(CC) -g -Wall -O2 -c raptor/raptor.c
	$(CC) -g -Wall -O2 test_preimage_chameleon_hash.o rng.o nist.o falcon-keygen.o falcon-sign.o falcon-vrfy.o shake.o falcon-fft.o falcon-enc.o frng.o poly.o fastrandombytes.o crypto_hash_sha512.o shred.o raptor.o crypto_stream.o -o chameleon_hash -lm -lcrypto
ateniese04a: chameleon_hash_ateniese04a.c
	$(CC) -g -Wall -O2 -c -include chameleon_hash_ateniese04a.c test_preimage_chameleon_hash.c
	$(CC) -g -Wall -O2 test_preimage_chameleon_hash.o -o chameleon_hash -lcrypto -lm
preimage_blockchain: chameleon_hash_bellare08c.c preimage_blockchain.c natural.c
	$(CC) -g -Wall -O2 -c natural.c
	$(CC) -g -Wall -O2 -c -include chameleon_hash_bellare08c.c preimage_blockchain.c
	$(CC) -g -Wall -O2 natural.o preimage_blockchain.o -o preimage_blockchain -lgmp -lm -lcrypto
secret_coin_redactable_blockchain: chameleon_hash_derler20.c secret_coin_redactable_blockchain.c natural.c
	$(CC) -g -Wall -O2 -c natural.c
	$(CC) -g -Wall -O2 -c -include chameleon_hash_derler20.c secret_coin_redactable_blockchain.c
	$(CC) -g -Wall -O2 natural.o secret_coin_redactable_blockchain.o -o secret_coin_redactable_blockchain -lgmp -lm -lcrypto
classical_redactable_blockchain: chameleon_hash_ateniese04a.c classical_redactable_blockchain.c
	$(CC) -g -Wall -O2 -c -include chameleon_hash_ateniese04a.c classical_redactable_blockchain.c
	$(CC) -g -Wall -O2  classical_redactable_blockchain.o -o classical_redactable_blockchain -lm -lcrypto
krawczyk98a:
	$(CC) -g -Wall -O2 -c natural.c
	$(CC) -g -Wall -O2 -c -include chameleon_hash_krawczyk98a.c test_preimage_chameleon_hash.c
	$(CC) -g -Wall -O2 natural.o test_preimage_chameleon_hash.o -o chameleon_hash -lgmp -lm
bellare08c:
	$(CC) -g -Wall -O2 -c natural.c
	$(CC) -g -Wall -O2 -c -include chameleon_hash_bellare08c.c test_preimage_chameleon_hash.c
	$(CC) -g -Wall -O2 natural.o test_preimage_chameleon_hash.o -o chameleon_hash -lgmp -lm
derler20:
	$(CC) -g -Wall -O2 -c natural.c
	$(CC) -g -Wall -O2 -c -include chameleon_hash_derler20.c test_secret_coin_chameleon_hash.c
	$(CC) -g -Wall -O2 natural.o test_secret_coin_chameleon_hash.o -o secret_coin_chameleon_hash -lgmp -lm -lcrypto
regular_blockchain:
	$(CC) -Wall -O2 sha256.c -o blockchain -lcrypto  -lm
