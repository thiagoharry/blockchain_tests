RING_INCLUDE=-I/usr/local/include/palisade-signature/ -I/usr/local/include/palisade/pke/ -I/usr/local/include/palisade/core/ -I/usr/local/include/palisade/

preimage_blockchain_ring_sis: src/preimage_blockchain_ring_sis.cpp src/ring_sis/chameleon_hash.cpp src/ring_sis/context.cpp 
	g++ --std=c++11 -Wall -O2 -fopenmp ${RING_INCLUDE} -c src/preimage_blockchain_ring_sis.cpp
	g++ --std=c++11 -Wall -O2 -fopenmp ${RING_INCLUDE} -c src/ring_sis/chameleon_hash.cpp
	g++ --std=c++11 -Wall -O2 -fopenmp ${RING_INCLUDE} -c src/ring_sis/context.cpp 
	g++ --std=c++11 -Wall -O2 -fopenmp ${RING_INCLUDE} preimage_blockchain_ring_sis.o chameleon_hash.o context.o -o preimage_blockchain_ring_sis -lPALISADEcore -lPALISADEsignature -lcrypto
preimage_blockchain_ntru: src/chameleon_hash_falcon.c src/preimage_blockchain_falcon.c
	$(CC) -g -Wall -O2 -c -include src/chameleon_hash_falcon.c src/preimage_blockchain_falcon.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/nist.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/falcon-keygen.c
	$(CC) -g -Wall -O2 -c src/raptor/rng/rng.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/falcon-sign.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/falcon-vrfy.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/shake.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/falcon-fft.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/falcon-enc.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/frng.c
	$(CC) -g -Wall -O2 -c src/raptor/poly.c
	$(CC) -g -Wall -O2 -c src/raptor/rng/fastrandombytes.c
	$(CC) -g -Wall -O2 -c src/raptor/rng/crypto_hash_sha512.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/crypto_stream.c
	$(CC) -g -Wall -O2 -c src/raptor/rng/shred.c
	$(CC) -g -Wall -O2 -c src/raptor/raptor.c
	$(CC) -g -Wall -O2 preimage_blockchain_falcon.o rng.o nist.o falcon-keygen.o falcon-sign.o falcon-vrfy.o shake.o falcon-fft.o falcon-enc.o frng.o poly.o fastrandombytes.o crypto_hash_sha512.o shred.o raptor.o crypto_stream.o -o preimage_blockchain_ntru -lgmp -lm -lcrypto
ch_falcon:
	$(CC) -g -Wall -O2 -c -include src/chameleon_hash_falcon.c src/test_preimage_chameleon_hash.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/nist.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/falcon-keygen.c
	$(CC) -g -Wall -O2 -c src/raptor/rng/rng.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/falcon-sign.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/falcon-vrfy.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/shake.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/falcon-fft.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/falcon-enc.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/frng.c
	$(CC) -g -Wall -O2 -c src/raptor/poly.c
	$(CC) -g -Wall -O2 -c src/raptor/rng/fastrandombytes.c
	$(CC) -g -Wall -O2 -c src/raptor/rng/crypto_hash_sha512.c
	$(CC) -g -Wall -O2 -c src/raptor/falcon/crypto_stream.c
	$(CC) -g -Wall -O2 -c src/raptor/rng/shred.c
	$(CC) -g -Wall -O2 -c src/raptor/raptor.c
	$(CC) -g -Wall -O2 test_preimage_chameleon_hash.o rng.o nist.o falcon-keygen.o falcon-sign.o falcon-vrfy.o shake.o falcon-fft.o falcon-enc.o frng.o poly.o fastrandombytes.o crypto_hash_sha512.o shred.o raptor.o crypto_stream.o -o chameleon_hash -lm -lcrypto
ateniese04a: src/chameleon_hash_ateniese04a.c
	$(CC) -g -Wall -O2 -c -include src/chameleon_hash_ateniese04a.c src/test_preimage_chameleon_hash.c
	$(CC) -g -Wall -O2 test_preimage_chameleon_hash.o -o chameleon_hash -lcrypto -lm
factoring_preimage_blockchain: src/chameleon_hash_bellare08c.c src/preimage_blockchain.c src/natural.c
	$(CC) -g -Wall -O2 -c src/natural.c
	$(CC) -g -Wall -O2 -c -include src/chameleon_hash_bellare08c.c src/preimage_blockchain.c
	$(CC) -g -Wall -O2 natural.o preimage_blockchain.o -o factoring_preimage_blockchain -lgmp -lm -lcrypto
preimage_blockchain_small_primes: src/chameleon_hash_bellare08c.c src/preimage_blockchain.c src/natural.c
	$(CC) -g -Wall -O2 -c src/natural.c
	$(CC) -g -Wall -O2 -c -DSMALL_PRIMES -include src/chameleon_hash_bellare08c.c src/preimage_blockchain.c
	$(CC) -g -Wall -O2 natural.o preimage_blockchain.o -o preimage_blockchain_small_primes -lgmp -lm -lcrypto
secret_coin_redactable_blockchain: src/chameleon_hash_derler20.c src/secret_coin_redactable_blockchain.c src/natural.c
	$(CC) -g -Wall -O2 -c src/natural.c
	$(CC) -g -Wall -O2 -c -include src/chameleon_hash_derler20.c src/secret_coin_redactable_blockchain.c
	$(CC) -g -Wall -O2 natural.o secret_coin_redactable_blockchain.o -o secret_coin_redactable_blockchain -lgmp -lm -lcrypto
classical_redactable_blockchain: src/chameleon_hash_ateniese04a.c src/classical_redactable_blockchain.c
	$(CC) -g -Wall -O2 -c -include src/chameleon_hash_ateniese04a.c src/classical_redactable_blockchain.c
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
	$(CC) -Wall -O2 src/sha256.c -o blockchain -lcrypto  -lm
clean:
	rm -rf *.o *~ preimage_blockchain_ring_sis preimage_blockchain_falcon chameleon_hash preimage_blockchain preimage_blockchain_small_primes secret_coin_redactable_blockchain classical_redactable_blockchain secret_coin_chameleon_hash blockchain
