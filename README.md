# Redactable Blockchain Tests and Experiments

This repository stores several tests used in the paper "Redacting
Blockchain without Exposing Chameleon Hash Functions", published in
the 21st International Conference on Cryptology and Network Security
(CANS 2022).

To run the tests, you should compile each one passing the correct
option for the Makefile.

The options are described below.

## Regular (non-redactable) Blockchain

To compile this test, run:

  make regular_blockchain

And then run the executable "blockchain" . The program will generate
1MB random blocks and compute its SHA256 hash twice (computing the
hash of the random block, and then computing the hash of the
digest). This simulates how long it takews to compute the hash of a
classical blockchain, like the Bitcoin blockchain, with 1MB blocks.

## Ateniese's Redactable Blockchain using Classical Chameleon Hash

To compile this test, run:

  make classical_redactable_blockchain

And then run the executable "classical_redactable_blockchain". This
program will create random 1MB blocks and will compute how long it
takes to compute the hash of these blocks running the generic group
Chameleon Hash described in the paper "On the Key Exposure Problem in
Chameleon Hashes" by Giuseppe Ateniese and Breno de Medeiros. It also
will compute how long one could use the chameleon hash "collision"
algorithm of this construction.

These tests simulate how long it takes to compute the hash of a
redactable blockchain using Ateniese's construction proposed in
"Redactable Blockchain – or – Rewriting History in Bitcoin and
Friends" using a traditional chameleon hash construction and also how
long it takes to redact a block using that construction.

## Ateniese's Redactable Blockchain using Secret-Coin Chameleon Hash

To compile this test, run:

  make secret_coin_redactable_blockchain

And then run the executable "secret_coin_redactable_blockchain". This
program will compute random 1MB blocks and will compute how long it
takes to compute the hash of these blocks using the composition of a
SHAKE256 hash and the secret-coin chameleon hash proposed in the paper
"Bringing order to chaos: The case of collision-resistant
chameleon-hashes" written by David Derler, Kai Samelin and Daniel
Slamanig. It also will compute how long it takes to compute the
chameleon hash "verify" "collision" algorithm of this construction.

These tests simulate how long it takes to compute the hash of a
redactable blockchain using Ateniese's construction proposed in
"Redactable Blockchain – or – Rewriting History in Bitcoin and
Friends" using a secret-coin chameleon hash and also how long it takes
to verify and redact a block using that construction.

## Our Proposed Blockchain with Bellare's Chameleon Hash (Factoring Assumption)

To compile this test, run:

  make factoring_preimage_blockchain

And then run the executable "factoring_preimage_blockchain". This
program will compute random 1MB blocks and will compute how long it
takes to compute the hash of these blocks using the composition of a
SHAKE256 hash and the traditional chameleon hash based on factoring
assumption proposed in the paper "A Characterization of Chameleon Hash
Functions and New, Efficient Designs" written by Mihir Bellare and
Todor Ristov. It also will compute how long it would take to compute
the chameleon hash "preimage" algorithm of this construction.

These tests simulate how long it takes to compute the hash of a
redactable blockchain using our paper's construction using a
traditional chameleon hash based on factoring assumption and also how
long it takes to redact a block using this construction.

## Our Proposed Blockchain with Bellare's Chameleon Hash (Small Primes Modular Square Root)

To compile this test, run:

  make preimage_blockchain_small_primes

And then run the executable "preimage_blockchain_small_primes". This
will run the same test from the previous section based on Factoring
Assumption. However, it activates a proposed optimization that
requires a stronger assumption: that it is hard to compute modular
square roots of small primes (instead of random prime numbers) modulo
a semiprime number.

## Our Proposed Blockchain with Post-Quantum Chameleon Hash based on Ring-SIS

To compile this test, run:

  make preimage_blockchain_ring_sis

And then run the executable "preimage_blockchain_ring_sis". This
program will compute random 1MB blocks and will compute how long it
takes to compute the hash of these blocks using the chameleon hash
proposed in the paper "Improved Short Lattice Signatures in the
Standard Model" written by Léo Ducas and Daniele Micciancio. We use a
small optimization that uses the random oracle model. It also will
compute how long it takes tocompute the chameleon hash "preimage"
algorithm of this construction.

These tests simulate how long it takes to compute the hash of a
redactable blockchain using our paper's construction using a
traditional chameleon hash based on Ring-SIS assumption and also how
long it takes to redact a block using this construction.

## Our Proposed Blockchain with Post-Quantum Chameleon Hash based on Ring-SIS + NTRU Assumptions

To compile this test, run:

  make preimage_blockchain_ntru

And then run the program "preimage_blockchain_ntru". This program will
compute random 1MB blocks and will compute how long it takes to
compute the hash of these blocks using the chameleon hash proposed in
the paper "Raptor: A Practical Lattice-Based (Linkable) Ring
Signature" written by Xingye Lu, Man Ho Au and Zhenfei Zhang. It also
will compute how long it takes tocompute the chameleon hash "preimage"
algorithm of this construction.

These tests simulate how long it takes to compute the hash of a
redactable blockchain using our paper's construction using a
traditional chameleon hash based on Ring-SIS + NTRU assumption and
also how long it takes to redact a block using this construction.
