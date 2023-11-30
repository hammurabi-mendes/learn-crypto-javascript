# Learning Cryptography with Javascript

Meant-for-learners Javascript implementations of threshold signatures, secret sharing, KZG polynomial commitments, blind signatures, ring signatures, merkle trees, poseidon helpers (without the circomlib dependency), verifiable random functions, and oblivious transfer among other things. **DO NOT USE IT IN PRODUCTION**: this code is meant for learners. The idea is to have **clean, well-organized code** for learning. If you need anything in production, do not use this code and do not "roll your own crypto": find **another** implementation, one that has been instead subject to auditing and written specifically for that purpose.

**NOTE:** I also published a meant-to-be-learned ZK-rollup in Javascript in "[A Simple ZK-rollup](https://github.com/hammurabi-mendes/zk-rollup)".

## Support
- If you think this repository is useful, please consider supporting it here:
	- Bitcoin: ```bc1qwjunpsdhtsmcwt7m8enpwepgc6yngk82apeus3```
	- Ethereum: ```0xcFD3F755e853AD1C3568ebF74ce5619D743c9b17```
	- Dogecoin: ```DDHuFi8im3qF3ma3NhG87fx9uADQuLxHhV```
	- Solana: ```6tiWSNnWA4GXdAbbxMjXpfLGjpvqufi3zBjdV3vgcAXv```
	- Polkadot: ```13EnQE9BKT5Ys5woLxbmoouez8RExv8y5H9zDkyMjfdqxYdT```
	- Cardano: ```addr1q98njwcme5spxtayqax4vcmw3etku0367azujs4ry5dlhpq29zq6wh60s8j3s6jnzclhgfncewffj33eamdn5swav5xsqqsyg4```
	- Algorand: ```FNTPKB6TSAW626J3SJJFM4DIJ4XG2J6WU2NX2DIKOR4ZOUUZQKFRNKOGQA```
	- Tezos: ```tz1NuFTzK5Gq7ekCwdSV7NZrhaBVjdJgY5qg```
	- NEAR: ```681243cea225318e97b1dc06cf9d81912e163992f67b1b2697e29ffcd4123cec```

- I am considering writing:
	- (MPC) The SPDZ protocol (Javascript and Rust)
	- (ZK) Sumcheck, GKR, and Plonk (Javascript and Rust)
	- (Trusted Setup) A tool to contribute to trusted setups and to read SnarkJS ptau files (Javascript)

## Walkthrough

You are ready to go through the ```index.mjs``` file. Examine the test functions in order, each time navigating to the files where the implementation is found. We start with the basics and we find ourselves quickly in the non-basics.

### (If you need background information...)
If you are starting from nothing, I suggest reading either [this](https://www.manning.com/books/real-world-cryptography) book or [this](https://nostarch.com/seriouscrypto). If you need background in elliptic-curve cryptography, there are various resources but maybe you can start [here](https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/). You can learn about the BLS12-381 curve [here](https://hackmd.io/@benjaminion/bls12-381) and about the BN254 [here](https://hackmd.io/@jpw/bn254). Maybe you can learn about BLS signatures [here](https://medium.com/cryptoadvance/bls-signatures-better-than-schnorr-5a7fe30ea716) and then signature aggregation [here](https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html). A good resource for Shamir's secret sharing and threshold signatures is [here](https://github.com/dashpay/dips/blob/master/dip-0006/bls_m-of-n_threshold_scheme_and_dkg.md). The Monero [book](https://web.getmonero.org/library/Zero-to-Monero-2-0-0.pdf) is well-written, and reading chapters 1-3 (up to Sec. 3.3, inclusive) should be helpful. A wonderful resource for KZG polynomial commitments is [here](https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html). There are many other resources, these are just examples. This repository does not suggest or require any of these resources specifically, but they might be helpful if you are in search for background information.

### The Basics
- PRNG and hashing in Node.js Crypto API
- (```symmetric.mjs```) Symmetric cryptography using Node.js Crypto API
	* encrypt/decrypt
	* Authenticated encryption using AES-256-GCM
- (```asymmetric-nodecrypto.mjs```) Asymmetric cryptography in Node.js Crypto API
- (```asymmetric-noble.mjs```) Asymmetric cryptography in Noble Curves
	* Demo on basic signing and BLS aggregate signatures
		- Including a naive/simplified BLS implementation done directly in $G_1$ and $G_2$
	* These are in the same file, but you'll find them again later; follow the order and you'll get there
		- Threshold signatures
		- ECIES
		- Blind signatures
		- Ring signatures
- (```diffie-helman*.mjs```) Diffie-Hellman in Node.js Crypto API and Noble Curves

### The Cool Stuff
- (```secret-sharing.mjs```) Shamir's Secret Sharing
	- (polynomials.mjs) Our interpolation is using the Lagrange algorithm [here](https://en.wikipedia.org/wiki/Lagrange_polynomial)
- (```asymmetric-noble.mjs```) Threshold Signatures
- (```poly-commitment.mjs```) KZG polynomial commitment scheme
- (```commitment.mjs```) HMACs and Pedersen commitments
	- Includes checking homomorphic properties of Pedersen commitments
- (```openssl directory```) OpenSSL certificates and CLI tool
	- Scripts documenting commands to create keypairs, certificates both in Ed25519 and secp256k1
	- Two certificates have been created and are manipulated using Javascript (see below)
- (```certificates.mjs```) Certificates loading/usage from Javascript
	- Uses both Node.js Crypto API and Noble Curves
	  * Including interoperation: load the certificate in one library, and use it in the other
	- If you want to regenerate the certificates, just run ```commands_*.sh``` in the ```openssl``` directory.
- (```merkle_tree.mjs```) Merkle Trees
	- A sparse Merkle Tree with extra convenient functions that are used in the ZK-Rollup project
- (```poseidon directory```) Poseidon hashing
	- Generated constants using SAGE (see README.txt inside the poseidon directory)
	  * Stored into a Javascript file
	- Parameters identical to those used in circom; generates the same circom outputs
- (```asymmetric-noble.mjs```) ECIES
	- Using AES-256-GCM as authenticated encryption
- (```asymmetric-noble.mjs```) Blind Signatures
	- Done on BLS12-381, based on [this](https://eprint.iacr.org/2002/118)
- (```asymmetric-noble.mjs```) Ring Signatures
	- SAG scheme from the [Monero documentation](https://web.getmonero.org/library/), done on BN254
- (```vrf.mjs```) VRFs (Verifiable Random Functions)
	- Construction 1 from [here](https://docs.harmony.one/home/developers/harmony-specifics/tools/harmony-vrf)
	- Construction 2 from [here](https://eprint.iacr.org/2017/099.pdf)
- (```oprf.mjs```) Oblivious PRF
	- Generate a hash output at the destination from a blinded input. Similar to blind signatures.
- (```oblivious-transfer.mjs```) Oblivious Transfer in Multiparty Computation (MPC)
	- Allows a sender to offer two values to a receiver, which can only obtain one of the values offerred (the chosen value is unknown to the sender)

## License and Closing Remarks

This code is licensed under the 3-Clause BSD License. Please maintain the donation addresses if you fork the repository. Do not use this code in production. If you need anything in production, do not use this code and do not "roll your own crypto": find **another** implementation, one that has been instead subject to auditing and written specifically for that purpose.
