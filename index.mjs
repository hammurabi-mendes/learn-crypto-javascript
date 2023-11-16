// Documentation in https://nodejs.org/api/crypto.htm
import * as crypto from 'crypto'

// Generates random bytes

function testRandom() {
	let random = crypto.randomBytes(32)

	console.log("Random numbers:", random.toString('hex'))
}

testRandom()

// Hashes

function testHashing() {
	let message = "I'm going to the Taylor Swift show"

	// Choose the algorithm
	// Use "openssl list -digest-algorithms" to see hash algorithms available
	// sha256, blake2s256 are most common

	// Create the hash once, update multiple times before calling digest()
	const hasher = crypto.createHash('sha256')
		.update(message)
		.digest()

	const hashed = hasher.toString('hex')

	console.log("Hashed message:", hashed)
}

testHashing()

// Symmetric encryption

import { encrypt, decrypt } from './symmetric.mjs'

function testSymmetric() {
	let key = "TaylorSwift"

	let encrypted = encrypt(key, "And I'm going to buy a T-shirt")
	console.log("Encrypted message:", encrypted)

	let decrypted = decrypt(key, encrypted)
	console.log("Decrypted message:", decrypted)
}

testSymmetric()

// Asymmetric encryption (using Node.js crypto)

import { getPublicPrivate, sign, verify } from './asymmetric-nodecrypto.mjs'

function testAsymmetric() {
	const { privateKey, publicKey } = getPublicPrivate()

	const message = 'Is his password really TaylorSwift?'

	// Sign
	const signature = sign(privateKey, message)
	console.log("Signature:", signature)

	// Verify
	console.log("Verification result:", verify(publicKey, message, signature))
}

testAsymmetric()

// Diffie Hellman (using Node.js crypto)

import { generatePublicPrivateDH, makeKey } from './diffie-hellman-nodecrypto.mjs'

function testDiffieHellman() {
	const aliceKeyPair = generatePublicPrivateDH()
	const bobKeyPair = generatePublicPrivateDH()

	const key1 = makeKey(aliceKeyPair.privateKey, bobKeyPair.publicKey)
	const key2 = makeKey(bobKeyPair.privateKey, aliceKeyPair.publicKey)

	console.log("DH Keys identical:", key1 == key2)
}

testDiffieHellman()

// Now using the Noble library:
// 	- noble-curves: audited (as of writing) and has multiple curves, multiple signature schemes
//	- noble-hashes: audited (as of writing) and has multiple hashes, KDFs, etc

import { demoDiffieHellman } from './diffie-hellman-noble.mjs'
import { demoSignature, demoBlsSignatures, demoBlsAggregateSignatures, demoVerifyBatch } from './asymmetric-noble.mjs'

demoSignature("Fearless")
demoDiffieHellman()
demoBlsSignatures("Red")
demoBlsAggregateSignatures("Folklore")
demoVerifyBatch()

///////////////////////////////////////////////////////////////
// From now on, most is done using noble-curves/noble-hashes //
///////////////////////////////////////////////////////////////

// Shamir's Secret Sharing

import { generateShares, reconstructSecret } from './secret-sharing.mjs'

function testSecretSharing() {
	let secret = 1989n

	let shares = generateShares(secret, 3, 5)

	let secretRecovered = reconstructSecret([shares[1], shares[3], shares[4]])

	console.log("Shamir secret recovered:", secret == secretRecovered)
}

testSecretSharing()

// Threshold signatures on BLS12-381

import { getSharesTS, signTS, aggregateSignaturesTS } from './asymmetric-noble.mjs'
import { bls12_381 } from '@noble/curves/bls12-381'

function testThresholdSignatures() {
	let { shares: sharesTS, masterPublicKey: publicKeyTS } = getSharesTS(3, 5)

	const message = "And you've got your share of secrets\n\
	 		 And I'm tired of being last to know, oh"
	const encodedMessage = new TextEncoder().encode(message)

	// Each party signs separately
	const partialSignatureA = signTS(message, sharesTS[1])
	const partialSignatureB = signTS(message, sharesTS[3])
	const partialSignatureC = signTS(message, sharesTS[4])

	let aggregateSignatureTS = aggregateSignaturesTS([partialSignatureA, partialSignatureB, partialSignatureC])

	console.log("Threshold signature valid:", bls12_381.verify(aggregateSignatureTS, encodedMessage, publicKeyTS))
}

testThresholdSignatures()

// Polynomial Commitments

import { demoPolynomialCommitment } from './poly-commitment.mjs'

demoPolynomialCommitment([10, 20, 30, 40, 50])

// MACs: HMACs and Pedersen

import { field, demoHmac, calculatePedersen, verifyPedersen } from './commitment.mjs'

demoHmac()

function testPedersen() {
	let message1 = "We get so caught up in all of it"
	let message2 = "Business and relationships"

	// Using object desctructuring feature in JavaScript
	let { commitment: commitment1, r: r1 } = calculatePedersen([message1])
	let { commitment: commitment2, r: r2 } = calculatePedersen([message2])

	console.log("Pedersen verification", verifyPedersen(commitment1, r1, [message1]))

	let commitmentA = field.mul(commitment1, commitment2)
	// Essential that this is not modular addition (because it's in the exponent)
	let rA = r1 + r2

	console.log("Pedersen verification (aggregate):", verifyPedersen(commitmentA, rA, [message1, message2]))
}

testPedersen()

import { demoPolynomials } from './polynomials.mjs'

demoPolynomials()

// Certificates

import { demoCertificates } from './certificates.mjs'

demoCertificates()

// Merkle Tree

import { MerkleTree } from './merkle_tree.mjs'
import { sha3_256 } from '@noble/hashes/sha3'
import { tuplehash256 } from '@noble/hashes/sha3-addons'
import { bytesToNumberLE } from '@noble/curves/abstract/utils'

function testMerkleTree() {
	let merkleTree = new MerkleTree(
		2,
		(a, b) => {
			return bytesToNumberLE(tuplehash256([a.toString(16), b.toString(16)]))

			// If you ever want to do something like this, you should probably use TupleHash or something similar
			// return bytesToNumberLE(sha3_256(a.toString(16) + "|" + b.toString(16)))

			// For debugging
			// return a.toString(10) + "|" + b.toString(10)
		}
	)

	console.log("Merkle Root:", merkleTree.getRoot())
	merkleTree.append(10n, true)
	console.log("Merkle Root:", merkleTree.getRoot())
	merkleTree.append(20n, true)
	console.log("Merkle Root:", merkleTree.getRoot())
	merkleTree.append(30n, true)
	console.log("Merkle Root:", merkleTree.getRoot())
	merkleTree.append(40n, true)
	console.log("Merkle Root:", merkleTree.getRoot())
}

testMerkleTree()

// Poseidon

import { getPoseidon } from './poseidon/poseidon.mjs'

function testPoseidon() {
	const poseidon = getPoseidon(2, 2)

	const poseidonOutput = poseidon([1n, 2n])

	const circomOutput = [
		7853200120776062878684798364095072458815029376092732009249414926327459813530n,
		7142104613055408817911962100316808866448378443474503659992478482890339429929n
	]

	console.log(
		"Poseidon hash (matches with circom):",
		(poseidonOutput[0] == circomOutput[0] && poseidonOutput[1] == circomOutput[1])
	)
}

testPoseidon()

// ECIES (Elliptic Curve Integrated Encryption Scheme)

import { x25519 } from '@noble/curves/ed25519'
import { encryptEcies, decryptEcies } from './asymmetric-noble.mjs'

function testECIES() {
	const privateKeyReceiver = x25519.utils.randomPrivateKey()
	const publicKeyReceiver = x25519.getPublicKey(privateKeyReceiver)

	const messageEcies = "You learn my secrets and you figure out why I'm guarded"

	const encryptedPackage = encryptEcies(messageEcies, publicKeyReceiver)
	const messageEcies2 = decryptEcies(privateKeyReceiver, encryptedPackage)

	console.log("ECICS decrypts successfully:", messageEcies == messageEcies2)
}

testECIES()

import { blindSignaturesSetup, blindSignaturesPack, blindSignaturesSign, blindSignaturesUnpack } from './asymmetric-noble.mjs'

// Blind Signatures

function testBlindSignatures() {
	const message = "Let's fast forward to three hundred awkward blind dates later (Oh)"
	const encodedMessage = new TextEncoder().encode(message)

	// Producer (pack)
	const { blindPoint, randomScalar } = blindSignaturesPack(encodedMessage)

	// Signer
	const { privateKey, publicKey1, publicKey2 } = blindSignaturesSetup()

	const blindSignatureB = blindSignaturesSign(privateKey, blindPoint)

	// Producer (unpack)
	const signatureB = blindSignaturesUnpack(publicKey2, randomScalar, blindSignatureB)

	// Producer (verify)
	console.log("Blind Signature valid:", bls12_381.verify(signatureB, encodedMessage, publicKey1))
}

testBlindSignatures()

// Ring Signatures

import { signRing, verifyRing } from './asymmetric-noble.mjs'
import { bn254 } from '@noble/curves/bn254'

function testRingSignatures() {
        const SIGN_INDEX = 3

	let publicKeys = []
	let privateKeys = []

	for(var i = 0; i < 10; i++) {
		privateKeys[i] = bn254.utils.randomPrivateKey()
		publicKeys[i] = bn254.getPublicKey(privateKeys[i])
        }

        let message = "The moon is high\n\
		Like your friends were the night that we first met\n\
		Went home and tried to stalk you on the internet\n\
		Now I've read all of the books beside your bed"

	const encodedMessage = new TextEncoder().encode(message)

        let ringSignature = signRing(
            SIGN_INDEX,
            privateKeys[SIGN_INDEX],
            publicKeys,
            encodedMessage
        )

	console.log("Ring Signature valid:", verifyRing(publicKeys, encodedMessage, ringSignature))
}

testRingSignatures()

// Verifiable Random Functions (First construction)

import { generateVR, checkVR } from './vrf.mjs'

function testVRF1() {
	const privateKeyVRF = bls12_381.utils.randomPrivateKey()
	const publicKeyVRF = bls12_381.getPublicKey(privateKeyVRF)

	const message = "Tonight, I'm gonna dance; For all that we've been through"

	let { random: outputVRF, signature: signatureVRF } = generateVR(privateKeyVRF, message)

	console.log("VRF-1 output:", outputVRF)
	console.log("VRF-1 checks:", checkVR(outputVRF, signatureVRF, message, publicKeyVRF))
}

testVRF1()

// Verifiable Random Functions (Second construction)

import { generateIntermediateAndProof, generateFinalAndVerify } from './vrf.mjs'

function testVRF2() {
	const privateKeyVRF = bls12_381.utils.randomPrivateKey()
	const publicKeyVRF = bls12_381.getPublicKey(privateKeyVRF)

	const message = "But I don't wanna dance; If I'm not dancing with you"
	const encodedMessage = new TextEncoder().encode(message)

	const { intermediate, proof } = generateIntermediateAndProof(privateKeyVRF, encodedMessage)
	const { final, valid } = generateFinalAndVerify(encodedMessage, publicKeyVRF, intermediate, proof)

	console.log("VRF-2 output:", final)
	console.log("VRF-2 checks:", valid)
}

testVRF2()

// OPRF (Oblivious PRF)

import { feedAndBlind, hashBlindPoint, unblind } from './oprf.mjs'

function testOPRF() {
	const privateKeyHasher = bls12_381.utils.randomPrivateKey()
	const publicKeyHasher = bls12_381.getPublicKey(privateKeyHasher)

	const message = "Maybe I was naive, got lost in your eyes\n\
		And never really had a chance"
	const encodedMessage = new TextEncoder().encode(message)

	const { randomScalar, blindPoint } = feedAndBlind(encodedMessage)

	const hashedBlindPoint = hashBlindPoint(blindPoint, privateKeyHasher)

	const oprfOutput = unblind(hashedBlindPoint, randomScalar)

	// For matching
	const prfOutput = bls12_381.G2.hashToCurve(encodedMessage).multiply(
		bls12_381.G1.normPrivateKeyToScalar(privateKeyHasher)
	)
	
	console.log("OPRF output:", oprfOutput)
	console.log("OPRF valid:", oprfOutput.equals(prfOutput))
}

testOPRF()

// Oblivious Transfer

import { ed25519 } from '@noble/curves/ed25519'
import { getReceiverPublicKeyOT, getSenderSharedSecretsOT, getReceiverSharedSecretOT } from './oblivious-transfer.mjs'
import { encryptAuthenticated, decryptAuthenticated } from './symmetric.mjs'

// Available for a more holistic perspective
// demoObliviousTransfer(1)

function testObliviousTransfer() {
	let privateKeyA = ed25519.utils.randomPrivateKey()
	let publicKeyA = ed25519.getPublicKey(privateKeyA)

	let privateKeyB = ed25519.utils.randomPrivateKey()
	let publicKeyB = ed25519.getPublicKey(privateKeyB)

	let choice = 1
	let choicePublicKeyB = getReceiverPublicKeyOT(publicKeyA, publicKeyB, choice)

	let { keySender1, keySender2 } = getSenderSharedSecretsOT(choicePublicKeyB, publicKeyA, privateKeyA)
	let { keyReceiver } = getReceiverSharedSecretOT(publicKeyA, privateKeyB)

	const messages = [
		"Cause the players gonna play, play, play, play, play",
		"And the haters gonna hate, hate, hate, hate, hate"
	]

	const encryptedPackages = [
		encryptAuthenticated(keySender1, messages[0]),
		encryptAuthenticated(keySender2, messages[1])
	]

	const plaintext = decryptAuthenticated(keyReceiver, encryptedPackages[choice])

	console.log("OT choice checks:", plaintext == messages[choice])

	try {
		const plaintext = decryptAuthenticated(keyB, encryptedPackages[1 - choice])

		console.log("OT non-choice checks:", plaintext == messages[1 - choice])
	}
	catch(error) {
		console.log("OT non-choice generates authentication error")
	}
}

testObliviousTransfer()
