import { schnorr } from '@noble/curves/secp256k1'
import { ed25519 } from '@noble/curves/ed25519'
import { bls12_381 } from '@noble/curves/bls12-381'

import { generateShares } from './secret-sharing.mjs'
import { lagrangeProjectivePoints, lagrangeProjectivePointsAtZero } from './polynomials.mjs'

export function demoSignature(message) {
	// let module = schnorr
	let module = ed25519

	const privateKey = module.utils.randomPrivateKey()
	const publicKey = module.getPublicKey(privateKey)

	const encodedMessage = new TextEncoder().encode(message)

	const signature = module.sign(encodedMessage, privateKey)
	console.log("Signature:", Buffer.from(signature).toString('hex'))
	console.log("Signature valid:", module.verify(signature, encodedMessage, publicKey))
}

export function demoBlsSignatures(message) {
	const privateKey = bls12_381.utils.randomPrivateKey()
	const publicKey = bls12_381.getPublicKey(privateKey)

	const encodedMessage = new TextEncoder().encode(message)

	const signature = bls12_381.sign(encodedMessage, privateKey)
	console.log("Signature:", Buffer.from(signature).toString('hex'))
	console.log("Signature valid:", bls12_381.verify(signature, encodedMessage, publicKey))
}

export function demoBlsAggregateSignatures(message) {
	const privateKeys = [
		bls12_381.utils.randomPrivateKey(),
		bls12_381.utils.randomPrivateKey(),
		bls12_381.utils.randomPrivateKey()
	]

	const publicKeys = privateKeys.map(bls12_381.getPublicKey)
	const aggregatePublicKey = bls12_381.aggregatePublicKeys(publicKeys)

	const encodedMessage = new TextEncoder().encode(message)

	const signatures = privateKeys.map((p) => bls12_381.sign(encodedMessage, p))
	const aggregatedSignature = bls12_381.aggregateSignatures(signatures)

	console.log("Signature valid:", bls12_381.verify(aggregatedSignature, encodedMessage, aggregatePublicKey))
}

export function demoVerifyBatch() {
	const privateKeys = [
		bls12_381.utils.randomPrivateKey(),
		bls12_381.utils.randomPrivateKey(),
		bls12_381.utils.randomPrivateKey()
	]

	const publicKeys = privateKeys.map(bls12_381.getPublicKey)

	const messages = ['Lover', 'Evermore', 'Midnights']

	const encodedMessages = messages.map((m) => new TextEncoder().encode(m))

	const signatures = privateKeys.map((privateKey, i) => bls12_381.sign(encodedMessages[i], privateKey))
	const aggregatedSignature = bls12_381.aggregateSignatures(signatures)

	console.log("Signature valid:", bls12_381.verifyBatch(aggregatedSignature, encodedMessages, publicKeys))
}

// Threshold Signatures

export function getSharesTS(numberThreshold, numberShares) {
	const masterPrivateKey = bls12_381.utils.randomPrivateKey()
	const masterPublicKey = bls12_381.getPublicKey(masterPrivateKey)

	let numericShares = generateShares(bls12_381.G1.normPrivateKeyToScalar(masterPrivateKey), numberThreshold, numberShares)

	return {
		shares: numericShares.map(({ number, subSecret }) => {
			let sharePrivateKey = bls12_381.fields.Fr.toBytes(subSecret)

			return {
				number,
				privateKey: sharePrivateKey,
				publicKey: bls12_381.getPublicKey(sharePrivateKey)
			}
		}),
		masterPublicKey
	}
}

export function signTS(message, share) {
	const encodedMessage = new TextEncoder().encode(message)

	const signature = bls12_381.sign(encodedMessage, share.privateKey)

	return { number: share.number, signature }
}

export function aggregateSignaturesTS(partialSignatures) {
	let xs = []
	let ys = []

	for (const partialSignature of partialSignatures) {
		xs.push(partialSignature.number)
		ys.push(bls12_381.G2.ProjectivePoint.fromHex(partialSignature.signature))
	}

	// Option 1:
	// let interpolated = lagrangeProjectivePoints(xs, ys, bls12_381.fields.Fr, bls12_381.G2.ProjectivePoint.ZERO)
	// return interpolated[0]

	// Option 2:
	let interpolated = lagrangeProjectivePointsAtZero(xs, ys, bls12_381.fields.Fr, bls12_381.G2.ProjectivePoint.ZERO)
	return interpolated
}

// ECIES

// Documentation in https://nodejs.org/api/crypto.htm
import * as crypto from 'crypto'

import { x25519 } from '@noble/curves/ed25519'
import { pbkdf2 } from '@noble/hashes/pbkdf2'
import { sha256 } from '@noble/hashes/sha256'

import { encryptAuthenticated, decryptAuthenticated } from './symmetric.mjs'

import { getRandomBytes, getRandomElement } from './random.mjs'

export function encryptEcies(message, receiverPublicKey) {
	const privateKey = x25519.utils.randomPrivateKey()
	const publicKey = x25519.getPublicKey(privateKey)

	const sharedKey = x25519.getSharedSecret(privateKey, receiverPublicKey)
	const hashSalt = getRandomBytes(32)

	const key = pbkdf2(sha256, sharedKey, hashSalt, { c: 131072, dkLen: 32 })

	return { publicKey, salt: hashSalt, encrypted: encryptAuthenticated(key, message) }
}

export function decryptEcies(privateKey, cryptogram) {
	const { publicKey: senderPublicKey, salt: hashSalt, encrypted } = cryptogram

	const sharedKey = x25519.getSharedSecret(privateKey, senderPublicKey)

	const key = pbkdf2(sha256, sharedKey, hashSalt, { c: 131072, dkLen: 32 })

	return decryptAuthenticated(key, encrypted)
}

// Blind signatures
// From https://eprint.iacr.org/2002/118
// Discussion about G1 and G2, and cofactors in:
// https://hackmd.io/@benjaminion/bls12-381#Cofactor
// https://eprint.iacr.org/2015/247
// https://eprint.iacr.org/2021/1130 (the isTorsionFree() function accounts for it at the time of writing)

export function blindSignaturesSetup(encodedMessage) {
	const privateKey = bls12_381.utils.randomPrivateKey()
	const publicKey1 = bls12_381.getPublicKey(privateKey)

	const publicKey2 = bls12_381.G2.ProjectivePoint.BASE.multiply(
		bls12_381.G1.normPrivateKeyToScalar(privateKey)
	).toRawBytes()

	return { privateKey, publicKey1, publicKey2 }
}

export function blindSignaturesPack(encodedMessage) {
	// Includes cofactor clearing; see https://hackmd.io/@benjaminion/bls12-381#Cofactor and https://eprint.iacr.org/2015/247
	const hashedPoint = bls12_381.G2.hashToCurve(encodedMessage)
	const randomScalar = bls12_381.G1.normPrivateKeyToScalar(
		bls12_381.utils.randomPrivateKey()
	)

	const blindPoint = hashedPoint.add(
		bls12_381.G2.ProjectivePoint.BASE.multiply(randomScalar)
	)

	return { blindPoint, randomScalar }
}

export function blindSignaturesSign(privateKey, blindPoint) {
	// Includes a subgroup check for the blind point
	// https://eprint.iacr.org/2021/1130
	blindPoint.assertValidity()

	return blindPoint.multiply(bls12_381.G1.normPrivateKeyToScalar(privateKey)).toRawBytes()
}

export function blindSignaturesUnpack(publicKey, randomScalar, blindSignature) {
	const blindSignaturePoint = bls12_381.G2.ProjectivePoint.fromAffine(
		bls12_381.G2.CURVE.fromBytes(blindSignature)
	)

	const publicKeyPoint = bls12_381.G2.ProjectivePoint.fromAffine(
		bls12_381.G2.CURVE.fromBytes(publicKey)
	)

	const signaturePoint = blindSignaturePoint.subtract(
		publicKeyPoint.multiply(randomScalar)
	)

	return signaturePoint.toRawBytes()
}

// Ring Signatures (on BN254)
// Main reference: https://web.getmonero.org/library/ 

import { bn254 } from '@noble/curves/bn254'
import { sha512 } from '@noble/hashes/sha512'

import * as modular from '@noble/curves/abstract/modular'
import { bytesToNumberBE } from '@noble/curves/abstract/utils'

let ringField = modular.Field(bn254.CURVE.n)

function generateHash(publicKeys, message, point) {
	// Normalize point from Projective coordinates to Affine coordinates
	point = bn254.ProjectivePoint.fromAffine(point.toAffine())

	let hasher = sha512.create()

	publicKeys.map(publicKey => hasher.update(publicKey))

	let bytes = hasher.update(message)
		.update(point.toRawBytes())
		.digest()

	return bytesToNumberBE(modular.mapHashToField(bytes, ringField.ORDER))
}

export function signRing(signerIndex, privateKey, publicKeys, message) {
	// Place to store all c_x's
	let c = new Array(publicKeys.length).fill(0n)

	// Place to store all s_x's
	let s = new Array(publicKeys.length).fill(0n)
	    
	// Initialize s_x's
	for(let curr = 0; curr < publicKeys.length; curr++) {
		s[curr] = getRandomElement(ringField)
	}
	    
	// Calculate c_{i + 1}
	let curr = signerIndex
	let next = (signerIndex + 1) % publicKeys.length
	    
	let k = getRandomElement(ringField)
	    
	let hashedPoint =  bn254.ProjectivePoint.BASE.multiply(k)
	    
	c[next] = generateHash(publicKeys, message, hashedPoint)
	    
	// Calculate c_j != c_i
	for(var offset = 0; offset < publicKeys.length - 1; offset++) {
		let curr = (signerIndex + 1 + offset) % publicKeys.length
		let next = (signerIndex + 1 + offset + 1) % publicKeys.length
	
		let pkCurr = bn254.ProjectivePoint.fromHex(publicKeys[curr])
	
		let hashedPoint1 =  bn254.ProjectivePoint.BASE.multiply(s[curr])
		let hashedPoint2 = pkCurr.multiply(c[curr])
	
		let hashedPoint = hashedPoint1.add(hashedPoint2)
	
		c[next] = generateHash(publicKeys, message, hashedPoint)
	}
	
	// Redefine privateKey to be a scalar (not a byte sequence)
	privateKey = bn254.utils.normPrivateKeyToScalar(privateKey)

	s[curr] = ringField.sub(k , ringField.mul(privateKey, c[curr]))
	
	return {
		c_0: c[0],
		s
	}
}

export function verifyRing(publicKeys, message, ringSignature) {
	// Place to store all c_x's
	let c = new Array(publicKeys.length).fill(0n)

	// Initialize the first c_x
	c[0] = ringSignature.c_0

	for (var offset = 0; offset < publicKeys.length; offset++) {
		let curr = offset % publicKeys.length
		let next = (offset + 1) % publicKeys.length

		let pkCurr = bn254.ProjectivePoint.fromHex(publicKeys[curr])

		let hashedPoint1 = bn254.ProjectivePoint.BASE.multiply(ringSignature.s[curr])
		let hashedPoint2 = pkCurr.multiply(c[curr])

		let hashedPoint = hashedPoint1.add(hashedPoint2)

		c[next] = generateHash(publicKeys, message, hashedPoint)
	}

	return (c[0] == ringSignature.c_0)
}

// Own BLS implementation
// Not exported

function signBLS(message, privateKey) {
	const encodedMessage = new TextEncoder().encode(message)

	const hashedPoint = bls12_381.G2.hashToCurve(encodedMessage)
	hashedPoint.assertValidity()

	const signature = hashedPoint.multiply(
		bls12_381.G2.normPrivateKeyToScalar(privateKey)
	).toRawBytes()

	return signature
}

function verifyBLS(signature, message, publicKey) {
	// Generator of G1
	const G = bls12_381.G1.ProjectivePoint.BASE
	// Signature
	const x_Hm = bls12_381.G2.ProjectivePoint.fromAffine(
		bls12_381.G2.CURVE.fromBytes(signature)
	)

	// Public key
	const G_x = bls12_381.G1.ProjectivePoint.fromAffine(
		bls12_381.G1.CURVE.fromBytes(publicKey)
	)
	// MessageHash
	const encodedMessage = new TextEncoder().encode(message)
	const Hm = bls12_381.G2.hashToCurve(encodedMessage)
	Hm.assertValidity()

	// Naive, but pedagogical
	const pairingA = bls12_381.pairing(G, x_Hm)
	const pairingB = bls12_381.pairing(G_x, Hm)

	return ( bls12_381.fields.Fp12.eql(pairingA, pairingB) )
}