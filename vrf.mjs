import { bls12_381 } from "@noble/curves/bls12-381"
import { sha3_256, sha3_512 } from '@noble/hashes/sha3'

import { mapHashToElement } from "./random.mjs"

//////////////////////////////////////////////////
// Verifiable Random Functions (construction 1) //
//////////////////////////////////////////////////

// Reference:  https://docs.harmony.one/home/developers/harmony-specifics/tools/harmony-vrf

export function generateVR(privateKey, message) {
	const encodedMessage = new TextEncoder().encode(message)

	const signature = bls12_381.sign(encodedMessage, privateKey)

	const random = sha3_256(signature)

	return { random, signature }
}

export function checkVR(random, signature, message, publicKey) {
	// Checks if the random is a hash of the signature

	const calculatedRandom = sha3_256(signature)

	let resultRandom = (calculatedRandom !== random)

	// Checks if the signature signs the message and verifies with the public key

	const encodedMessage = new TextEncoder().encode(message)

	let resultSignature = bls12_381.verify(signature, encodedMessage, publicKey)

	return (resultRandom && resultSignature)
}

//////////////////////////////////////////////////
// Verifiable Random Functions (construction 2) //
//////////////////////////////////////////////////

// Reference: https://eprint.iacr.org/2017/099.pdf 

export let field = bls12_381.fields.Fr

function hash3(points) {
	let normalizedPoints = bls12_381.G1.ProjectivePoint.normalizeZ(points)
	let normalizedPointArrays = normalizedPoints.map((p) => p.toRawBytes())

	let hash = sha3_512(concatenateArrays(normalizedPointArrays))

	return mapHashToElement(hash, field)
}

function concatenateArrays(arrays) {
	let totalLength = arrays.reduce((acc, cur) => acc + cur.length, 0)

	let result = new Uint8Array(totalLength)

	let position = 0

	for(let i = 0; i < arrays.length; i++) {
		result.set(arrays[i], position)
		position += arrays[i].length
	}

	return result
}

export function generateIntermediateAndProof(privateKey, encodedMessage) {
	const G = bls12_381.G1.ProjectivePoint.BASE
	const H = bls12_381.G1.hashToCurve(encodedMessage) // H_1

	const x = bls12_381.G1.normPrivateKeyToScalar(privateKey)

	const xG = G.multiply(x)
	const xH = H.multiply(x)

	const k = bls12_381.G1.normPrivateKeyToScalar(
		bls12_381.utils.randomPrivateKey()
	)

	const kG = G.multiply(k)
	const kH = H.multiply(k)

	// H_3: $\ell$-bit hash function (we aim for $\ell$ bits of security)
	const c = hash3([G, H, xG, xH, kG, kH])

	const s = field.sub(k, field.mul(c, x))

	return { intermediate: xH, proof: { c, s } }
}

export function generateFinal(intermediate) {
	const cofactor = bls12_381.G1.CURVE.h

	// H_2: $2\ell$-bit hash function (we aim for $\ell$ bits of security)
	const final = sha3_512(intermediate.multiply(cofactor).toRawBytes()) // 512 bits

	return final
}

export function generateFinalAndVerify(encodedMessage, publicKey, intermediate, proof) {
	const final = generateFinal(intermediate)

	const G = bls12_381.G1.ProjectivePoint.BASE
	const H = bls12_381.G1.hashToCurve(encodedMessage)

	const xG = bls12_381.G1.ProjectivePoint.fromAffine(
		bls12_381.G1.CURVE.fromBytes(publicKey)
	)
	const sG = G.multiply(proof.s)

	const xH = intermediate
	const sH = H.multiply(proof.s)

	const kG = xG
		.multiply(proof.c)
		.add(sG)

	const kH = xH
		.multiply(proof.c)
		.add(sH)

	// H_3: $\ell$-bit hash function (we aim for $\ell$ bits of security)
	const c = hash3([G, H, xG, xH, kG, kH])

	return { final, valid: (proof.c == c) }
}