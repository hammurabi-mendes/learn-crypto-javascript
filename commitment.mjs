import { bls12_381 } from '@noble/curves/bls12-381'
import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha256'
import { sha512 } from '@noble/hashes/sha512'


import { getRandomElement, mapHashToElement } from './random.mjs'

// The most used key or password in the world
const key = '123456'

// This one, not so much
const message = 'I got tickets to the show'

// HMAC

export function demoHmac() {
	// A hash based commitment (not the formal HMAC)
	const poor_hmac_sha256 = sha256(key + message)

	// HMAC formally defined
	const hmac_sha256 = hmac(sha256, key, message)

	console.log("HMACs:", poor_hmac_sha256.toString('hex'), hmac_sha256.toString('hex'))
}

// Pedersen

export let field = bls12_381.fields.Fr

const generator1 = getRandomElement(field)
const generator2 = getRandomElement(field)

export function calculatePedersen(messages, r) {
	if (messages.length == 0) {
		throw new Error("The messages array is empty.")
	}

	const hashMessages = messages.map(sha512)

	// Essential that this is not modular addition (because it's in the exponent)
	const m = hashMessages.reduce(
		(acc, cur) => acc + mapHashToElement(cur, field),
		field.ZERO
	)

	if (r == undefined) {
		r = getRandomElement(field)
	}

	const commitment = 
		field.mul(
			field.pow(generator1, m),
			field.pow(generator2, r)
		)
	
	return { commitment, m, r }
}

export function verifyPedersen(commitment, r, messages) {
	if (messages.length == 0) {
		throw new Error("The messages array is empty.")
	}

	const hashMessages = messages.map(sha512)

	// Essential that this is not modular addition (because it's in the exponent)
	const m = hashMessages.reduce(
		(acc, cur) => acc + mapHashToElement(cur, field),
		field.ZERO
	)

	const calculated = 
		field.mul(
			field.pow(generator1, m),
			field.pow(generator2, r)
		)

	return field.eql(commitment, calculated)
}