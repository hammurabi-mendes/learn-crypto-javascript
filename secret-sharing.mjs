import { bls12_381 } from '@noble/curves/bls12-381'

import * as polynomials from './polynomials.mjs'

import { getRandomElement } from './random.mjs'

const defaultField = bls12_381.fields.Fr

export function generateShares(secret, numberThreshold, numberShares, field = defaultField) {
	const coefficients = [secret]

	for(let i = 0; i < numberThreshold - 1; i++) {
		coefficients.push(
			getRandomElement(field)
		)
	}

	const result = []

	for(let i = 0; i < numberShares; i++) {
		result.push({
			number: BigInt(i + 1),
			subSecret: polynomials.evaluate(coefficients, BigInt(i + 1), field)
		})
	}

	return result
}

export function reconstructSecret(shares, field = defaultField) {
	const keyCoefficients = polynomials.lagrange(
		shares.map(({ number }) => number),
		shares.map(({ subSecret }) => subSecret),
		field
	)

	return polynomials.evaluate(keyCoefficients, 0n, field)
}