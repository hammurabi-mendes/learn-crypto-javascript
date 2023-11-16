import { bls12_381 } from '@noble/curves/bls12-381'

import * as polynomials from './polynomials.mjs'

import { getRandomElement } from './random.mjs'

const field = bls12_381.fields.Fr

// For now, just find powers of a random secret in the most simple way
// Later I plan to read the snarkJS' ptau files and get the powers from the ceremony there
const secret = getRandomElement(field)
const SRS_LENGTH = 64

let srsG1 = [ bls12_381.G1.ProjectivePoint.BASE ]
let srsG2 = [ bls12_381.G2.ProjectivePoint.BASE ]

for(let i = 1; i < SRS_LENGTH; i++) {
	srsG1.push(srsG1[srsG1.length - 1].multiply(secret))
	srsG2.push(srsG2[srsG2.length - 1].multiply(secret))
}

export function demoPolynomialCommitment() {
	const coefficients = [10n, 20n, 30n, 40n]

	const commitment = commit(coefficients)

	// Single

	const z = 77n
	const y = polynomials.evaluate(coefficients, z, field)

	let proof = prove(coefficients, z)

	let verificationResult = verify(commitment, proof, z, y)
	console.log("KZG single verification:", verificationResult)

	// Multiple

	const zs = [77n, 88n, 99n]
	const ys = zs.map((z) => polynomials.evaluate(coefficients, z, field))

	let proofMultiple = proveMultiple(coefficients, zs)

	let verificationResultMultiple = verifyMultiple(commitment, proofMultiple, zs, ys)
	console.log("KZG multiple verification:", verificationResultMultiple)
}

export function commit(coefficients) {
	let result = bls12_381.G1.ProjectivePoint.ZERO

	for (let i = 0; i < coefficients.length; i++) {
		result = result.add(srsG1[i].multiply(coefficients[i]))
	}

	return result
}

export function prove(coefficients, z) {
	const quotientPolynomial = getQuotientPolynomial(coefficients, z)

	return commit(quotientPolynomial)
}

function getQuotientPolynomial(coefficients, z) {
	const originalPol = coefficients
	const identityPol = [0n, 1n]

	const y = polynomials.evaluate(originalPol, z, field)

	const yPol = [y]
	const zPol = [z]

	return polynomials.divide(
		polynomials.sub(originalPol, yPol, field),
		polynomials.sub(identityPol, zPol, field),
		field
	).quotient
}

export function verify(commitment, proof, z, y) {
	const lhs = bls12_381.pairing(
		proof,
		srsG2[1].subtract(bls12_381.G2.ProjectivePoint.BASE.multiply(z))
	)

	const rhs = bls12_381.pairing(
		commitment.subtract(bls12_381.G1.ProjectivePoint.BASE.multiply(y)),
		bls12_381.G2.ProjectivePoint.BASE
	)

	return bls12_381.fields.Fp12.eql(lhs, rhs)
}

export function proveMultiple(coefficients, zs) {
	const quotientPolynomial = getQuotientPolynomialMultiple(coefficients, zs)

	return commit(quotientPolynomial)
}

function getQuotientPolynomialMultiple(coefficients, zs) {
	const originalPol = coefficients

	const ys = zs.map((z) => polynomials.evaluate(originalPol, z, field))

	const iPol = polynomials.lagrange(
		zs,
		ys,
		field
	)

	let zPol = [1n]
	zs.forEach((z) => {
		zPol = polynomials.multiply(
			zPol,
			[field.neg(z), 1n],
			field
		)
	})

	return polynomials.divide(
		polynomials.sub(originalPol, iPol, field),
		zPol,
		field
	).quotient
}

export function verifyMultiple(commitment, proof, zs, ys) {
	const iPol = polynomials.lagrange(
		zs,
		ys,
		field
	)

	let zPol = [1n]
	zs.forEach((z) => {
		zPol = polynomials.multiply(
			zPol,
			[field.neg(z), 1n],
			field
		)
	})

	let evalZatStimesGen2 = bls12_381.G2.ProjectivePoint.ZERO
	for(let pos = 0; pos < zPol.length; pos++) {
		evalZatStimesGen2 = evalZatStimesGen2.add(srsG2[pos].multiply(zPol[pos]))
	}

	let evalIatStimesGen1 = bls12_381.G1.ProjectivePoint.ZERO
	for(let pos = 0; pos < iPol.length; pos++) {
		evalIatStimesGen1 = evalIatStimesGen1.add(srsG1[pos].multiply(iPol[pos]))
	}

	const lhs = bls12_381.pairing(
		proof,
		evalZatStimesGen2 // srsG2[1].subtract(bls12_381.G2.ProjectivePoint.BASE.multiply(z))
	)

	const rhs = bls12_381.pairing(
		commitment.subtract(evalIatStimesGen1), // commitment.subtract(bls12_381.G1.ProjectivePoint.BASE.multiply(y)),
		bls12_381.G2.ProjectivePoint.BASE
	)

	return bls12_381.fields.Fp12.eql(lhs, rhs)
}