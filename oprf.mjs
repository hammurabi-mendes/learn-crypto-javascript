import { bls12_381 } from '@noble/curves/bls12-381'

import * as modular from '@noble/curves/abstract/modular'

export function feedAndBlind(encodedMessage) {
	// Includes cofactor clearing; see https://hackmd.io/@benjaminion/bls12-381#Cofactor and https://eprint.iacr.org/2015/247
	const hashedPoint = bls12_381.G2.hashToCurve(encodedMessage)
	const randomScalar = bls12_381.G1.normPrivateKeyToScalar(
		bls12_381.utils.randomPrivateKey()
	)

	const blindPoint = hashedPoint.multiply(randomScalar)

	return { randomScalar, blindPoint }
}

export function hashBlindPoint(blindPoint, privateKey) {
	// Includes a subgroup check for the given point
	// https://eprint.iacr.org/2021/1130
	blindPoint.assertValidity()

	return blindPoint.multiply(bls12_381.G1.normPrivateKeyToScalar(privateKey))
}

export function unblind(hashedBlindPoint, randomScalar) {
	return hashedBlindPoint.multiply(bls12_381.G1.normPrivateKeyToScalar(
		modular.invert(randomScalar, bls12_381.fields.Fr.ORDER)
	))
}