import * as modular from '@noble/curves/abstract/modular'
import * as utils from '@noble/curves/abstract/utils'

import * as crypto from 'crypto'

export function getRandomBytes(amount) {
	return crypto.randomBytes(amount)
}

export function mapHashToElement(hash, field) {
	return utils.bytesToNumberBE(
		modular.mapHashToField(
			hash,
			field.ORDER
		)
	)
}

export function getRandomElement(field) {
	return utils.bytesToNumberBE(
		modular.mapHashToField(
			getRandomBytes(field.BYTES * 2),
			field.ORDER
		)
	)
}