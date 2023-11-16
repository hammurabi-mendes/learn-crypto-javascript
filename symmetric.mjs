// Documentation in https://nodejs.org/api/crypto.htm
import * as crypto from 'crypto'

import { deriveKey } from './kdf.mjs'
import { getRandomBytes } from './random.mjs'

// Use "openssl list -cipher-algorithms" to see symmetric algorithms available

export function encrypt(userKey, message) {
	// Make an initialization vector of 16B
	// (256b -- same size as required by the algorithm)
	let iv = getRandomBytes(16)

	let key = deriveKey(userKey)

	// Algorithm, key, initialization vector
	const symmetricCipher = crypto.createCipheriv('aes-256-cbc', key, iv)

	// If you input strings, you have to provide input and output encodings otherwise they're optional (default to Buffer)

	// Create the cypher object once, update multiple times before calling final()
	let cyphertext = symmetricCipher.update(message, 'utf8', 'hex')
	// Final returns leftover encrypted data, so make sure to use +=
	cyphertext += symmetricCipher.final('hex')

	let ivString = iv.toString('hex')
	return { cyphertext, ivString }
}

export function decrypt(userKey, encryptedPackage) {
	let { cyphertext, ivString } = encryptedPackage

	let iv = Buffer.from(ivString, 'hex')

	let key = deriveKey(userKey)

	// Algorithm, key, initialization vector
	const symmetricDecipher = crypto.createDecipheriv('aes-256-cbc', key, iv)

	// If you input strings, you have to provide input and output encodings otherwise they're optional (default to Buffer)

	// Create the decypher object once, update multiple times before calling final()
	let plaintext = symmetricDecipher.update(cyphertext, 'hex', 'utf8')
	// Final returns leftover encrypted data, so make sure to use +=
	plaintext += symmetricDecipher.final('utf8')

	return plaintext
}

//////////////////////////////
// Authenticated Encryption //
//////////////////////////////

export function encryptAuthenticated(keyE, message) {
	// Make an initialization vector of 16B
	// (256b -- same size as required by the algorithm)
	let iv = getRandomBytes(16)

	// Algorithm, key, initialization vector
	const symmetricCipher = crypto.createCipheriv('aes-256-gcm', keyE, iv)

	// If you input strings, you have to provide input and output encodings otherwise they're optional (default to Buffer)

	// Create the cypher object once, update multiple times before calling final()
	let cyphertext = symmetricCipher.update(message, 'utf8', 'hex')
	// Final returns leftover encrypted data, so make sure to use +=
	cyphertext += symmetricCipher.final('hex')

	// Get the authentication tag
	const tag = symmetricCipher.getAuthTag()

	let ivString = iv.toString('hex')
	return { cyphertext, tag, ivString }
}

export function decryptAuthenticated(keyE, encryptedPackage) {
	let { cyphertext, tag, ivString } = encryptedPackage

	let iv = Buffer.from(ivString, 'hex')

	// Algorithm, key, initialization vector
	const symmetricDecipher = crypto.createDecipheriv('aes-256-gcm', keyE, iv)

	// Set the authentication tag (in the hope it matches the calculated output)
	symmetricDecipher.setAuthTag(tag)

	// If you input strings, you have to provide input and output encodings otherwise they're optional (default to Buffer)

	// Create the decypher object once, update multiple times before calling final()
	let plaintext = symmetricDecipher.update(cyphertext, 'hex', 'utf8')
	// Final returns leftover encrypted data, so make sure to use +=
	plaintext += symmetricDecipher.final('utf8')

	return plaintext
}