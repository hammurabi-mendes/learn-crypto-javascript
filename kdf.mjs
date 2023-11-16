// Documentation in https://nodejs.org/api/crypto.htm
import * as crypto from 'crypto'

/////////////////////////
// Node-Crypto library //
/////////////////////////

export function deriveKey(userKey, salt = 'csc-354-cji32-rjwiro', size = 32) {
	// Uses a key derivation algorithm to transform a user-provided key
	// into a key with the same size the algorithm requires
	//
	// Available algorithms:
	//   scrypt, pbkdf2

	// let key = crypto.scryptSync(userKey, salt, size)
	let key = crypto.pbkdf2Sync(userKey, salt, 131072, size, 'sha256')

	return key
}

///////////////////
// Noble library //
///////////////////

import { pbkdf2 } from '@noble/hashes/pbkdf2'
import { sha256 } from '@noble/hashes/sha256'

export function deriveKey2(userKey, salt = 'csc-354-cji32-rjwiro', size = 32) {
	let key = pbkdf2(sha256, userKey, salt, { c: 131072, dkLen: size })

	return key
}