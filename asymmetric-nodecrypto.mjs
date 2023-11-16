// Documentation in https://nodejs.org/api/crypto.htm
import * as crypto from 'crypto'

// Generate public private keys
export function getPublicPrivate() {
	// DSA: Digital Signature Algorithm
	// const { privateKey, publicKey } = crypto.generateKeyPairSync('dsa')

	// Edwards-Curve Digital Signature Algorithm (EdDSA)
	//  - A variant of Schnorr signatures over Twisted Edwards curves.
	//  - ed25519 is EdDSA over the Curve 25519
	// const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519')

	// EC-DSA: DSA over an elliptic curve
	//  - Default uses curve P-256 (NIST) (= secp256r1)
	//  - Can use the secp256k1 (a non-NIST curve, anonymously contributed)
	const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { 
		namedCurve: "secp256k1"
		// namedCurve: "P-256" // (i.e. secp256r1)
	})

	return { privateKey, publicKey }
}


export function sign(privateKey, message) {
	// First parameter is the algorithm, which is deducted from the privateKey metadata
	const signature = crypto.sign(null, Buffer.from(message), privateKey)
	
	return signature.toString('hex')
}

export function verify(publicKey, message, signatureString) {
	let signature = Buffer.from(signatureString, 'hex')

	// First parameter is the algorithm, which is deducted from the publicKey metadata
	const result = crypto.verify(null, Buffer.from(message), publicKey, signature)

	return result
}