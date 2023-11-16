// Documentation in https://nodejs.org/api/crypto.htm
import * as crypto from 'crypto'

// const alice = crypto.createECDH('secp256k1')
// const aliceKey = alice.generateKeys()

// // Generate Bob's keys...
// const bob = crypto.createECDH('secp256k1')
// const bobKey = bob.generateKeys()

// // Exchange and generate the secret...
// const aliceSecret = alice.computeSecret(bobKey)
// const bobSecret = bob.computeSecret(aliceKey)

// console.log("ECDH Keys identical:", aliceSecret.toString('hex') == bobSecret.toString('hex'))

// // Talk about man-in-the-middle (because there's no authentication here)

export function generatePublicPrivateDH() {
	// // Using x25519
	// // - 25519 isn't a curve, it's an Elliptic-Curve Diffie-Hellman (ECDH)
	// //   using the x coordinate of Curve25519

	// return crypto.generateKeyPairSync('x25519')

	// Using secp256k1
	return crypto.generateKeyPairSync('ec', { 
		// namedCurve: "secp256k1"
		namedCurve: "P-256" // (i.e. secp256r1)
	})
}

export function makeKey(myPrivate, otherPublic) {
	let key = crypto.diffieHellman({
		    publicKey : otherPublic,
		    privateKey: myPrivate
		})
	
	return key.toString('hex')
}

// // You can also export the keys into a certificate and import with crypto.createPublicKey()
// const alicePubExport = aliceKeyPair.publicKey.export({ type: 'spki', format: 'pem' })
// const bobPubExport = bobKeyPair.publicKey.export({ type: 'spki', format: 'pem' })

// const bobKeyAgree = crypto.diffieHellman({
//     publicKey : aliceKeyPair.publicKey,
//     privateKey: bobKeyPair.privateKey
// })

// const aliceKeyAgree = crypto.diffieHellman({
//     publicKey : bobKeyPair.publicKey,
//     privateKey: aliceKeyPair.privateKey
// })

//  console.log("ECDH (x25519) Keys identical:", bobKeyAgree.toString('hex') == aliceKeyAgree.toString('hex'))