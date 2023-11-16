import { ed25519, x25519 } from '@noble/curves/ed25519'
import { edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519'

export function demoDiffieHellman() {
	// First we generate keypairs in Curve 25519 then we convert to x25519
	
	const privateKey1 = edwardsToMontgomeryPriv(ed25519.utils.randomPrivateKey())
	const publicKey1 = x25519.getPublicKey(privateKey1)

	const privateKey2 = edwardsToMontgomeryPriv(ed25519.utils.randomPrivateKey())
	const publicKey2 = x25519.getPublicKey(privateKey2)

	const key1 = x25519.getSharedSecret(privateKey1, publicKey2)
	const key2 = x25519.getSharedSecret(privateKey2, publicKey1)

	console.log("DH Keys identical:",
		key1.length == key2.length
		&&
		key1.every((val, pos) => (key2[pos] == val))
	)
}