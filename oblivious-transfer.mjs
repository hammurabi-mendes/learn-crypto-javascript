import { ed25519 } from '@noble/curves/ed25519'

import { deriveKey2 } from './kdf.mjs'

import { decryptAuthenticated, encryptAuthenticated } from './symmetric.mjs'

export function demoObliviousTransfer(choice) {
	let privateKeyA = ed25519.utils.randomPrivateKey()
	let publicKeyA = ed25519.getPublicKey(privateKeyA)

	let privateKeyB = ed25519.utils.randomPrivateKey()
	let publicKeyB = ed25519.getPublicKey(privateKeyB)

	privateKeyA = ed25519.utils.getExtendedPublicKey(privateKeyA).scalar
	privateKeyB = ed25519.utils.getExtendedPublicKey(privateKeyB).scalar

	publicKeyA = ed25519.ExtendedPoint.fromHex(publicKeyA)
	publicKeyB = ed25519.ExtendedPoint.fromHex(publicKeyB)

	const choicePublicKeyB = 
		(choice == 0) ? publicKeyB : publicKeyA.add(publicKeyB)
	
	// Includes a subgroup check for the given point
	// https://eprint.iacr.org/2021/1130
	publicKeyA.assertValidity()
	choicePublicKeyB.assertValidity()

	const keyPointA1 = choicePublicKeyB.multiply(privateKeyA)
	const keyPointA2 = choicePublicKeyB.subtract(publicKeyA).multiply(privateKeyA)

	const keyPointB = publicKeyA.multiply(privateKeyB)

	const keyA1 = deriveKey2(keyPointA1.toRawBytes())
	const keyA2 = deriveKey2(keyPointA2.toRawBytes())

	const keyB = deriveKey2(keyPointB.toRawBytes())

	const messages = [
		"a",
		"b"
	]

	const encryptedPackages = [
		encryptAuthenticated(keyA1, messages[0]),
		encryptAuthenticated(keyA2, messages[1])
	]

	const plaintext = decryptAuthenticated(keyB, encryptedPackages[choice])

	console.log("OT choice checks:", plaintext == messages[choice])

	try {
		const plaintext = decryptAuthenticated(keyB, encryptedPackages[1 - choice])

		console.log("OT non-choice checks:", plaintext == messages[1 - choice])
	}
	catch(error) {
		console.log("OT non-choice generates authentication error")
	}
}

export function getReceiverPublicKeyOT(publicKeyA, publicKeyB, choice) {
	publicKeyA = ed25519.ExtendedPoint.fromHex(publicKeyA)
	publicKeyB = ed25519.ExtendedPoint.fromHex(publicKeyB)

	const choicePublicKeyB = 
		(choice == 0) ? publicKeyB : publicKeyA.add(publicKeyB)
	
	return choicePublicKeyB.toRawBytes()
}

export function getSenderSharedSecretsOT(choicePublicKeyB, publicKeyA, privateKeyA) {
	choicePublicKeyB = ed25519.ExtendedPoint.fromHex(choicePublicKeyB)
	publicKeyA = ed25519.ExtendedPoint.fromHex(publicKeyA)

	privateKeyA = ed25519.utils.getExtendedPublicKey(privateKeyA).scalar

	const keyPointA1 = choicePublicKeyB.multiply(privateKeyA)
	const keyPointA2 = choicePublicKeyB.subtract(publicKeyA).multiply(privateKeyA)

	const keyA1 = deriveKey2(keyPointA1.toRawBytes())
	const keyA2 = deriveKey2(keyPointA2.toRawBytes())

	return { keySender1: keyA1, keySender2: keyA2 }

}

export function getReceiverSharedSecretOT(publicKeyA, privateKeyB) {
	publicKeyA = ed25519.ExtendedPoint.fromHex(publicKeyA)

	privateKeyB = ed25519.utils.getExtendedPublicKey(privateKeyB).scalar

	const keyPointB = publicKeyA.multiply(privateKeyB)

	const keyB = deriveKey2(keyPointB.toRawBytes())

	return { keyReceiver: keyB }
}