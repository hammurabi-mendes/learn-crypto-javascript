import fs from 'fs'
import * as crypto from 'crypto'
import { ed25519 } from '@noble/curves/ed25519'
import { secp256k1 } from '@noble/curves/secp256k1'
import { bytesToNumberLE, bytesToNumberBE } from '@noble/curves/abstract/utils'

export function readPrivate(filename, passphrase) {
	const fileContents = fs.readFileSync(filename)

	return crypto.createPrivateKey({ key: fileContents, passphrase })
}

export function readPrivateNobleCurves(filename, passphrase) {
	const privateKey = readPrivate(filename, passphrase)

	const privateKeyJWK = privateKey.export({ type: 'pkcs8', format: 'jwk' })
	const privateKeyBuffer = Buffer.from(privateKeyJWK.d, 'base64')

	return Uint8Array.from(privateKeyBuffer)
}

export function readCertificate(filename) {
	const fileContents = fs.readFileSync(filename)

	return new crypto.X509Certificate(fileContents)
}

export function getPublicKey(certificate) {
	return certificate.publicKey
}

export function getPublicKeyNobleEd25519(certificate) {
	const publicKeyJWK = certificate.publicKey.export({ type: 'pkcs8', format: 'jwk' })

	const xBuffer = Buffer.from(publicKeyJWK.x, 'base64')

	return module.ExtendedPoint.fromHex(xBuffer.toString('hex')).toRawBytes()
}

export function getPublicKeyNobleSecp256k1(certificate) {
	const publicKeyJWK = certificate.publicKey.export({ type: 'pkcs8', format: 'jwk' })

	const xBuffer = Buffer.from(publicKeyJWK.x, 'base64')
	const yBuffer = Buffer.from(publicKeyJWK.y, 'base64')

	const x = bytesToNumberBE(xBuffer)
	const y = bytesToNumberBE(yBuffer)

	return module.ProjectivePoint.fromAffine({ x, y }).toRawBytes()
	// ALTERNATIVE: return module.ProjectivePoint.fromHex('04' + xBuffer.toString('hex') + yBuffer.toString('hex')).toRawBytes()
}

let module = ed25519
// let module = secp256k1

export function demoCertificates() {
	let privateKey
	let privateKey2
	let certificate

	if (module == ed25519) {
		privateKey = readPrivate("openssl/serv_privkey.pem", "123456")
		certificate = readCertificate("openssl/serv_certificate.pem")

		privateKey2 = readPrivateNobleCurves("openssl/serv_privkey.pem", "123456")
	}

	if (module == secp256k1) {
		privateKey = readPrivate("openssl/serv2_privkey.pem", "123456")
		certificate = readCertificate("openssl/serv2_certificate.pem")

		privateKey2 = readPrivateNobleCurves("openssl/serv2_privkey.pem", "123456")
	}

	// Node Crypto

	let signature = crypto.sign(null, Buffer.from("test"), privateKey)
	const verificationResult11 = crypto.verify(null, Buffer.from("test"), certificate.publicKey, signature)

	console.log("Verification node-node: ", verificationResult11)

	// Noble

	const encodedMessage = new TextEncoder().encode('test')

	const publicKey2 = module.getPublicKey(privateKey2)

	let signature2 = module.sign(encodedMessage, privateKey2, { prehash: true })
	let verificationResult22 = module.verify(signature2, encodedMessage, publicKey2, { prehash: true })
	console.log("Verification noble-noble: ", verificationResult22)

	// Combinations

	if (module == ed25519) {
		let verificationResult21 = crypto.verify(null, Buffer.from("test"), certificate.publicKey, signature2)
		console.log("Verification noble-node (Ed25519): ", verificationResult21)

		let verificationResult2CNoble = module.verify(signature2, encodedMessage, getPublicKeyNobleEd25519(certificate))
		console.log("Verification noble-certificate_noble (Ed25519): ", verificationResult2CNoble)

		let verificationResult2CNodeCrypto = crypto.verify(null, Buffer.from("test"), certificate.publicKey, signature2)
		console.log("Verification noble-certificate_nodecrypto (Ed25519): ", verificationResult2CNodeCrypto)

		let verificationResult12 = module.verify(signature, encodedMessage, publicKey2)
		console.log("Verification node-noble (secp256k1): ", verificationResult12)
	}

	if (module == secp256k1) {
		let signature2 = module.sign(encodedMessage, privateKey2, { prehash: true })
		let verificationResult22 = module.verify(signature2, encodedMessage, publicKey2, { prehash: true })
		console.log("Verification noble-noble: ", verificationResult22)

		let signature2DER = signature2.toDERRawBytes()
		let verificationResult21 = crypto.verify(null, Buffer.from("test"), certificate.publicKey, signature2DER)
		console.log("Verification noble-node (secp256k1): ", verificationResult21)

		let verificationResult2CNoble = module.verify(signature2, encodedMessage, getPublicKeyNobleSecp256k1(certificate), { prehash: true })
		console.log("Verification noble-certificate_noble (secp256k1): ", verificationResult2CNoble)

		let verificationResult2CNodeCrypto = crypto.verify(null, Buffer.from("test"), certificate.publicKey, signature2.toDERRawBytes())
		console.log("Verification noble-certificate_nodecrypto (secp256k1): ", verificationResult2CNodeCrypto)

		let signaturePoint = module.Signature.fromDER(signature)
		let verificationResult12 = module.verify(signaturePoint, encodedMessage, publicKey2, { prehash: true })
		console.log("Verification node-noble (secp256k1): ", verificationResult12)
	}
}