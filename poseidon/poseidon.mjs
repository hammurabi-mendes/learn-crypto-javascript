import { bn254 } from '@noble/curves/bn254'
import { poseidon } from '@noble/curves/abstract/poseidon'

import * as modular from '@noble/curves/abstract/modular'

import poseidonConstants from './poseidon_constants.json' assert { type: "json" }

export function getPoseidon(nInputs = 2, nOutputs = 1) {
	let t = nInputs + 1

	let roundConstants = poseidonConstants["C"][t - 2]
	let mds = poseidonConstants["M"][t - 2]

	let roundsFull = 8
	let roundsPartial = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68][t - 2]

	let sboxPower = 5

	let roundConstantsT = []

	for (let i = 0; i < roundConstants.length; i += t) {
		let inner = []

		for (let j = 0; j < t; j++) {
			inner.push(BigInt(roundConstants[i + j]))
		}

		roundConstantsT.push(inner)
	}

	let mdsT = mds.map(a => a.map(b => BigInt(b)))

	let options = {
		// Fp: modular.Field(BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617")),
		Fp: modular.Field(bn254.CURVE.n),
		t,
		roundsFull,
		roundsPartial,
		sboxPower,
		mds: mdsT,
		roundConstants: roundConstantsT
	}

	if(nOutputs == 1) {
		return (inputs) => {
			inputs.unshift(0n)
			return poseidon(options)(inputs)[0]
		}
	}
	else {
		return (inputs) => {
			inputs.unshift(0n)
			return poseidon(options)(inputs).slice(0, nOutputs)
		}
	}
}

// For comparison with circomlibjs

// import { getCurveFromName } from "ffjavascript"
// import { buildPoseidon } from 'circomlibjs'

// const bn128 = await getCurveFromName("bn128", true)
// const bls = await getCurveFromName("bls12-381", true)

// let ffPoseidon = await buildPoseidon()
// let poseidonFF = (a, b) => {
// 	// return ffPoseidon.F.toObject(ffPoseidon([a, b]))
// 	return ffPoseidon([a, b], 0n, 2).map(x => ffPoseidon.F.toObject(x))
// }

// console.log(poseidonFF(1n, 2n))