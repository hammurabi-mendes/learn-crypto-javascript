import { bls12_381 } from '@noble/curves/bls12-381'

const defaultField = bls12_381.fields.Fr

export function demoPolynomials() {
	let resultE = evaluate([10n, 100n, 1000n], bls12_381.fields.Fr.ONE + bls12_381.fields.Fr.ONE, bls12_381.fields.Fr)

	let resultMP = multiply([10n, 20n], [300n, 500n, 700n], bls12_381.fields.Fr)
	let resultME = multiplyScalar([10n, 20n], 33n, bls12_381.fields.Fr)

	let resultD1 = divide([-4n, 0n, -2n, 1n], [-3n, 1n], bls12_381.fields.Fr)
	console.log(resultD1)

	let resultD2 = divide([-42n, 0n, -12n, 1n], [1n, -2n, 1n], bls12_381.fields.Fr)
	console.log(resultD2)

	let resultMD = add(
		multiply(resultD2.quotient, [1n, -2n, 1n], bls12_381.fields.Fr),
		resultD2.rest,
		bls12_381.fields.Fr
	)
	console.log(resultMD)

	let resultI = lagrange([2n, 5n], [3n, 4n], bls12_381.fields.Fr)

	let output1 = evaluate(resultI, 2n, bls12_381.fields.Fr)
	console.log(output1)

	let output2 = evaluate(resultI, 5n, bls12_381.fields.Fr)
	console.log(output2)
}

export function add(coefficients1, coefficients2, field = defaultField) {
	if (coefficients1.length == 0 || coefficients2.length == 0) {
		throw new Error("Coefficients should not be empty")
	}

	var maxLength = Math.max(coefficients1.length, coefficients2.length)

	let result = []

	for (var i = 0; i < maxLength; i++) {
		result.push(field.add(coefficients1[i] || field.ZERO, coefficients2[i] || field.ZERO))
	}

	return result
}

export function sub(coefficients1, coefficients2, field = defaultField) {
	if (coefficients1.length == 0 || coefficients2.length == 0) {
		throw new Error("Coefficients should not be empty")
	}

	var maxLength = Math.max(coefficients1.length, coefficients2.length)

	let result = []

	for (var i = 0; i < maxLength; i++) {
		result.push(field.sub(coefficients1[i] || field.ZERO, coefficients2[i] || field.ZERO))
	}

	return result
}

export function multiply(coefficients1, coefficients2, field = defaultField) {
	if (coefficients1.length == 0 || coefficients2.length == 0) {
		throw new Error("Coefficients should not be empty")
	}

	let result = [field.ZERO]

	let copyCoefficient2 = Array.from(coefficients2)

	for (let i = 0; i < coefficients1.length; i++) {
		if(i > 0) {
			copyCoefficient2.unshift(0n)
		}
		result = add(
			result,
			multiplyScalar(copyCoefficient2, coefficients1[i], field),
			field
		)
	}

	return result
}

export function normalize(coefficients, field = defaultField) {
	while (coefficients.length > 1 && coefficients[coefficients.length - 1] == field.ZERO) {
		coefficients.pop()
	}
}

export function divide(coefficients1, coefficients2, field = defaultField) {
	if (coefficients1.length == 0 || coefficients2.length == 0) {
		throw new Error("Coefficients should not be empty")
	}

	if (coefficients1.length < coefficients2.length) {
		return { quotient: [field.ZERO], rest: Array.from(coefficients1) }
	}

	let numerator = Array.from(coefficients1)
	let denominator = Array.from(coefficients2)

	normalize(numerator, field)
	normalize(denominator, field)
    
	const shiftLength = (numerator.length - denominator.length)

	for(let i = 0; i < shiftLength; i++) {
		denominator.unshift(field.ZERO)
	}
    
	let result = []
	let divisor = denominator[denominator.length - 1]

	for(let i = 0; i <= shiftLength; i++) {
		let factor = field.div(
			numerator[numerator.length - 1],
			divisor
		)
		result.unshift(factor)

		if (factor != 0) {
			numerator = sub(
				numerator,
				multiplyScalar(denominator, factor, field),
				field
			)
		}

		// Remove last one
		numerator.pop()
		// Remove first one
		denominator.shift()
	}
    
	normalize(numerator, field)

	return { quotient: result, rest: numerator }
}

export function multiplyScalar(coefficients, scalar, field = defaultField) {
	if (coefficients.length == 0) {
		throw new Error("Coefficients should not be empty")
	}

	return coefficients.map(coefficient => field.mul(coefficient, scalar))
}

export function evaluate(coefficients, point, field = defaultField) {
	if (coefficients.length == 0) {
		throw new Error("Coefficients should not be empty")
	}

	let result = field.ZERO

	for (let i = coefficients.length - 1; i >= 1; i--) {
		result = field.mul(result, point)
		result = field.add(result, field.mul(point, coefficients[i]))
	}

	result = field.add(result, coefficients[0])

	return result
}

export function lagrange(xs, ys, field = defaultField) {
	if (xs.length == 0 || ys.length == 0) {
		throw new Error("Point arrays should not be empty")
	}

	if (xs.length != ys.length) {
		throw new Error("Point arrays should have the same length")
	}

	let top = [field.ONE]

	for (let k = 1; k < xs.length; k++) {
		top = multiply(top, [field.neg(xs[k]), field.ONE], field)
	}

	let sum = [field.ZERO]

	for (let j = 0; j < xs.length; j++) {
		// top = (X - x_0)...(X - x_k) [ excluding (X - x_j)]

		// bottom = (x_j - x_0) ... (x_j - x_k) [ excluding (x_j - x_j)]
		let bottom = field.ONE

		for(let k = 0; k < xs.length; k++) {
			if (k != j) {
				bottom = field.mul(bottom, field.sub(xs[j], xs[k]))
			}
		}

		let lj = multiplyScalar(top, field.inv(bottom), field)

		lj = lj.map(coefficient => field.mul(coefficient, ys[j]))

		sum = add(sum, lj, field)

		// Adjust top
		if(j != xs.length - 1) {
			top = divide(top, [field.neg(xs[j + 1]), field.ONE], field).quotient
			top = multiply(top, [field.neg(xs[j]), field.ONE], field)
		}
	}

	return sum
}

export function lagrangeLiteral(xs, ys, field = defaultField) {
	if (xs.length == 0 || ys.length == 0) {
		throw new Error("Point arrays should not be empty")
	}

	if (xs.length != ys.length) {
		throw new Error("Point arrays should have the same length")
	}

	let sum = [field.ZERO]

	for (let j = 0; j < xs.length; j++) {
		// top = (X - x_0)...(X - x_k) [ excluding (X - x_j)]
		let top = [field.ONE]

		for (let k = 0; k < xs.length; k++) {
			if (k != j) {
				top = multiply(top, [field.neg(xs[k]), field.ONE], field)
			}
		}

		// bottom = (x_j - x_0) ... (x_j - x_k) [ excluding (x_j - x_j)]
		let bottom = field.ONE

		for(let k = 0; k < xs.length; k++) {
			if (k != j) {
				bottom = field.mul(bottom, field.sub(xs[j], xs[k]))
			}
		}

		let lj = multiplyScalar(top, field.inv(bottom), field)

		lj = lj.map(coefficient => field.mul(coefficient, ys[j]))

		sum = add(sum, lj, field)
	}

	return sum
}

export function lagrangeProjectivePointsAtZero(xs, ys, field = defaultField, zeroPoint = defaultField.ZERO) {
	if (xs.length == 0 || ys.length == 0) {
		throw new Error("Point arrays should not be empty")
	}

	if (xs.length != ys.length) {
		throw new Error("Point arrays should have the same length")
	}

	let sum = zeroPoint

	for (let j = 0; j < xs.length; j++) {
		// top = (X - x_0)...(X - x_k) [ excluding (X - x_j)]
		let top = field.ONE

		for (let k = 0; k < xs.length; k++) {
			if (k != j) {
				top = field.mul(top, xs[k])
			}
		}

		let bottom = field.ONE

		for(let k = 0; k < xs.length; k++) {
			if (k != j) {
				bottom = field.mul(bottom, field.sub(xs[k], xs[j]))
			}
		}

		let lj = field.mul(top, field.inv(bottom))

		sum = sum.add(ys[j].multiply(lj))
	}

	return sum
}

export function lagrangeProjectivePoints(xs, ys, field = defaultField, zeroPoint = defaultField.ZERO) {
	if (xs.length == 0 || ys.length == 0) {
		throw new Error("Point arrays should not be empty")
	}

	if (xs.length != ys.length) {
		throw new Error("Point arrays should have the same length")
	}

	let sum = [zeroPoint]

	for (let j = 0; j < xs.length; j++) {
		// top = (X - x_0)...(X - x_k) [ excluding (X - x_j)]
		let top = [field.ONE]

		for (let k = 0; k < xs.length; k++) {
			if (k != j) {
				top = multiply(top, [field.neg(xs[k]), field.ONE], field)
			}
		}

		// bottom = (x_j - x_0) ... (x_j - x_k) [ excluding (x_j - x_j)]
		let bottom = field.ONE

		for(let k = 0; k < xs.length; k++) {
			if (k != j) {
				bottom = field.mul(bottom, field.sub(xs[j], xs[k]))
			}
		}

		let lj = multiplyScalar(top, field.inv(bottom), field)

		// Multiply coefficients by point
		lj = lj.map(coefficient => ys[j].multiply(coefficient))

		// Update sum
		var maxLength = Math.max(sum.length, lj.length)

		let result = []
	
		for (var i = 0; i < maxLength; i++) {
			const lhs = sum[i] || zeroPoint
			const rhs = lj[i] || zeroPoint

			result.push(lhs.add(rhs))
		}

		sum = result
	}

	return sum
}