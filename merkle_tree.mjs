export class MerkleTree {
	constructor(bottomLevel, hasher) {
		this.bottomLevel = bottomLevel
		this.hasher = hasher

		// node -> index at level 0
		this.nodeMap = {}

		// [level, index] -> node
		this.positionMap = {}

		// level -> zero at the level
		this.zeroes = []

		this.nextAppendIndex = 0

		let current = 0n

		for(let currentLevel = this.bottomLevel; currentLevel >= 1; currentLevel--) {
			this.zeroes[currentLevel] = current

			current = this.hasher(current, current)
		}

		this.zeroes[0] = current
	}

	append(element, updateInternalState = false) {
		this.insert(this.nextAppendIndex, element, updateInternalState)

		this.nextAppendIndex++
	}

	appendAll(elements, updateInternalState = false) {
		for(let element of elements) {
			this.append(element, updateInternalState)
		}
	}

	insert(bottomIndex, element, updateInternalState = false) {
		if(updateInternalState) {
			this.updateInternalState(bottomIndex)
		}

		this.nodeMap[element] = bottomIndex
		this.positionMap[[this.bottomLevel, bottomIndex]] = element
	}

	remove(bottomIndex) {
		let element = this.positionMap[[this.bottomLevel, bottomIndex]]

		if(!element) {
			return false
		}

		delete this.nodeMap[element]
		delete this.positionMap[[this.bottomLevel, bottomIndex]]

		this.updateInternalState(bottomIndex)

		return true
	}

	updateInternalState(bottomIndex) {
		let currentIndex = bottomIndex

		for(let currentLevel = this.bottomLevel; currentLevel >= 0; currentLevel--) {
			if(currentLevel != this.bottomLevel) {
				delete this.positionMap[[currentLevel, currentIndex]]
			}

			currentIndex = Math.floor(currentIndex / 2)
		}
	}

	getBottomIndex(element) {
		return this.nodeMap[element]
	}

	getNode(level, index) {
		if(index > ((this.nextAppendIndex - 1) >> (this.bottomLevel - level))) {
			return this.zeroes[level]
		}

		let result = this.positionMap[[level, index]]

		if(result == undefined) {
			if(level < this.bottomLevel) {
				result = this.hasher(this.getNode(level + 1, 2 * index), this.getNode(level + 1, (2 * index) + 1))
			}
			else {
				return this.zeroes[level]
			}
		}

		this.positionMap[[level, index]] = result
		return result
	}

	getRoot() {
		return this.getNode(0, 0)
	}

	getProof(bottomIndex) {
		return this.getLevelProof(bottomIndex, 0)
	}

	getLevelProof(bottomIndex, topLevel) {
		let siblings = []
		let isLeft = []

		let currentIndex = bottomIndex

		for(let currentLevel = this.bottomLevel; currentLevel >= (topLevel + 1); currentLevel--) {
			if(currentIndex & 0x1) {
				siblings[currentLevel] = this.getNode(currentLevel, currentIndex - 1)
				isLeft[currentLevel] = false
			}
			else {
				siblings[currentLevel] = this.getNode(currentLevel, currentIndex + 1)
				isLeft[currentLevel] = true
			}

			currentIndex = Math.floor(currentIndex / 2)
		}
		
		// For levels not asked, just place default values
		for(let currentLevel = topLevel; currentLevel >= 1; currentLevel--) {
			siblings[currentLevel] = 0n
			isLeft[currentLevel] = false
		}

		let root = this.getNode(topLevel, currentIndex)

		siblings.shift()
		isLeft.shift()

		console.log([root, siblings, isLeft])
		return [root, siblings, isLeft]
	}

	size() {
		return this.nextAppendIndex
	}
}