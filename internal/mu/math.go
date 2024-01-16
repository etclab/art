package mu

func IsPowerOfTwo(x uint) bool {
	return (x & (x - 1)) == 0
}
