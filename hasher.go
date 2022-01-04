package hasher

import "math/big"

type Block struct {
	Header     string
	SeedHash   string
	Height     uint64
	Nonce      uint64
	Difficulty string
}

func Sum(Block) (*big.Int, error) {
	// ...
	return new(big.Int), nil
}

func Verify(Block) (bool, error) {
	// ...
	return false, nil
}
