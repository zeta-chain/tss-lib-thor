// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"math/big"
)

// LiterallyJustMod implements the logic for converting a
// SHA512/256 hash to a value between 0-q by taking the number modulo q.
// XXX: this is only safe if used with values of q that are extremely close
// to a power of 2. The order of secp256k1 happens to be one of those values,
// and the bias introduced by the modulus is around 1.27*2^-128.
// The same applies to the order of curve25519.
func LiterallyJustMod(q *big.Int, eHash *big.Int) *big.Int { // e' = eHash
	e := eHash.Mod(eHash, q)
	return e
}

// Return a big.Int between 0 and N
func HashToN(N *big.Int, in ...*big.Int) *big.Int {
	bitCnt := N.BitLen()
	// Add 256 bits to remove bias from LiterallyJustMod,
	// and another 256 bits to compensate for any remainder from the division.
	blockCnt := (bitCnt / 256) + 2

	dest := big.NewInt(0)
	tmp := make([]*big.Int, 1, 1+len(in))
	tmp = append(tmp, in...)

	for i := 0; i < blockCnt; i++ {
		// dest = h(0, in) | h(1, in) | h(2, in) | ...
		tmp[0] = big.NewInt(int64(i))
		dest.Lsh(dest, 256)
		dest.Or(dest, SHA512_256i(tmp...))
	}

	// dest has at least N.BitLen + 256 bits,
	// thus it is safe to use Mod
	return LiterallyJustMod(N, dest)
}
