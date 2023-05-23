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
