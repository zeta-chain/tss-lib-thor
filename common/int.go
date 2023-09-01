// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"math/big"
)

// modInt is a *big.Int that performs all of its arithmetic with modular reduction.
type modInt big.Int

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)
)

func Eq(x, y *big.Int) bool {
	return x.Cmp(y) == 0
}

func Gt(x, y *big.Int) bool {
	return x.Cmp(y) == 1
}

func Lt(x, y *big.Int) bool {
	return x.Cmp(y) == -1
}

func Coprime(x, y *big.Int) bool {
	z := new(big.Int).GCD(nil, nil, x, y)
	return Eq(z, big.NewInt(1))
}

// return x + yz
func AddMul(x, y, z *big.Int) *big.Int {
	res := new(big.Int)
	res.Mul(y, z)
	res.Add(res, x)
	return res
}

func ModInt(mod *big.Int) *modInt {
	return (*modInt)(mod)
}

func (mi *modInt) Neg(x *big.Int) *big.Int {
	i := new(big.Int)
	i.Neg(x)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Add(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Add(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Sub(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Sub(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Div(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Div(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Mul(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Mul(x, y)
	return i.Mod(i, mi.i())
}

func (mi *modInt) Exp(x, y *big.Int) *big.Int {
	return new(big.Int).Exp(x, y, mi.i())
}

// return x * y^z % mi
func (mi *modInt) MulExp(x, y, z *big.Int) *big.Int {
	return mi.Mul(x, mi.Exp(y, z))
}

// return x^y * z^w % mi
func (mi *modInt) ExpMulExp(x, y, z, w *big.Int) *big.Int {
	return mi.Mul(mi.Exp(x, y), mi.Exp(z, w))
}

func (mi *modInt) ModInverse(g *big.Int) *big.Int {
	return new(big.Int).ModInverse(g, mi.i())
}

func (mi *modInt) i() *big.Int {
	return (*big.Int)(mi)
}

// Marshal the given bigint into bytes.
// with the sign stored in the first byte and the absolute value in the rest.
// `nil` or 0 is stored as the byte 0x00.
// The sign byte is 0x00 for positive and 0x01 for negative.
func MarshalSigned(i *big.Int) []byte {
	if i == nil || Eq(i, big.NewInt(0)) {
		return []byte{0}
	}

	// 0 = positive, 1 = negative
	sign := make([]byte, 1)
	if i.Sign() == 1 {
		sign[0] = 0
	} else {
		sign[0] = 1
	}

	bs := i.Bytes()

	return append(sign, bs...)
}

// Unmarshal a signed bigint from the given bytes.
// Slices of length 1 are interpreted as 0;
// in longer slices the first byte determines the sign
// (0x00 is positive, anything else is negative)
// and the remaining bytes contain the value of the bigint.
func UnmarshalSigned(b []byte) *big.Int {
	if len(b) <= 1 {
		return big.NewInt(0)
	}

	sign := b[0]
	rest := b[1:]
	i := new(big.Int).SetBytes(rest)
	if sign != 0 {
		i.Neg(i)
	}
	return i
}

// Returns true when at least one of the arguments is nil
func AnyIsNil(is ...*big.Int) bool {
	for _, i := range is {
		if i == nil {
			return true
		}
	}
	return false
}
