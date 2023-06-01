package paillier

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func modSetUp(t *testing.T) {
	if privateKey != nil && publicKey != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var err error
	privateKey, publicKey, err = GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)
}

func TestModProofVerify(t *testing.T) {
	modSetUp(t)
	proof := privateKey.ModProof()
	res, err := proof.ModVerify(publicKey.N)
	assert.NoError(t, err)
	assert.True(t, res, "proof verify result must be true")
}

func TestModProofVerifyFail(t *testing.T) {
	modSetUp(t)
	proof := privateKey.ModProof()
	last := proof.Z[PARAM_M-1]
	last.Sub(last, big.NewInt(1))
	res, err := proof.ModVerify(publicKey.N)
	assert.Error(t, err)
	assert.False(t, res, "proof verify result must be false")
}

func TestModProofVerify_ForgedProof(t *testing.T) {
	p := big.NewInt(17) // NOT a safe prime and NOT congruent to 3 (mod 4) because 17 mod 4 = 1
	q := big.NewInt(7)  // safe prime because 2*3+1 and congruent to 3 (mod 4) because 7 mod 4 = 3
	N := new(big.Int).Mul(p, q)

	// phiN = (p-1)(q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phiN := new(big.Int).Mul(pMinus1, qMinus1)

	// Use w = 0 deliberately.
	w := big.NewInt(0)
	// Construct the mod challenge as usual.
	y := ModChallenge(N, w)

	var x [PARAM_M]*big.Int
	var a [PARAM_M]bool
	var b [PARAM_M]bool
	var z [PARAM_M]*big.Int

	z_0 := new(big.Int).ModInverse(N, phiN)

	for i, y_i := range y {
		// Use a_i = true, b_i = true, x_i = 0 deliberately.
		x[i] = big.NewInt(0)
		a[i] = true
		b[i] = true
		z[i] = new(big.Int).Exp(y_i, z_0, N)
	}

	forgedMoodProof := &ModProof{
		W: w,
		X: x,
		A: a,
		B: b,
		Z: z,
	}

	res, err := forgedMoodProof.ModVerify(N)
	assert.Error(t, err)
	assert.False(t, res, "proof verify result must be false")
}

func TestModSqrt(t *testing.T) {
	assert := assert.New(t)
	b := big.NewInt

	one := b(1)
	two := b(2)
	three := b(3)
	four := b(4)
	five := b(5)
	six := b(6)

	seven := b(7) // safe prime: 7 = 2*3+1

	eight := b(8)
	nine := b(9)
	ten := b(10)

	eleven := b(11) // safe prime: 11 = 2*5+1

	// 1*1 = 1  = 1 mod 7 = 1 mod 11
	// 2*2 = 4  = 4 mod 7 = 4 mod 11
	// 3*3 = 9  = 2 mod 7 = 9 mod 11
	// 4*4 = 16 = 2 mod 7 = 5 mod 11
	// 5*5 = 25 = 4 mod 7 = 3 mod 11
	// 6*6 = 36 = 1 mod 7 = 3 mod 11
	// 7*7 = 49           = 5 mod 11
	// 8*8 = 64           = 9 mod 11
	// 9*9 = 81           = 4 mod 11
	// 10*10 = 100        = 1 mod 11

	assert.ElementsMatch([]*big.Int{one, six}, primeModSqrt(one, seven))
	assert.ElementsMatch([]*big.Int{three, four}, primeModSqrt(two, seven))
	assert.ElementsMatch([]*big.Int{}, primeModSqrt(three, seven))
	assert.ElementsMatch([]*big.Int{two, five}, primeModSqrt(four, seven))
	assert.ElementsMatch([]*big.Int{}, primeModSqrt(five, seven))
	assert.ElementsMatch([]*big.Int{}, primeModSqrt(six, seven))

	assert.ElementsMatch([]*big.Int{one, ten}, primeModSqrt(one, eleven))
	assert.ElementsMatch([]*big.Int{}, primeModSqrt(two, eleven))
	assert.ElementsMatch([]*big.Int{five, six}, primeModSqrt(three, eleven))
	assert.ElementsMatch([]*big.Int{two, nine}, primeModSqrt(four, eleven))
	assert.ElementsMatch([]*big.Int{four, seven}, primeModSqrt(five, eleven))
	assert.ElementsMatch([]*big.Int{}, primeModSqrt(six, eleven))
	assert.ElementsMatch([]*big.Int{}, primeModSqrt(seven, eleven))
	assert.ElementsMatch([]*big.Int{}, primeModSqrt(eight, eleven))
	assert.ElementsMatch([]*big.Int{three, eight}, primeModSqrt(nine, eleven))
	assert.ElementsMatch([]*big.Int{}, primeModSqrt(ten, eleven))

	aa, bb := b(0), b(0)
	b(0).GCD(aa, bb, b(7), b(11))
	assert.Equal(b(-3), aa)
	assert.Equal(b(2), bb)

	// p = 7, q = 11, n = 77
	//
	// -3*7 + 2*11 = 1
	// a = -3, b = 2
	// ap = -21 = 56 (mod 77), bq = 22
	//
	// sqrt(60) mod 77:
	// 60 = 4 (mod 7), 2^2 = 4, 5^2 = 4 (mod 7)
	// 60 = 5 (mod 11), 4^2 = 5 (mod 11), 7^2 = 5 (mod 11)
	//
	// rps = 2, 5
	// rqs = 4, 7
	//
	// r = 22rp + 56rq
	//
	// 22*2 = 44
	// 22*5 = 110 = 33 (mod 77)
	// 56*4 = 224 = 70 (mod 77)
	// 56*7 = 392 = 7 (mod 77)
	//
	// r1 = 44+70 = 114 = 37 (mod 77)
	// r2 = 44+7 = 51
	// r3 = 33+70 = 103 = 26 (mod 77)
	// r4 = 33+7 = 40
	//
	// 37^2 = 1369 = 60 mod 77
	// 51^2 = 2601 = 60 mod 77
	// 26^2 = 676 = 60 mod 77
	// 40^2 = 1600 = 60 mod 77

	assert.ElementsMatch([]*big.Int{b(37), b(51), b(26), b(40)}, compModSqrt(b(60), b(7), b(11), b(77)))

	// 60^2 = 3600 = 58 mod 77
	// 37^4 = 58 mod 77
	assert.Equal(b(37), compMod4thRt(b(58), b(7), b(11), b(77)))

	// 59 = 3 (mod 7) which is not a residue
	// 59 = 4 (mod 11)
	assert.Nil(compMod4thRt(b(59), b(7), b(11), b(77)))
}
