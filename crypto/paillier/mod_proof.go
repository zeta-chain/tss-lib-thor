package paillier

import (
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
)

const (
	PARAM_M = 80 // ZKP iterations
)

type (
	ModProof struct {
		W *big.Int
		X [PARAM_M]*big.Int
		A [PARAM_M]bool
		B [PARAM_M]bool
		Z [PARAM_M]*big.Int
	}
)

// ModProof is an implementation of the paillier-blum modulus proof of
// Canetti, R., Gennaro, R., Goldfeder, S., Makriyannis, N., Peled, U.:
// UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.
// In: Cryptology ePrint Archive 2021/060
func (privateKey *PrivateKey) ModProof() *ModProof {
	N := privateKey.PublicKey.N
	phiN := privateKey.PhiN
	p, q := privateKey.GetPQ()

	w := common.GetRandomPositiveInt(N)
	for big.Jacobi(w, N) != -1 {
		w = common.GetRandomPositiveInt(N)
	}

	y := ModChallenge(N, w)

	var x [PARAM_M]*big.Int
	var a [PARAM_M]bool
	var b [PARAM_M]bool
	var z [PARAM_M]*big.Int

	for i, y_i := range y {
		a_i, b_i, x_i := defineXi(w, y_i, p, q, N, phiN)
		x[i] = x_i
		a[i] = a_i
		b[i] = b_i

		z_i := new(big.Int).ModInverse(N, phiN)
		z_i.Exp(y_i, z_i, N)

		z[i] = z_i
	}

	return &ModProof{
		W: w,
		X: x,
		A: a,
		B: b,
		Z: z,
	}
}

// Verification: Accept iff all of the following hold:
// – N is an odd composite number.
// – z_i^N = y_i for every i ∈ [m]
// – x_i^4 = (-1)^a_i * w^b_i * y_i mod N and a_i, b_i ∈ {0, 1} for every i ∈ [m].
func (pf ModProof) ModVerify(N *big.Int) (bool, error) {
	if common.AnyIsNil(pf.W) || common.AnyIsNil(pf.X[:]...) || common.AnyIsNil(pf.Z[:]...) {
		return false, fmt.Errorf("mod proof verify: nil inputs in proof")
	}

	rem2 := new(big.Int).Mod(N, big.NewInt(2))
	odd := rem2.Int64() == 1

	if !odd {
		return false, fmt.Errorf("mod proof verify: modulus %d is even", N)
	}

	if N.ProbablyPrime(30) {
		return false, fmt.Errorf("mod proof verify: modulus %d seems prime", N)
	}

	if big.Jacobi(pf.W, N) != -1 {
		return false, fmt.Errorf("mod proof verify: w %d has invalid jacobi symbol %d", pf.W, big.Jacobi(pf.W, N))
	}

	if !common.Lt(pf.W, N) {
		return false, fmt.Errorf("mod proof verify: w %d exceeds N %d", pf.W, N)
	}

	y := ModChallenge(N, pf.W)

	for i, yi := range y {
		if !common.Lt(pf.X[i], N) {
			return false, fmt.Errorf("mod proof verify: x_%d %d exceeds N %d", i, pf.X[i], N)
		}
		if !common.Lt(pf.Z[i], N) {
			return false, fmt.Errorf("mod proof verify: z_%d %d exceeds N %d", i, pf.Z[i], N)
		}

		ziN := new(big.Int).Exp(pf.Z[i], N, N)

		if !common.Eq(ziN, yi) {
			return false, fmt.Errorf("mod proof verify: z_%d^N = %d != y_%d = %d", i, ziN, i, yi)
		}

		xi4 := new(big.Int).Exp(pf.X[i], big.NewInt(4), N)
		yy_i := new(big.Int).Set(yi)
		if pf.B[i] {
			yy_i.Mul(yy_i, pf.W)
		}
		if pf.A[i] {
			yy_i.Neg(yy_i)
		}
		yy_i.Mod(yy_i, N)
		if !common.Eq(xi4, yy_i) {
			return false, fmt.Errorf("mod proof verify: x_%d^4 = %d != (-1)^a_%d w^b_%d y_%d = %d", i, xi4, i, i, i, yy_i)
		}
	}

	return true, nil
}

// Standard Fiat-Shamir transform
func ModChallenge(N, w *big.Int) [PARAM_M]*big.Int {
	var y [PARAM_M]*big.Int

	for i := range y {
		y[i] = common.HashToN(N, w, big.NewInt(int64(i)))
	}

	return y
}

// Determine values a_i and b_i so that a valid x_i exists,
// and return a_i, b_i and x_i.
func defineXi(w, y_i, p, q, N, phiN *big.Int) (bool, bool, *big.Int) {
	bools := [...]bool{false, true}

	for _, a := range bools {
		for _, b := range bools {
			yy_i := new(big.Int).Set(y_i)

			if b {
				yy_i.Mul(yy_i, w)
			}

			if a {
				yy_i.Neg(yy_i)
			}

			yy_i.Mod(yy_i, N)

			if isQuadResidueModComposite(yy_i, p, q) {
				return a, b, quadResidueModComposite(yy_i, p, q, N, phiN)
			}
		}
	}

	panic("no root found") // this should not be reached with n=pq for safe primes p, q
}

// x is quadratic residue modulo pq if x is a quadratic residue modulo p and q
func isQuadResidueModComposite(x, p, q *big.Int) bool {
	return isQuadResidueModPrime(x, p) && isQuadResidueModPrime(x, q)
}

// x is a quadratic residue modulo p if x^((p-1)/2) = 1
func isQuadResidueModPrime(x, p *big.Int) bool {
	ps := new(big.Int).Sub(p, big.NewInt(1))
	ps = ps.Div(ps, big.NewInt(2))

	return common.Eq(new(big.Int).Exp(x, ps, p), big.NewInt(1))
}

// the square root of x can be calculated as x^((phiN+4)/8)
// apply this twice to get the 4th root
func quadResidueModComposite(x, p, q, n, phiN *big.Int) *big.Int {
	e := new(big.Int).Add(phiN, big.NewInt(4))
	e = e.Div(e, big.NewInt(8))

	res := new(big.Int).Exp(x, e, n)
	res = res.Exp(res, e, n)

	return res
}

func UnmarshalModProof(ws []byte, xs [][]byte, as []bool, bs []bool, zs [][]byte) (*ModProof, error) {
	if len(ws) == 0 {
		return nil, fmt.Errorf("UnmarshalModProof: W length zero")
	}
	if len(xs) != PARAM_M {
		return nil, fmt.Errorf("UnmarshalModProof: incorrect number of Xs: %d, expected %d", len(xs), PARAM_M)
	}
	if len(as) != PARAM_M {
		return nil, fmt.Errorf("UnmarshalModProof: incorrect number of As: %d, expected %d", len(as), PARAM_M)
	}
	if len(bs) != PARAM_M {
		return nil, fmt.Errorf("UnmarshalModProof: incorrect number of Bs: %d, expected %d", len(bs), PARAM_M)
	}
	if len(zs) != PARAM_M {
		return nil, fmt.Errorf("UnmarshalModProof: incorrect number of Zs: %d, expected %d", len(zs), PARAM_M)
	}

	W := new(big.Int).SetBytes(ws)
	x := common.MultiBytesToBigInts(xs)
	z := common.MultiBytesToBigInts(zs)

	var X [PARAM_M]*big.Int
	var A [PARAM_M]bool
	var B [PARAM_M]bool
	var Z [PARAM_M]*big.Int

	for i := 0; i < PARAM_M; i++ {
		X[i] = x[i]
		A[i] = as[i]
		B[i] = bs[i]
		Z[i] = z[i]
	}

	return &ModProof{W, X, A, B, Z}, nil
}
