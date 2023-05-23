package paillier

import (
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
)

const (
	PARAM_E = 512
	PARAM_L = 256
)

type (
	FactorProof struct {
		// Commitment
		P     *big.Int
		Q     *big.Int
		A     *big.Int
		B     *big.Int
		T     *big.Int
		Sigma *big.Int
		// Response
		Z1 *big.Int
		Z2 *big.Int
		W1 *big.Int
		W2 *big.Int
		V  *big.Int
	}
)

// FactorProof is an implementation of the no small factor proof of
// Canetti, R., Gennaro, R., Goldfeder, S., Makriyannis, N., Peled, U.:
// UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.
// In: Cryptology ePrint Archive 2021/060
func (privateKey *PrivateKey) FactorProof(N, s, t *big.Int) *FactorProof {
	N0 := privateKey.PublicKey.N
	p, q := privateKey.GetPQ()

	a := common.GetRandomIntIn2PowerRange(PARAM_L + PARAM_E)
	b := common.GetRandomIntIn2PowerRange(PARAM_L + PARAM_E)

	mu := common.GetRandomIntIn2PowerMulRange(PARAM_L, N)
	v := common.GetRandomIntIn2PowerMulRange(PARAM_L, N)

	sigma := common.GetRandomIntIn2PowerMulRange(PARAM_L, new(big.Int).Mul(N0, N))
	r := common.GetRandomIntIn2PowerMulRange(PARAM_L+PARAM_E, new(big.Int).Mul(N0, N))

	x := common.GetRandomIntIn2PowerMulRange(PARAM_L+PARAM_E, N)
	y := common.GetRandomIntIn2PowerMulRange(PARAM_L+PARAM_E, N)

	modN := common.ModInt(N)

	P := modN.ExpMulExp(s, p, t, mu)
	Q := modN.ExpMulExp(s, q, t, v)
	A := modN.ExpMulExp(s, a, t, x)
	B := modN.ExpMulExp(s, b, t, y)
	T := modN.ExpMulExp(Q, a, t, r)

	e := FactorChallenge(N, s, t, N0, P, Q, A, B, T, sigma)

	sigmaH := new(big.Int)
	sigmaH.Mul(v, p)
	sigmaH.Sub(sigma, sigmaH)

	z1 := common.AddMul(a, e, p)
	z2 := common.AddMul(b, e, q)
	w1 := common.AddMul(x, e, mu)
	w2 := common.AddMul(y, e, v)
	vv := common.AddMul(r, e, sigmaH)

	return &FactorProof{P, Q, A, B, T, sigma, z1, z2, w1, w2, vv}
}

func (pf FactorProof) FactorVerify(pkN, N, s, t *big.Int) (bool, error) {
	if common.AnyIsNil(pkN, N, s, t) {
		return false, fmt.Errorf("fac proof verify: nil bigint present in args")
	}
	if common.AnyIsNil(pf.P, pf.Q, pf.A, pf.B, pf.T, pf.Sigma, pf.Z1, pf.Z2, pf.W1, pf.W2, pf.V) {
		return false, fmt.Errorf("fac proof verify: nil bigint present in proof")
	}

	e := FactorChallenge(N, s, t, pkN, pf.P, pf.Q, pf.A, pf.B, pf.T, pf.Sigma)

	modN := common.ModInt(N)

	R := modN.ExpMulExp(s, pkN, t, pf.Sigma)

	sz1tw1 := modN.ExpMulExp(s, pf.Z1, t, pf.W1)
	sz2tw2 := modN.ExpMulExp(s, pf.Z2, t, pf.W2)
	Qz1tv := modN.ExpMulExp(pf.Q, pf.Z1, t, pf.V)

	APe := modN.MulExp(pf.A, pf.P, e)
	BQe := modN.MulExp(pf.B, pf.Q, e)
	TRe := modN.MulExp(pf.T, R, e)

	if !common.Eq(sz1tw1, APe) {
		return false, fmt.Errorf("fac proof verify: s^z1*t^w1 = %x != A*P^e = %x", sz1tw1, APe)
	}

	if !common.Eq(sz2tw2, BQe) {
		return false, fmt.Errorf("fac proof verify: s^z2*t^w2 = %x != B*Q^e = %x", sz2tw2, BQe)
	}

	if !common.Eq(Qz1tv, TRe) {
		return false, fmt.Errorf("fac proof verify: Q^z1*t^v = %x != T*R^e = %x", Qz1tv, TRe)
	}

	limit := big.NewInt(1)
	limit.Lsh(limit, PARAM_L+PARAM_E)
	limit.Mul(limit, new(big.Int).Sqrt(pkN))

	if pf.Z1.CmpAbs(limit) > 0 {
		return false, fmt.Errorf("fac proof verify: z1 = %x exceeds limit %x", pf.Z1, limit)
	}

	if pf.Z2.CmpAbs(limit) > 0 {
		return false, fmt.Errorf("fac proof verify: z2 = %x exceeds limit %x", pf.Z2, limit)
	}

	return true, nil
}

func FactorChallenge(N, s, t, pkN, P, Q, A, B, T, sigma *big.Int) *big.Int {
	h := common.SHA512_256i(N, s, t, pkN, P, Q, A, B, T, sigma)

	// calculate the sign bit
	// FIXME: ugly hack
	signInt := new(big.Int).SetBytes([]byte("factor proof sign bit"))
	sign := common.SHA512_256i(signInt, N, s, t, pkN, P, Q, A, B, T, sigma)

	sign.Mod(sign, big.NewInt(2))

	if sign.Cmp(big.NewInt(1)) == 0 {
		h.Neg(h)
	}

	return h
}
