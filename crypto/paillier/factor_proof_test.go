package paillier_test

import (
	"context"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	. "github.com/bnb-chain/tss-lib/crypto/paillier"
)

var (
	auxPrime *PublicKey
	s        *big.Int
	tt       *big.Int
	badPrivateKey *PrivateKey
	badPublicKey *PublicKey
)

func facSetUp(t *testing.T) {
	if privateKey != nil && publicKey != nil && auxPrime != nil && s != nil && tt != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var err error
	privateKey, publicKey, err = GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	var err2 error
	var auxSecret *PrivateKey
	auxSecret, auxPrime, err2 = GenerateKeyPair(ctx, testPaillierKeyLength)

	lambda := common.GetRandomPositiveInt(auxSecret.PhiN)
	N := auxPrime.N
	r := common.GetRandomPositiveRelativelyPrimeInt(N)
	tt = new(big.Int).Mod(new(big.Int).Mul(r, r), N)
	s = new(big.Int).Exp(tt, lambda, N)

	assert.NoError(t, err2)

	var err3 error
	badPrivateKey, badPublicKey, err3 = GenerateBadKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err3)
}

func GenerateBadKeyPair(ctx context.Context, modulusBitLen int) (privateKey *PrivateKey, publicKey *PublicKey, err error) {
	var concurrency int
	concurrency = runtime.NumCPU()
	one := big.NewInt(1)

	// KS-BTL-F-03: use two safe primes for P, Q
	var P, Q, N *big.Int
	{
		tmp := new(big.Int)
		sgpsLong, err := common.GetRandomSafePrimesConcurrent(ctx, modulusBitLen-128, 1, concurrency)
		if err != nil {
			return nil, nil, err
		}
		sgpsShort, err := common.GetRandomSafePrimesConcurrent(ctx, 128, 1, concurrency)
		if err != nil {
			return nil, nil, err
		}
		P, Q = sgpsLong[0].SafePrime(), sgpsShort[0].SafePrime()
		N = tmp.Mul(P, Q)
	}

	// phiN = P-1 * Q-1
	PMinus1, QMinus1 := new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one)
	phiN := new(big.Int).Mul(PMinus1, QMinus1)

	// lambdaN = lcm(P−1, Q−1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	lambdaN := new(big.Int).Div(phiN, gcd)

	publicKey = &PublicKey{N: N}
	privateKey = &PrivateKey{PublicKey: *publicKey, LambdaN: lambdaN, PhiN: phiN}
	return
}

func TestFactorProofVerify(t *testing.T) {
	facSetUp(t)
	proof := privateKey.FactorProof(auxPrime.N, s, tt)
	res, err := proof.FactorVerify(publicKey.N, auxPrime.N, s, tt)
	assert.NoError(t, err)
	assert.True(t, res, "proof verify result must be true")
}

func TestFactorProofVerifyFail1(t *testing.T) {
	facSetUp(t)
	badN := new(big.Int).Mul(publicKey.N, big.NewInt(3))
	proof := privateKey.FactorProof(auxPrime.N, s, tt)
	res, err := proof.FactorVerify(badN, auxPrime.N, s, tt)
	assert.Error(t, err)
	assert.False(t, res, "proof verify result must be false")
}

func TestFactorProofVerifyFail2(t *testing.T) {
	facSetUp(t)
	proof := privateKey.FactorProof(auxPrime.N, s, tt)
	proof.V = nil
	res, err := proof.FactorVerify(publicKey.N, auxPrime.N, s, tt)
	assert.Error(t, err)
	assert.False(t, res, "proof verify result must be false")
}

func TestFactorProofVerifyFail3(t *testing.T) {
	facSetUp(t)
	proof := privateKey.FactorProof(auxPrime.N, s, tt)
	res, err := proof.FactorVerify(publicKey.N, auxPrime.N, s, nil)
	assert.Error(t, err)
	assert.False(t, res, "proof verify result must be false")
}

func TestFactorProofVerifyFailBadFactors(t *testing.T) {
	facSetUp(t)
	proof := badPrivateKey.FactorProof(auxPrime.N, s, tt)
	res, err := proof.FactorVerify(badPublicKey.N, auxPrime.N, s, tt)
	assert.Error(t, err)
	assert.False(t, res, "proof verify result must be false")
}
