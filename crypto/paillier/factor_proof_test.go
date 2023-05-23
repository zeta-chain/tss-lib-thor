package paillier_test

import (
	"context"
	"math/big"
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
}

func TestFactorProofVerify(t *testing.T) {
	facSetUp(t)
	proof := privateKey.FactorProof(auxPrime.N, s, tt)
	res, err := proof.FactorVerify(publicKey.N, auxPrime.N, s, tt)
	assert.NoError(t, err)
	assert.True(t, res, "proof verify result must be true")
}

func TestFactorProofVerifyFail(t *testing.T) {
	facSetUp(t)
	badN := new(big.Int).Mul(publicKey.N, big.NewInt(3))
	proof := privateKey.FactorProof(auxPrime.N, s, tt)
	res, err := proof.FactorVerify(badN, auxPrime.N, s, tt)
	assert.Error(t, err)
	assert.False(t, res, "proof verify result must be false")
}