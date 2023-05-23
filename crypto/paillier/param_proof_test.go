package paillier_test

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	. "github.com/bnb-chain/tss-lib/crypto/paillier"
)

var (
	lambda *big.Int
)

func prmSetUp(t *testing.T) {
	if privateKey != nil && publicKey != nil && lambda != nil && s != nil && tt != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var err error
	privateKey, publicKey, err = GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	lambda = common.GetRandomPositiveInt(privateKey.PhiN)
	N := publicKey.N
	r := common.GetRandomPositiveRelativelyPrimeInt(N)
	tt = new(big.Int).Mod(new(big.Int).Mul(r, r), N)
	s = new(big.Int).Exp(tt, lambda, N)
}

func TestBytesToBits(t *testing.T) {
	bs, err := hex.DecodeString("0102030405060708090a0b0c0d0e0f")
	assert.NoError(t, err)
	b := BytesToBits(bs)
	assert.Equal(t, 80, len(b))
	assert.Equal(t, byte(1), b[0], "b[0] should be 1")
	assert.Equal(t, byte(0), b[1], "b[1] should be 0")
	assert.Equal(t, byte(0), b[8], "b[8] should be 0")
	assert.Equal(t, byte(1), b[9], "b[9] should be 1")
	assert.Equal(t, byte(1), b[16], "b[16] should be 1")
	assert.Equal(t, byte(1), b[17], "b[17] should be 1")
}

func TestParamProofVerify(t *testing.T) {
	prmSetUp(t)
	proof := privateKey.ParamProof(s, tt, lambda)
	res := proof.ParamVerify(publicKey.N, s, tt)
	assert.True(t, res, "proof verify result must be true")
}
