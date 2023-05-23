package common_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
)

func TestMarshalSigned(t *testing.T) {
	assert := assert.New(t)

	assert.Equal([]byte{0}, common.MarshalSigned(nil), "Nil should marshal to 0x00")
	assert.Equal([]byte{0}, common.MarshalSigned(big.NewInt(0)), "0 should marshal to 0x00")
	assert.Equal([]byte{0, 1}, common.MarshalSigned(big.NewInt(1)), "1 should marshal to 0x0001")
	assert.Equal([]byte{0, 1, 1}, common.MarshalSigned(big.NewInt(257)), "257 should marshal to 0x000101")
	assert.Equal([]byte{1, 1}, common.MarshalSigned(big.NewInt(-1)), "-1 should marshal to 0x0101")
}

func TestUnmarshalSigned(t *testing.T) {
	assert := assert.New(t)

	assert.True(
		big.NewInt(0).Cmp(common.UnmarshalSigned([]byte{0})) == 0,
		"0x00 should unmarshal to 0",
	)
	assert.True(
		big.NewInt(0).Cmp(common.UnmarshalSigned([]byte{1})) == 0,
		"0x01 should unmarshal to 0",
	)
	assert.True(
		big.NewInt(0).Cmp(common.UnmarshalSigned([]byte{255})) == 0,
		"0xff should unmarshal to 0",
	)

	assert.True(
		big.NewInt(0).Cmp(common.UnmarshalSigned([]byte{0, 0})) == 0,
		"0x0000 should unmarshal to 0",
	)
	assert.True(
		big.NewInt(0).Cmp(common.UnmarshalSigned([]byte{1, 0})) == 0,
		"0x0100 should unmarshal to 0",
	)
	assert.True(
		big.NewInt(0).Cmp(common.UnmarshalSigned([]byte{255, 0})) == 0,
		"0xff00 should unmarshal to 0",
	)

	assert.True(
		big.NewInt(1).Cmp(common.UnmarshalSigned([]byte{0, 1})) == 0,
		"0x0001 should unmarshal to 1",
	)
	assert.True(
		big.NewInt(-1).Cmp(common.UnmarshalSigned([]byte{1, 1})) == 0,
		"0x0101 should unmarshal to -1",
	)
	assert.True(
		big.NewInt(-1).Cmp(common.UnmarshalSigned([]byte{255, 1})) == 0,
		"0xff01 should unmarshal to -1",
	)

	assert.True(
		big.NewInt(255).Cmp(common.UnmarshalSigned([]byte{0, 255})) == 0,
		"0x00ff should unmarshal to 255",
	)
	assert.True(
		big.NewInt(-255).Cmp(common.UnmarshalSigned([]byte{1, 255})) == 0,
		"0x01ff should unmarshal to -255",
	)
	assert.True(
		big.NewInt(-255).Cmp(common.UnmarshalSigned([]byte{255, 255})) == 0,
		"0xffff should unmarshal to -255",
	)
}

func TestAnyIsNil(t *testing.T) {
	assert := assert.New(t)

	assert.True(common.AnyIsNil(nil))
	assert.False(common.AnyIsNil(big.NewInt(1)))

	assert.True(common.AnyIsNil(big.NewInt(1), nil))
	assert.True(common.AnyIsNil(nil, big.NewInt(2)))
	assert.False(common.AnyIsNil(big.NewInt(1), big.NewInt(2)))
}
