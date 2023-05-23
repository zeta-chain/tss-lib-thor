// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
)

type ProofVerifier struct {
	semaphore chan interface{}
}

type message interface {
	UnmarshalDLNProof1() (*dlnproof.Proof, error)
	UnmarshalDLNProof2() (*dlnproof.Proof, error)
	UnmarshalParamProof() (*paillier.ParamProof, error)
}

func NewProofVerifier(concurrency int) *ProofVerifier {
	if concurrency == 0 {
		panic(errors.New("NewDlnProofverifier: concurrency level must not be zero"))
	}

	semaphore := make(chan interface{}, concurrency)

	return &ProofVerifier{
		semaphore: semaphore,
	}
}

func (dpv *ProofVerifier) VerifyDLNProof1(
	m message,
	h1, h2, n *big.Int,
	onDone func(bool),
) {
	dpv.semaphore <- struct{}{}
	go func() {
		defer func() { <-dpv.semaphore }()

		dlnProof, err := m.UnmarshalDLNProof1()
		if err != nil {
			onDone(false)
			return
		}

		onDone(dlnProof.Verify(h1, h2, n))
	}()
}

func (dpv *ProofVerifier) VerifyDLNProof2(
	m message,
	h1, h2, n *big.Int,
	onDone func(bool),
) {
	dpv.semaphore <- struct{}{}
	go func() {
		defer func() { <-dpv.semaphore }()

		dlnProof, err := m.UnmarshalDLNProof2()
		if err != nil {
			onDone(false)
			return
		}

		onDone(dlnProof.Verify(h1, h2, n))
	}()
}

func (pv *ProofVerifier) VerifyParamProof(
	m message,
	N, s, t *big.Int,
	onDone func(bool),
) {
	pv.semaphore <- struct{}{}
	go func() {
		defer func() { <-pv.semaphore }()

		prmProof, err := m.UnmarshalParamProof()
		if err != nil {
			onDone(false)
			return
		}

		onDone(prmProof.ParamVerify(N, s, t))
	}()
}
