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

type dlnMessage interface {
	UnmarshalDLNProof1() (*dlnproof.Proof, error)
	UnmarshalDLNProof2() (*dlnproof.Proof, error)
}

type modMessage interface {
	UnmarshalModProof() (*paillier.ModProof, error)
	UnmarshalModProofTilde() (*paillier.ModProof, error)
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

func (pv *ProofVerifier) VerifyDLNProof1(
	m dlnMessage,
	h1, h2, n *big.Int,
	onDone func(bool),
) {
	pv.semaphore <- struct{}{}
	go func() {
		defer func() { <-pv.semaphore }()

		dlnProof, err := m.UnmarshalDLNProof1()
		if err != nil {
			onDone(false)
			return
		}

		onDone(dlnProof.Verify(h1, h2, n))
	}()
}

func (pv *ProofVerifier) VerifyDLNProof2(
	m dlnMessage,
	h1, h2, n *big.Int,
	onDone func(bool),
) {
	pv.semaphore <- struct{}{}
	go func() {
		defer func() { <-pv.semaphore }()

		dlnProof, err := m.UnmarshalDLNProof2()
		if err != nil {
			onDone(false)
			return
		}

		onDone(dlnProof.Verify(h1, h2, n))
	}()
}

func (pv *ProofVerifier) VerifyModProof(
	m modMessage,
	N *big.Int,
	onDone func(bool),
) {
	pv.semaphore <- struct{}{}
	go func() {
		defer func() { <-pv.semaphore }()

		modProof, err := m.UnmarshalModProof()
		if err != nil {
			onDone(false)
			return
		}

		ok, err2 := modProof.ModVerify(N)
		if err2 != nil {
			onDone(false)
			return
		}
		onDone(ok)
	}()
}

func (pv *ProofVerifier) VerifyModProofTilde(
	m modMessage,
	N *big.Int,
	onDone func(bool),
) {
	pv.semaphore <- struct{}{}
	go func() {
		defer func() { <-pv.semaphore }()

		modProof, err := m.UnmarshalModProofTilde()
		if err != nil {
			onDone(false)
			return
		}

		ok, err2 := modProof.ModVerify(N)
		if err2 != nil {
			onDone(false)
			return
		}
		onDone(ok)
	}()
}
