// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"math/big"
	"runtime"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/dlnproof"
)

func BenchmarkDlnProof_Verify(b *testing.B) {
	localPartySaveData, _, err := LoadKeygenTestFixtures(1)
	if err != nil {
		b.Fatal(err)
	}

	params := localPartySaveData[0].LocalPreParams

	proof := dlnproof.NewDLNProof(
		params.H1i,
		params.H2i,
		params.Alpha,
		params.P,
		params.Q,
		params.NTildei,
	)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		proof.Verify(params.H1i, params.H2i, params.NTildei)
	}
}

func BenchmarkDlnVerifier_VerifyProof1(b *testing.B) {
	preParams, alpha, t := prepareProofB(b)
	message := &KGRound1Message{
		Dlnproof_1: &KGRound1Message_DLNProof{
			Alpha: alpha,
			T:     t,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		resultChan := make(chan bool)
		verifier.VerifyDLNProof1(message, preParams.H1i, preParams.H2i, preParams.NTildei, func(result bool) {
			resultChan <- result
		})
		<-resultChan
	}
}

func BenchmarkDlnVerifier_VerifyProof2(b *testing.B) {
	preParams, alpha, t := prepareProofB(b)
	message := &KGRound1Message{
		Dlnproof_2: &KGRound1Message_DLNProof{
			Alpha: alpha,
			T:     t,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		resultChan := make(chan bool)
		verifier.VerifyDLNProof2(message, preParams.H1i, preParams.H2i, preParams.NTildei, func(result bool) {
			resultChan <- result
		})
		<-resultChan
	}
}

func TestVerifyDLNProof1_Success(t *testing.T) {
	preParams, alpha, tt := prepareProofT(t)
	message := &KGRound1Message{
		Dlnproof_1: &KGRound1Message_DLNProof{
			Alpha: alpha,
			T:     tt,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyDLNProof1(message, preParams.H1i, preParams.H2i, preParams.NTildei, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if !success {
		t.Fatal("expected positive verification")
	}
}

func TestVerifyDLNProof1_MalformedMessage1(t *testing.T) {
	preParams, alpha, tt := prepareProofT(t)
	message := &KGRound1Message{
		Dlnproof_1: &KGRound1Message_DLNProof{
			Alpha: alpha[:len(alpha)-1], // truncate
			T:     tt,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyDLNProof1(message, preParams.H1i, preParams.H2i, preParams.NTildei, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyDLNProof1_MalformedMessage2(t *testing.T) {
	preParams, alpha, tt := prepareProofT(t)
	message := &KGRound1Message{
		Dlnproof_1: &KGRound1Message_DLNProof{
			Alpha: alpha,
			T:     tt[:len(tt)-1], // truncate
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyDLNProof1(message, preParams.H1i, preParams.H2i, preParams.NTildei, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyDLNProof1_IncorrectProof(t *testing.T) {
	preParams, alpha, tt := prepareProofT(t)
	message := &KGRound1Message{
		Dlnproof_1: &KGRound1Message_DLNProof{
			Alpha: alpha,
			T:     tt,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	wrongH1i := preParams.H1i.Sub(preParams.H1i, big.NewInt(1))
	verifier.VerifyDLNProof1(message, wrongH1i, preParams.H2i, preParams.NTildei, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyDLNProof2_Success(t *testing.T) {
	preParams, alpha, tt := prepareProofT(t)
	message := &KGRound1Message{
		Dlnproof_2: &KGRound1Message_DLNProof{
			Alpha: alpha,
			T:     tt,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyDLNProof2(message, preParams.H1i, preParams.H2i, preParams.NTildei, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if !success {
		t.Fatal("expected positive verification")
	}
}

func TestVerifyDLNProof2_MalformedMessage1(t *testing.T) {
	preParams, alpha, tt := prepareProofT(t)
	message := &KGRound1Message{
		Dlnproof_2: &KGRound1Message_DLNProof{
			Alpha: alpha[:len(alpha)-1], // truncate
			T:     tt,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyDLNProof2(message, preParams.H1i, preParams.H2i, preParams.NTildei, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyDLNProof2_MalformedMessage2(t *testing.T) {
	preParams, alpha, tt := prepareProofT(t)
	message := &KGRound1Message{
		Dlnproof_2: &KGRound1Message_DLNProof{
			Alpha: alpha,
			T:     tt[:len(tt)-1], // truncate
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyDLNProof2(message, preParams.H1i, preParams.H2i, preParams.NTildei, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyDLNProof2_IncorrectProof(t *testing.T) {
	preParams, alpha, tt := prepareProofT(t)
	message := &KGRound1Message{
		Dlnproof_2: &KGRound1Message_DLNProof{
			Alpha: alpha,
			T:     tt,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	wrongH2i := preParams.H2i.Add(preParams.H2i, big.NewInt(1))
	verifier.VerifyDLNProof2(message, preParams.H1i, wrongH2i, preParams.NTildei, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func prepareProofT(t *testing.T) (*LocalPreParams, [][]byte, [][]byte) {
	preParams, alpha, tt, err := prepareProof()
	if err != nil {
		t.Fatal(err)
	}

	return preParams, alpha, tt
}

func prepareProofB(b *testing.B) (*LocalPreParams, [][]byte, [][]byte) {
	preParams, alpha, t, err := prepareProof()
	if err != nil {
		b.Fatal(err)
	}

	return preParams, alpha, t
}

func prepareProof() (*LocalPreParams, [][]byte, [][]byte, error) {
	localPartySaveData, _, err := LoadKeygenTestFixtures(1)
	if err != nil {
		return nil, [][]byte{}, [][]byte{}, err
	}

	preParams := localPartySaveData[0].LocalPreParams

	proof := dlnproof.NewDLNProof(
		preParams.H1i,
		preParams.H2i,
		preParams.Alpha,
		preParams.P,
		preParams.Q,
		preParams.NTildei,
	)

	return &preParams, common.BigIntsToBytes(proof.Alpha[:]), common.BigIntsToBytes(proof.T[:]), nil
}
