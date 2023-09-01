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
	preParams, alpha, tt := prepareProofB(b)
	message := &KGRound1Message{
		Dlnproof_1: &KGRound1Message_DLNProof{
			Alpha: alpha,
			T:     tt,
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
	preParams, alpha, tt := prepareProofB(b)
	message := &KGRound1Message{
		Dlnproof_2: &KGRound1Message_DLNProof{
			Alpha: alpha,
			T:     tt,
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
	preParams, alpha, tt, err := prepareProof()
	if err != nil {
		b.Fatal(err)
	}

	return preParams, alpha, tt
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

func BenchmarkProofVerifier_VerifyModProof(b *testing.B) {
	preParams, w, x, a, bb, z := prepareModProofB(b)
	message := &KGRound1Message{
		Modproof: &KGRound1Message_ModProof{
			W: w,
			X: x,
			A: a,
			B: bb,
			Z: z,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		resultChan := make(chan bool)
		verifier.VerifyModProof(message, preParams.PaillierSK.PublicKey.N, func(result bool) {
			resultChan <- result
		})
		<-resultChan
	}
}

func TestVerifyModProof_Success(t *testing.T) {
	preParams, w, x, a, b, z := prepareModProofT(t)
	message := &KGRound1Message{
		Modproof: &KGRound1Message_ModProof{
			W: w,
			X: x,
			A: a,
			B: b,
			Z: z,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyModProof(message, preParams.PaillierSK.PublicKey.N, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if !success {
		t.Fatal("expected positive verification")
	}
}

func TestVerifyModProof_MalformedMessage1(t *testing.T) {
	preParams, w, x, a, b, z := prepareModProofT(t)
	message := &KGRound1Message{
		Modproof: &KGRound1Message_ModProof{
			W: w,
			X: x[:len(x)-1],
			A: a,
			B: b,
			Z: z,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyModProof(message, preParams.PaillierSK.PublicKey.N, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyModProof_MalformedMessage2(t *testing.T) {
	preParams, w, x, a, b, z := prepareModProofT(t)
	message := &KGRound1Message{
		Modproof: &KGRound1Message_ModProof{
			W: w,
			X: x,
			A: a[:len(a)-1],
			B: b,
			Z: z,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyModProof(message, preParams.PaillierSK.PublicKey.N, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyModProof_MalformedMessage3(t *testing.T) {
	preParams, w, x, a, b, z := prepareModProofT(t)
	message := &KGRound1Message{
		Modproof: &KGRound1Message_ModProof{
			W: w,
			X: x,
			A: a,
			B: b[:len(b)-1],
			Z: z,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyModProof(message, preParams.PaillierSK.PublicKey.N, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyModProof_MalformedMessage4(t *testing.T) {
	preParams, w, x, a, b, z := prepareModProofT(t)
	message := &KGRound1Message{
		Modproof: &KGRound1Message_ModProof{
			W: w,
			X: x,
			A: a,
			B: b,
			Z: z[:len(z)-1],
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyModProof(message, preParams.PaillierSK.PublicKey.N, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyModProof_Invalid1(t *testing.T) {
	preParams, w, x, a, b, z := prepareModProofT(t)
	x[1] = big.NewInt(1234).Bytes()
	message := &KGRound1Message{
		Modproof: &KGRound1Message_ModProof{
			W: w,
			X: x,
			A: a,
			B: b,
			Z: z,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyModProof(message, preParams.PaillierSK.PublicKey.N, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyModProof_Invalid2(t *testing.T) {
	preParams, w, x, a, b, z := prepareModProofT(t)
	z[1] = big.NewInt(1234).Bytes()
	message := &KGRound1Message{
		Modproof: &KGRound1Message_ModProof{
			W: w,
			X: x,
			A: a,
			B: b,
			Z: z,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyModProof(message, preParams.PaillierSK.PublicKey.N, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyModProof_Invalid3(t *testing.T) {
	preParams, w, x, a, b, z := prepareModProofT(t)
	// When defining x_i, we try false first.
	// If a[i] = true, it means a 4th root does not exist for a[i] = false.
	for i, aa := range a {
		if aa {
			a[i] = false
			break
		}
	}

	message := &KGRound1Message{
		Modproof: &KGRound1Message_ModProof{
			W: w,
			X: x,
			A: a,
			B: b,
			Z: z,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyModProof(message, preParams.PaillierSK.PublicKey.N, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyModProof_Invalid4(t *testing.T) {
	preParams, w, x, a, b, z := prepareModProofT(t)
	// When defining x_i, we try false first.
	// If b[i] = true, it means a 4th root does not exist for b[i] = false.
	for i, bb := range b {
		if bb {
			b[i] = false
			break
		}
	}

	message := &KGRound1Message{
		Modproof: &KGRound1Message_ModProof{
			W: w,
			X: x,
			A: a,
			B: b,
			Z: z,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyModProof(message, preParams.PaillierSK.PublicKey.N, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyModProof_Invalid5(t *testing.T) {
	preParams, _, x, a, b, z := prepareModProofT(t)

	message := &KGRound1Message{
		Modproof: &KGRound1Message_ModProof{
			W: big.NewInt(987654321).Bytes(),
			X: x,
			A: a,
			B: b,
			Z: z,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyModProof(message, preParams.PaillierSK.PublicKey.N, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func TestVerifyModProof_Invalid6(t *testing.T) {
	preParams, w, x, a, b, z := prepareModProofT(t)

	message := &KGRound1Message{
		Modproof: &KGRound1Message_ModProof{
			W: w,
			X: x,
			A: a,
			B: b,
			Z: z,
		},
	}

	verifier := NewProofVerifier(runtime.GOMAXPROCS(0))

	resultChan := make(chan bool)

	verifier.VerifyModProof(message, preParams.PaillierSK.PhiN, func(result bool) {
		resultChan <- result
	})

	success := <-resultChan
	if success {
		t.Fatal("expected negative verification")
	}
}

func prepareModProofT(t *testing.T) (*LocalPreParams, []byte, [][]byte, []bool, []bool, [][]byte) {
	preParams, w, x, a, b, z, err := prepareModProof()
	if err != nil {
		t.Fatal(err)
	}

	return preParams, w, x, a, b, z
}

func prepareModProofB(b *testing.B) (*LocalPreParams, []byte, [][]byte, []bool, []bool, [][]byte) {
	preParams, w, x, a, bb, z, err := prepareModProof()
	if err != nil {
		b.Fatal(err)
	}

	return preParams, w, x, a, bb, z
}

func prepareModProof() (*LocalPreParams, []byte, [][]byte, []bool, []bool, [][]byte, error) {
	localPartySaveData, _, err := LoadKeygenTestFixtures(1)
	if err != nil {
		return nil, []byte{}, [][]byte{}, []bool{}, []bool{}, [][]byte{}, err
	}

	preParams := localPartySaveData[0].LocalPreParams

	proof := preParams.PaillierSK.ModProof()

	return &preParams, proof.W.Bytes(), common.BigIntsToBytes(proof.X[:]), proof.A[:], proof.B[:], common.BigIntsToBytes(proof.Z[:]), nil
}
