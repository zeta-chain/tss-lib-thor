// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	cmt "github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/crypto/vss"
	"github.com/bnb-chain/tss-lib/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-keygen.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*KGRound1Message)(nil),
		(*KGRound2Message1)(nil),
		(*KGRound2Message2)(nil),
		(*KGRound3Message)(nil),
	}
)

// ----- //

func NewKGRound1Message(
	from *tss.PartyID,
	ct cmt.HashCommitment,
	paillierPK *paillier.PublicKey,
	nTildeI, h1I, h2I *big.Int,
	dlnProof1, dlnProof2 *dlnproof.Proof,
	si, ti *big.Int,
	paramProof *paillier.ParamProof,
) (tss.ParsedMessage, error) {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &KGRound1Message{
		Commitment: ct.Bytes(),
		PaillierN:  paillierPK.N.Bytes(),
		NTilde:     nTildeI.Bytes(),
		H1:         h1I.Bytes(),
		H2:         h2I.Bytes(),
		Dlnproof_1: &KGRound1Message_DLNProof{
			Alpha: common.BigIntsToBytes(dlnProof1.Alpha[:]),
			T:     common.BigIntsToBytes(dlnProof1.T[:]),
		},
		Dlnproof_2: &KGRound1Message_DLNProof{
			Alpha: common.BigIntsToBytes(dlnProof2.Alpha[:]),
			T:     common.BigIntsToBytes(dlnProof2.T[:]),
		},
		S: si.Bytes(),
		T: ti.Bytes(),
		Prmproof: &KGRound1Message_ParamProof{
			A: common.BigIntsToBytes(paramProof.A[:]),
			Z: common.BigIntsToBytes(paramProof.Z[:]),
		},
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg), nil
}

func (m *KGRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetCommitment()) &&
		common.NonEmptyBytes(m.GetPaillierN()) &&
		common.NonEmptyBytes(m.GetNTilde()) &&
		common.NonEmptyBytes(m.GetH1()) &&
		common.NonEmptyBytes(m.GetH2()) &&
		m.GetDlnproof_1().ValidateBasic() &&
		m.GetDlnproof_2().ValidateBasic() &&
		common.NonEmptyBytes(m.GetS()) &&
		common.NonEmptyBytes(m.GetT()) &&
		m.GetPrmproof().ValidateBasic()
}

func (m *KGRound1Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

func (m *KGRound1Message) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{N: new(big.Int).SetBytes(m.GetPaillierN())}
}

func (m *KGRound1Message) UnmarshalNTilde() *big.Int {
	return new(big.Int).SetBytes(m.GetNTilde())
}

func (m *KGRound1Message) UnmarshalH1() *big.Int {
	return new(big.Int).SetBytes(m.GetH1())
}

func (m *KGRound1Message) UnmarshalH2() *big.Int {
	return new(big.Int).SetBytes(m.GetH2())
}

func (m *KGRound1Message) UnmarshalDLNProof1() (*dlnproof.Proof, error) {
	p := m.GetDlnproof_1()
	return dlnproof.UnmarshalDLNProof(p.GetAlpha(), p.GetT())
}

func (m *KGRound1Message) UnmarshalDLNProof2() (*dlnproof.Proof, error) {
	p := m.GetDlnproof_2()
	return dlnproof.UnmarshalDLNProof(p.GetAlpha(), p.GetT())
}

func (m *KGRound1Message) UnmarshalS() *big.Int {
	return new(big.Int).SetBytes(m.GetS())
}

func (m *KGRound1Message) UnmarshalT() *big.Int {
	return new(big.Int).SetBytes(m.GetT())
}

func (m *KGRound1Message) UnmarshalParamProof() (*paillier.ParamProof, error) {
	p := m.GetPrmproof()
	return paillier.UnmarshalParamProof(p.GetA(), p.GetZ())
}

func (p *KGRound1Message_DLNProof) ValidateBasic() bool {
	return p != nil &&
		common.NonEmptyMultiBytes(p.GetAlpha(), dlnproof.Iterations) &&
		common.NonEmptyMultiBytes(p.GetT(), dlnproof.Iterations)
}

func (p *KGRound1Message_ParamProof) ValidateBasic() bool {
	return p != nil &&
		common.NonEmptyMultiBytes(p.GetA(), paillier.PARAM_M) &&
		common.NonEmptyMultiBytes(p.GetZ(), paillier.PARAM_M)
}

// ----- //

func NewKGRound2Message1(
	to, from *tss.PartyID,
	share *vss.Share,
	proof *paillier.FactorProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	var facProof *KGRound2Message1_FactorProof
	if proof != nil {
		facProof = &KGRound2Message1_FactorProof{
			P:     common.MarshalSigned(proof.P),
			Q:     common.MarshalSigned(proof.Q),
			A:     common.MarshalSigned(proof.A),
			B:     common.MarshalSigned(proof.B),
			T:     common.MarshalSigned(proof.T),
			Sigma: common.MarshalSigned(proof.Sigma),
			Z1:    common.MarshalSigned(proof.Z1),
			Z2:    common.MarshalSigned(proof.Z2),
			W1:    common.MarshalSigned(proof.W1),
			W2:    common.MarshalSigned(proof.W2),
			V:     common.MarshalSigned(proof.V),
		}
	} else {
		facProof = nil
	}
	content := &KGRound2Message1{
		Share:    share.Share.Bytes(),
		Facproof: facProof,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetShare()) &&
		m.GetFacproof().ValidateBasic()
}

func (m *KGRound2Message1) UnmarshalShare() *big.Int {
	return new(big.Int).SetBytes(m.Share)
}

func (m *KGRound2Message1) UnmarshalFactorProof() *paillier.FactorProof {
	proof := m.GetFacproof()
	return &paillier.FactorProof{
		P:     common.UnmarshalSigned(proof.P),
		Q:     common.UnmarshalSigned(proof.Q),
		A:     common.UnmarshalSigned(proof.A),
		B:     common.UnmarshalSigned(proof.B),
		T:     common.UnmarshalSigned(proof.T),
		Sigma: common.UnmarshalSigned(proof.Sigma),
		Z1:    common.UnmarshalSigned(proof.Z1),
		Z2:    common.UnmarshalSigned(proof.Z2),
		W1:    common.UnmarshalSigned(proof.W1),
		W2:    common.UnmarshalSigned(proof.W2),
		V:     common.UnmarshalSigned(proof.V),
	}
}

func (proof *KGRound2Message1_FactorProof) ValidateBasic() bool {
	return proof != nil &&
		common.NonEmptyBytes(proof.GetP()) &&
		common.NonEmptyBytes(proof.GetQ()) &&
		common.NonEmptyBytes(proof.GetA()) &&
		common.NonEmptyBytes(proof.GetB()) &&
		common.NonEmptyBytes(proof.GetT()) &&
		common.NonEmptyBytes(proof.GetSigma()) &&
		common.NonEmptyBytes(proof.GetZ1()) &&
		common.NonEmptyBytes(proof.GetZ2()) &&
		common.NonEmptyBytes(proof.GetW1()) &&
		common.NonEmptyBytes(proof.GetW2()) &&
		common.NonEmptyBytes(proof.GetV())
}

// ----- //

func NewKGRound2Message2(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	content := &KGRound2Message2{
		DeCommitment: dcBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound2Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetDeCommitment())
}

func (m *KGRound2Message2) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

func NewKGRound3Message(
	from *tss.PartyID,
	proof paillier.Proof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pfBzs := make([][]byte, len(proof))
	for i := range pfBzs {
		if proof[i] == nil {
			continue
		}
		pfBzs[i] = proof[i].Bytes()
	}
	content := &KGRound3Message{
		PaillierProof: pfBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *KGRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetPaillierProof(), paillier.ProofIters)
}

func (m *KGRound3Message) UnmarshalProofInts() paillier.Proof {
	var pf paillier.Proof
	proofBzs := m.GetPaillierProof()
	for i := range pf {
		pf[i] = new(big.Int).SetBytes(proofBzs[i])
	}
	return pf
}
