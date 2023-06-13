// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"crypto/elliptic"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	cmt "github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/crypto/vss"
	"github.com/bnb-chain/tss-lib/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-resharing.pb.go

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*DGRound1Message)(nil),
		(*DGRound2Message1)(nil),
		(*DGRound2Message2)(nil),
		(*DGRound3Message1)(nil),
		(*DGRound3Message2)(nil),
	}
)

// ----- //

func NewDGRound1Message(
	to []*tss.PartyID,
	from *tss.PartyID,
	ecdsaPub *crypto.ECPoint,
	vct cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	content := &DGRound1Message{
		EcdsaPubX:   ecdsaPub.X().Bytes(),
		EcdsaPubY:   ecdsaPub.Y().Bytes(),
		VCommitment: vct.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.EcdsaPubX) &&
		common.NonEmptyBytes(m.EcdsaPubY) &&
		common.NonEmptyBytes(m.VCommitment)
}

func (m *DGRound1Message) UnmarshalECDSAPub(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.EcdsaPubX),
		new(big.Int).SetBytes(m.EcdsaPubY))
}

func (m *DGRound1Message) UnmarshalVCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetVCommitment())
}

// ----- //

func NewDGRound2Message1(
	to []*tss.PartyID,
	from *tss.PartyID,
	paillierPK *paillier.PublicKey,
	paillierPf paillier.Proof,
	NTildei, H1i, H2i *big.Int,
	dlnProof1, dlnProof2 *dlnproof.Proof,
	modProof, modProofTilde *paillier.ModProof,
) (tss.ParsedMessage, error) {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	paiPfBzs := common.BigIntsToBytes(paillierPf[:])
	content := &DGRound2Message1{
		PaillierN:     paillierPK.N.Bytes(),
		PaillierProof: paiPfBzs,
		NTilde:        NTildei.Bytes(),
		H1:            H1i.Bytes(),
		H2:            H2i.Bytes(),
		Dlnproof_1: &DGRound2Message1_DLNProof{
			Alpha: common.BigIntsToBytes(dlnProof1.Alpha[:]),
			T:     common.BigIntsToBytes(dlnProof1.T[:]),
		},
		Dlnproof_2: &DGRound2Message1_DLNProof{
			Alpha: common.BigIntsToBytes(dlnProof2.Alpha[:]),
			T:     common.BigIntsToBytes(dlnProof2.T[:]),
		},
		Modproof: &DGRound2Message1_ModProof{
			W: modProof.W.Bytes(),
			X: common.BigIntsToBytes(modProof.X[:]),
			A: modProof.A[:],
			B: modProof.B[:],
			Z: common.BigIntsToBytes(modProof.Z[:]),
		},
		ModproofTilde: &DGRound2Message1_ModProof{
			W: modProofTilde.W.Bytes(),
			X: common.BigIntsToBytes(modProofTilde.X[:]),
			A: modProofTilde.A[:],
			B: modProofTilde.B[:],
			Z: common.BigIntsToBytes(modProofTilde.Z[:]),
		},
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg), nil
}

func (m *DGRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.PaillierProof) &&
		common.NonEmptyBytes(m.PaillierN) &&
		common.NonEmptyBytes(m.NTilde) &&
		common.NonEmptyBytes(m.H1) &&
		common.NonEmptyBytes(m.H2) &&
		m.GetDlnproof_1().ValidateBasic() &&
		m.GetDlnproof_2().ValidateBasic() &&
		m.GetModproof().ValidateBasic() &&
		m.GetModproofTilde().ValidateBasic()
}

func (m *DGRound2Message1) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{
		N: new(big.Int).SetBytes(m.PaillierN),
	}
}

func (m *DGRound2Message1) UnmarshalNTilde() *big.Int {
	return new(big.Int).SetBytes(m.GetNTilde())
}

func (m *DGRound2Message1) UnmarshalH1() *big.Int {
	return new(big.Int).SetBytes(m.GetH1())
}

func (m *DGRound2Message1) UnmarshalH2() *big.Int {
	return new(big.Int).SetBytes(m.GetH2())
}

func (m *DGRound2Message1) UnmarshalPaillierProof() paillier.Proof {
	var pf paillier.Proof
	ints := common.MultiBytesToBigInts(m.PaillierProof)
	copy(pf[:], ints[:paillier.ProofIters])
	return pf
}

func (m *DGRound2Message1) UnmarshalDLNProof1() (*dlnproof.Proof, error) {
	p := m.GetDlnproof_1()
	return dlnproof.UnmarshalDLNProof(p.GetAlpha(), p.GetT())
}

func (m *DGRound2Message1) UnmarshalDLNProof2() (*dlnproof.Proof, error) {
	p := m.GetDlnproof_2()
	return dlnproof.UnmarshalDLNProof(p.GetAlpha(), p.GetT())
}

func (m *DGRound2Message1) UnmarshalModProof() (*paillier.ModProof, error) {
	p := m.GetModproof()
	return paillier.UnmarshalModProof(p.GetW(), p.GetX(), p.GetA(), p.GetB(), p.GetZ())
}

func (m *DGRound2Message1) UnmarshalModProofTilde() (*paillier.ModProof, error) {
	p := m.GetModproofTilde()
	return paillier.UnmarshalModProof(p.GetW(), p.GetX(), p.GetA(), p.GetB(), p.GetZ())
}

func (p *DGRound2Message1_DLNProof) ValidateBasic() bool {
	return p != nil &&
		common.NonEmptyMultiBytes(p.GetAlpha(), dlnproof.Iterations) &&
		common.NonEmptyMultiBytes(p.GetT(), dlnproof.Iterations)
}

func (p *DGRound2Message1_ModProof) ValidateBasic() bool {
	return p != nil &&
		common.NonEmptyBytes(p.GetW()) &&
		common.NonEmptyMultiBytes(p.GetX(), paillier.PARAM_M) &&
		common.NonEmptyBools(p.GetA(), paillier.PARAM_M) &&
		common.NonEmptyBools(p.GetB(), paillier.PARAM_M) &&
		common.NonEmptyMultiBytes(p.GetZ(), paillier.PARAM_M)
}

// ----- //

func NewDGRound2Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: true,
	}
	content := &DGRound2Message2{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound2Message2) ValidateBasic() bool {
	return true
}

// ----- //

func NewDGRound3Message1(
	to *tss.PartyID,
	from *tss.PartyID,
	share *vss.Share,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               []*tss.PartyID{to},
		IsBroadcast:      false,
		IsToOldCommittee: false,
	}
	content := &DGRound3Message1{
		Share: share.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound3Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Share)
}

// ----- //

func NewDGRound3Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
	vdct cmt.HashDeCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	vDctBzs := common.BigIntsToBytes(vdct)
	content := &DGRound3Message2{
		VDecommitment: vDctBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound3Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.VDecommitment)
}

func (m *DGRound3Message2) UnmarshalVDeCommitment() cmt.HashDeCommitment {
	deComBzs := m.GetVDecommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

func NewDGRound4Message1(
	to *tss.PartyID,
	from *tss.PartyID,
	proof, proofTilde *paillier.FactorProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               []*tss.PartyID{to},
		IsBroadcast:      false,
		IsToOldCommittee: false,
	}
	var facProof *DGRound4Message1_FactorProof
	if proof != nil {
		facProof = &DGRound4Message1_FactorProof{
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
		// The proof is nil when creating the self-message in round 2.
		facProof = nil
	}
	var facProofTilde *DGRound4Message1_FactorProof
	if proofTilde != nil {
		facProofTilde = &DGRound4Message1_FactorProof{
			P:     common.MarshalSigned(proofTilde.P),
			Q:     common.MarshalSigned(proofTilde.Q),
			A:     common.MarshalSigned(proofTilde.A),
			B:     common.MarshalSigned(proofTilde.B),
			T:     common.MarshalSigned(proofTilde.T),
			Sigma: common.MarshalSigned(proofTilde.Sigma),
			Z1:    common.MarshalSigned(proofTilde.Z1),
			Z2:    common.MarshalSigned(proofTilde.Z2),
			W1:    common.MarshalSigned(proofTilde.W1),
			W2:    common.MarshalSigned(proofTilde.W2),
			V:     common.MarshalSigned(proofTilde.V),
		}
	} else {
		// The proof is nil when creating the self-message in round 2.
		facProofTilde = nil
	}
	content := &DGRound4Message1{
		Facproof: facProof,
		FacproofTilde: facProofTilde,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound4Message1) ValidateBasic() bool {
	return m != nil &&
		m.GetFacproof().ValidateBasic() &&
		m.GetFacproofTilde().ValidateBasic()
}

func (m *DGRound4Message1) UnmarshalFactorProof() *paillier.FactorProof {
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

func (m *DGRound4Message1) UnmarshalFactorProofTilde() *paillier.FactorProof {
	proof := m.GetFacproofTilde()
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

func (proof *DGRound4Message1_FactorProof) ValidateBasic() bool {
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

func NewDGRound4Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:                    from,
		To:                      to,
		IsBroadcast:             true,
		IsToOldAndNewCommittees: true,
	}
	content := &DGRound4Message2{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound4Message2) ValidateBasic() bool {
	return true
}
