// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"encoding/hex"
	"errors"
	"math/big"
	"sync"

	errors2 "github.com/pkg/errors"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/crypto/vss"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK

	round.allOldOK()

	if !round.ReSharingParams().IsNewCommittee() {
		// both committees proceed to round 5 after receiving "ACK" messages from the new committee
		return nil
	}

	common.Logger.Debugf(
		"%s Setting up DLN verification with concurrency level of %d",
		round.PartyID(),
		round.Concurrency(),
	)
	verifier := keygen.NewProofVerifier(round.Concurrency())

	Pi := round.PartyID()
	i := Pi.Index

	// 1-3. verify paillier & dln proofs, store message pieces, ensure uniqueness of h1j, h2j
	h1H2Map := make(map[string]struct{}, len(round.temp.dgRound2Message1s)*2)
	paiProofCulprits := make([]*tss.PartyID, len(round.temp.dgRound2Message1s)) // who caused the error(s)
	dlnProof1FailCulprits := make([]*tss.PartyID, len(round.temp.dgRound2Message1s))
	dlnProof2FailCulprits := make([]*tss.PartyID, len(round.temp.dgRound2Message1s))
	modProofFailCulprits := make([]*tss.PartyID, len(round.temp.dgRound2Message1s))
	modProofTildeFailCulprits := make([]*tss.PartyID, len(round.temp.dgRound2Message1s))
	wg := new(sync.WaitGroup)
	for j, msg := range round.temp.dgRound2Message1s {
		r2msg1 := msg.Content().(*DGRound2Message1)
		paiPK, NTildej, H1j, H2j :=
			r2msg1.UnmarshalPaillierPK(),
			r2msg1.UnmarshalNTilde(),
			r2msg1.UnmarshalH1(),
			r2msg1.UnmarshalH2()
		if H1j.Cmp(H2j) == 0 {
			return round.WrapError(errors.New("h1j and h2j were equal for this party"), msg.GetFrom())
		}
		h1JHex, h2JHex := hex.EncodeToString(H1j.Bytes()), hex.EncodeToString(H2j.Bytes())
		if _, found := h1H2Map[h1JHex]; found {
			return round.WrapError(errors.New("this h1j was already used by another party"), msg.GetFrom())
		}
		if _, found := h1H2Map[h2JHex]; found {
			return round.WrapError(errors.New("this h2j was already used by another party"), msg.GetFrom())
		}
		h1H2Map[h1JHex], h1H2Map[h2JHex] = struct{}{}, struct{}{}
		wg.Add(5)
		go func(j int, msg tss.ParsedMessage, r2msg1 *DGRound2Message1) {
			if ok, err := r2msg1.UnmarshalPaillierProof().Verify(paiPK.N, msg.GetFrom().KeyInt(), round.save.ECDSAPub); err != nil || !ok {
				paiProofCulprits[j] = msg.GetFrom()
				common.Logger.Warningf("paillier verify failed for party %s", msg.GetFrom(), err)
			}
			wg.Done()
		}(j, msg, r2msg1)
		_j := j
		_msg := msg
		verifier.VerifyDLNProof1(r2msg1, H1j, H2j, NTildej, func(isValid bool) {
			if !isValid {
				dlnProof1FailCulprits[_j] = _msg.GetFrom()
				common.Logger.Warningf("dln proof 1 verify failed for party %s", _msg.GetFrom())
			}
			wg.Done()
		})
		verifier.VerifyDLNProof2(r2msg1, H2j, H1j, NTildej, func(isValid bool) {
			if !isValid {
				dlnProof2FailCulprits[_j] = _msg.GetFrom()
				common.Logger.Warningf("dln proof 2 verify failed for party %s", _msg.GetFrom())
			}
			wg.Done()
		})
		verifier.VerifyModProof(r2msg1, paiPK.N, func(isValid bool) {
			if !isValid {
				modProofFailCulprits[_j] = _msg.GetFrom()
				common.Logger.Warningf("mod proof verify failed for party %s", _msg.GetFrom())
			}
			wg.Done()
		})
		verifier.VerifyModProofTilde(r2msg1, NTildej, func(isValid bool) {
			if !isValid {
				modProofFailCulprits[_j] = _msg.GetFrom()
				common.Logger.Warningf("mod proof tilde verify failed for party %s", _msg.GetFrom())
			}
			wg.Done()
		})
	}
	wg.Wait()
	for _, culprit := range append(append(paiProofCulprits, dlnProof1FailCulprits...), dlnProof2FailCulprits...) {
		if culprit != nil {
			return round.WrapError(errors.New("dln proof verification failed"), culprit)
		}
	}
	for _, culprit := range append(modProofFailCulprits, modProofTildeFailCulprits...) {
		if culprit != nil {
			return round.WrapError(errors.New("mod proof verification failed"), culprit)
		}
	}
	// save NTilde_j, h1_j, h2_j received in NewCommitteeStep1 here
	for j, msg := range round.temp.dgRound2Message1s {
		if j == i {
			continue
		}
		r2msg1 := msg.Content().(*DGRound2Message1)
		round.save.NTildej[j] = new(big.Int).SetBytes(r2msg1.NTilde)
		round.save.H1j[j] = new(big.Int).SetBytes(r2msg1.H1)
		round.save.H2j[j] = new(big.Int).SetBytes(r2msg1.H2)
	}

	// 4.
	newXi := big.NewInt(0)

	// 5-9.
	modQ := common.ModInt(round.Params().EC().Params().N)
	vjc := make([][]*crypto.ECPoint, len(round.OldParties().IDs()))
	for j := 0; j <= len(vjc)-1; j++ { // P1..P_t+1. Ps are indexed from 0 here
		// 6-7.
		r1msg := round.temp.dgRound1Messages[j].Content().(*DGRound1Message)
		r3msg2 := round.temp.dgRound3Message2s[j].Content().(*DGRound3Message2)

		vCj, vDj := r1msg.UnmarshalVCommitment(), r3msg2.UnmarshalVDeCommitment()

		// 6. unpack flat "v" commitment content
		vCmtDeCmt := commitments.HashCommitDecommit{C: vCj, D: vDj}
		ok, flatVs := vCmtDeCmt.DeCommit()
		if !ok || len(flatVs) != (round.NewThreshold()+1)*2 { // they're points so * 2
			// TODO collect culprits and return a list of them as per convention
			return round.WrapError(errors.New("de-commitment of v_j0..v_jt failed"), round.Parties().IDs()[j])
		}
		vj, err := crypto.UnFlattenECPoints(round.Params().EC(), flatVs)
		if err != nil {
			return round.WrapError(err, round.Parties().IDs()[j])
		}
		vjc[j] = vj

		// 8.
		r3msg1 := round.temp.dgRound3Message1s[j].Content().(*DGRound3Message1)
		sharej := &vss.Share{
			Threshold: round.NewThreshold(),
			ID:        round.PartyID().KeyInt(),
			Share:     new(big.Int).SetBytes(r3msg1.Share),
		}
		if ok := sharej.Verify(round.Params().EC(), round.NewThreshold(), vj); !ok {
			// TODO collect culprits and return a list of them as per convention
			return round.WrapError(errors.New("share from old committee did not pass Verify()"), round.Parties().IDs()[j])
		}

		// 9.
		newXi = new(big.Int).Add(newXi, sharej.Share)
	}

	// 10-13.
	var err error
	Vc := make([]*crypto.ECPoint, round.NewThreshold()+1)
	for c := 0; c <= round.NewThreshold(); c++ {
		Vc[c] = vjc[0][c]
		for j := 1; j <= len(vjc)-1; j++ {
			Vc[c], err = Vc[c].Add(vjc[j][c])
			if err != nil {
				return round.WrapError(errors2.Wrapf(err, "Vc[c].Add(vjc[j][c])"))
			}
		}
	}

	// 14.
	if !Vc[0].Equals(round.save.ECDSAPub) {
		return round.WrapError(errors.New("assertion failed: V_0 != y"), round.PartyID())
	}

	// 15-19.
	newKs := make([]*big.Int, 0, round.NewPartyCount())
	newBigXjs := make([]*crypto.ECPoint, round.NewPartyCount())
	paiProofCulprits = make([]*tss.PartyID, 0, round.NewPartyCount()) // who caused the error(s)
	for j := 0; j < round.NewPartyCount(); j++ {
		Pj := round.NewParties().IDs()[j]
		kj := Pj.KeyInt()
		newBigXj := Vc[0]
		newKs = append(newKs, kj)
		z := new(big.Int).SetInt64(int64(1))
		for c := 1; c <= round.NewThreshold(); c++ {
			z = modQ.Mul(z, kj)
			newBigXj, err = newBigXj.Add(Vc[c].ScalarMult(z))
			if err != nil {
				paiProofCulprits = append(paiProofCulprits, Pj)
			}
		}
		newBigXjs[j] = newBigXj
	}
	if len(paiProofCulprits) > 0 {
		return round.WrapError(errors2.Wrapf(err, "newBigXj.Add(Vc[c].ScalarMult(z))"), paiProofCulprits...)
	}

	for j, Pj := range round.NewParties().IDs() {

		if common.Eq(Pi.KeyInt(), Pj.KeyInt()) {
			round.temp.dgRound4Message1s[j] = NewDGRound4Message1(Pj, Pi, nil, nil)
		}

		// Add factor proofs
		H1j, H2j, NTildej := round.save.H1j[j], round.save.H2j[j], round.save.NTildej[j]
		facProof := round.save.LocalPreParams.PaillierSK.FactorProof(NTildej, H1j, H2j)
		facProofTilde := round.temp.skTilde.FactorProof(NTildej, H1j, H2j)

		r4msg1 := NewDGRound4Message1(Pj, Pi, facProof, facProofTilde)
		round.out <- r4msg1
	}

	round.temp.newXi = newXi
	round.temp.newKs = newKs
	round.temp.newBigXjs = newBigXjs

	// Send an "ACK" message to both committees to signal that we're ready to save our data
	r4msg := NewDGRound4Message2(round.OldAndNewParties(), Pi)
	round.temp.dgRound4Message2s[i] = r4msg
	round.out <- r4msg

	return nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*DGRound4Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*DGRound4Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	if round.ReSharingParameters.IsNewCommittee() {
		// accept messages from new -> everyone
		for j, msg1 := range round.temp.dgRound4Message2s {
			if round.newOK[j] {
				continue
			}
			if msg1 == nil || !round.CanAccept(msg1) {
				return false, nil
			}
			// accept message from new -> new committee
			msg2 := round.temp.dgRound4Message1s[j]
			if msg2 == nil || !round.CanAccept(msg2) {
				return false, nil
			}
			round.newOK[j] = true
		}
	} else if round.ReSharingParams().IsOldCommittee() {
		// accept messages from new -> old committee
		for j, msg := range round.temp.dgRound4Message2s {
			if round.newOK[j] {
				continue
			}
			if msg == nil || !round.CanAccept(msg) {
				return false, nil
			}
			round.newOK[j] = true
		}
	} else {
		return false, round.WrapError(errors.New("this party is not in the old or the new committee"), round.PartyID())
	}
	return true, nil
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &round5{round}
}
