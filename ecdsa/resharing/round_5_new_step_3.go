// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"errors"

	"github.com/hashicorp/go-multierror"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/tss"
)

func (round *round5) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK

	round.allOldOK()

	if !round.IsNewCommittee() {
		// both committees proceed to round 6 after receiving "ACK" messages from the new committee
		return nil
	}

	Pi := round.PartyID()
	i := Pi.Index

	Ps := round.NewParties().IDs()

	type proofOut struct {
		unWrappedErr error
	}
	chs := make([]chan proofOut, len(Ps))
	for j, Pj := range Ps {
		if common.Eq(Pi.KeyInt(), Pj.KeyInt()) {
			continue
		}
		chs[j] = make(chan proofOut)
	}
	for j, Pj := range Ps {
		if common.Eq(Pi.KeyInt(), Pj.KeyInt()) {
			continue
		}
		go func(j int, ch chan<- proofOut) {
			r4msg1 := round.temp.dgRound4Message1s[j].Content().(*DGRound4Message1)

			FacProof := r4msg1.UnmarshalFactorProof()

			r2msg1 := round.temp.dgRound2Message1s[j].Content().(*DGRound2Message1)
			pk := r2msg1.UnmarshalPaillierPK()
			pkN := pk.N
			NTilde := round.save.LocalPreParams.NTildei
			H1i, H2i := round.save.LocalPreParams.H1i, round.save.LocalPreParams.H2i
			ok, err := FacProof.FactorVerify(pkN, NTilde, H1i, H2i)
			if err != nil {
				ch <- proofOut{err}
			}
			if !ok {
				ch <- proofOut{errors.New("factor proof verify failed")}
			}
			FacProofTilde := r4msg1.UnmarshalFactorProofTilde()
			NTildej := round.save.NTildej[j]
			ok, err = FacProofTilde.FactorVerify(NTildej, NTilde, H1i, H2i)
			if err != nil {
				ch <- proofOut{err}
			}
			if !ok {
				ch <- proofOut{errors.New("factor proof verify failed")}
			}
			// (9) handled above
			ch <- proofOut{nil}
		}(j, chs[j])
	}

	proofResults := make([]proofOut, len(Ps))
	{
		culprits := make([]*tss.PartyID, 0, len(Ps))
		for j, Pj := range Ps {
			if common.Eq(Pi.KeyInt(), Pj.KeyInt()) {
				continue
			}
			proofResults[j] = <-chs[j]
			if err := proofResults[j].unWrappedErr; err != nil {
				culprits = append(culprits, Pj)
			}
		}
		var multiErr error
		if len(culprits) > 0 {
			for _, proofResult := range proofResults {
				if proofResult.unWrappedErr == nil {
					continue
				}
				multiErr = multierror.Append(multiErr, proofResult.unWrappedErr)
			}
			return round.WrapError(multiErr, culprits...)
		}
	}

	r5msg := NewDGRound5Message(round.OldAndNewParties(), Pi)
	round.temp.dgRound5Messages[i] = r5msg
	round.out <- r5msg
	return nil
}

func (round *round5) CanAccept(msg tss.ParsedMessage) bool {
	// accept messages from new -> both committees
	if _, ok := msg.Content().(*DGRound5Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round5) Update() (bool, *tss.Error) {
	if round.ReSharingParameters.IsNewCommittee() || round.ReSharingParams().IsOldCommittee() {
		// accept messages from new -> everyone
		for j, msg := range round.temp.dgRound5Messages {
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

func (round *round5) NextRound() tss.Round {
	round.started = false
	return &round6{round}
}
