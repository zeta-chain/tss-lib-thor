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

	round.allOldOK()

	Pi := round.PartyID()
	i := Pi.Index

	if !round.IsNewCommittee() {
		if round.IsOldCommittee() {
			round.input.Xi.SetInt64(0)
			round.allNewOK()
		}
		round.end <- *round.save
		return nil
	}

	// 21.
	// for this P: SAVE data
	round.save.BigXj = round.temp.newBigXjs
	round.save.ShareID = round.PartyID().KeyInt()
	round.save.Xi = round.temp.newXi
	round.save.Ks = round.temp.newKs

	// misc: build list of paillier public keys to save
	for j, msg := range round.temp.dgRound2Message1s {
		if j == i {
			continue
		}
		r2msg1 := msg.Content().(*DGRound2Message1)
		round.save.PaillierPKs[j] = r2msg1.UnmarshalPaillierPK()
	}

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
			pkN := round.save.PaillierPKs[j].N
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
				round.newOK[j] = true
				continue
			}
			proofResults[j] = <-chs[j]
			if err := proofResults[j].unWrappedErr; err != nil {
				culprits = append(culprits, Pj)
			} else {
				round.newOK[j] = true
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

	round.end <- *round.save
	return nil
}

func (round *round5) CanAccept(msg tss.ParsedMessage) bool {
	return false
}

func (round *round5) Update() (bool, *tss.Error) {
	return false, nil
}

func (round *round5) NextRound() tss.Round {
	return nil // both committees are finished!
}
