// Copyright (c) 2021 dustinxie. All rights reserved.
//
// Use of this source code is governed by MIT license
// that can be found in the LICENSE file.

package ecc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestEther(t *testing.T) {
	curve := P256k1()
	param := curve.Params()
	for i := 0; i < 16; i++ {
		privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			panic(err)
		}

		msg := sha256.Sum256(privKey.PublicKey.X.Bytes())
		sig, err := SignEthereum(msg[:], privKey)
		if err != nil {
			t.Errorf("SignEthereum failed for %T", curve)
		}

		// verify both uncompressed and compressed public key
		pubkey := make([][]byte, 2)
		pubkey[0] = elliptic.Marshal(curve, privKey.X, privKey.Y)
		pubkey[1] = elliptic.MarshalCompressed(curve, privKey.X, privKey.Y)
		for _, pk := range pubkey {
			if VerifyEthereum(pk[:len(pk)-1], msg[:], sig[:64], false) {
				t.Error("VerifyEthereum passed with wrong public key length")
			}
			if VerifyEthereum(pk, msg[:31], sig[:64], false) {
				t.Error("VerifyEthereum passed with wrong msg length")
			}
			if VerifyEthereum(pk, msg[:], sig, false) {
				t.Error("VerifyEthereum passed with wrong sig length")
			}
			if !VerifyEthereum(pk, msg[:], sig[:64], false) {
				t.Error("VerifyEthereum failed")
			}
			if !VerifyEthereum(pk, msg[:], sig[:64], true) {
				t.Error("VerifyEthereum failed")
			}
			r, s, _ := decodeSigBytes(param, sig)
			s.Sub(param.N, s)
			rs := make([]byte, 64)
			r.FillBytes(rs[:32])
			s.FillBytes(rs[32:])
			if !VerifyEthereum(pk, msg[:], rs, false) {
				t.Error("VerifyEthereum failed")
			}
			if VerifyEthereum(pk, msg[:], rs, true) {
				t.Error("VerifyEthereum passed with higher s value")
			}
		}

		pk, err := RecoverEthereum(msg[:], sig)
		if err != nil {
			t.Error("RecoverEthereum failed")
		}
		if bytes.Compare(pk, pubkey[0]) != 0 {
			t.Errorf("Recovered key %x not equal to %x", pk, pubkey[0])
		}
	}
}
