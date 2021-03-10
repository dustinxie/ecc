// Copyright (c) 2021 dustinxie. All rights reserved.
//
// Use of this source code is governed by MIT license
// that can be found in the LICENSE file.

package ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestRecoverPubkey(t *testing.T) {
	for _, curve := range []elliptic.Curve{
		elliptic.P224(),
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
		P256k1(),
	} {
		privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			panic(err)
		}

		for _, hashed := range [][]byte{
			make([]byte, 64),
			[]byte("testing"),
		} {

			for _, flag := range []byte{
				Ecc_Normal,
				Ecc_LowerS,
				Ecc_RecId,
				Ecc_LowerS | Ecc_RecId,
			} {
				b, err := SignBytes(privKey, hashed, flag)
				if err != nil {
					t.Errorf("SignBytes failed for %T", curve)
				}

				k := testRecoverPubkey(t, curve.Params().Name, hashed, b, flag)
				if k != nil {
					if !privKey.PublicKey.Equal(k[0]) {
						t.Errorf("Recovered pubkey %v not equal %v", k[0], privKey.PublicKey)
					}
					if privKey.PublicKey.Equal(k[1]) {
						t.Errorf("Tampered pubkey %v equal %v", k[1], privKey.PublicKey)
					}
				}
			}
		}
	}
}

// returns 2 pubkeys, first is the correct one, second is a key with tampered r
func testRecoverPubkey(t *testing.T, name string, hash, sig []byte, flag byte) []*ecdsa.PublicKey {
	var (
		k, k1 *ecdsa.PublicKey
		err   error
	)

	k, err = RecoverPubkey(name, hash, sig)
	if flag&Ecc_RecId == 0 {
		if err == nil {
			t.Error("RecoverPubkey pass w/o recovery id")
		}
		return nil
	}

	if err != nil {
		t.Error(err.Error())
		return nil
	}
	if k == nil {
		t.Error("RecoverPubkey returns nil")
		return nil
	}
	if !VerifyBytes(k, hash, sig, flag) {
		t.Error("Recovered pubkey failed verification")
	}

	// invalid recovery id
	size := len(sig)
	v := sig[size-1]
	sig[size-1] = 4
	if _, err = RecoverPubkey(name, hash, sig); err == nil {
		t.Error("RecoverPubkey pass with invalid recovery id")
	}

	// add N to r fails the recovery
	if v <= 1 {
		sig[size-1] = v + 2
		if _, err = RecoverPubkey(name, hash, sig); err == nil {
			t.Error("RecoverPubkey pass with r+N")
		}
	}
	sig[size-1] = v

	// recover another key with tampered r
	rSize := (size - 1) / 2
	r := new(big.Int).SetBytes(sig[:rSize])
	one := big.NewInt(1)
	for {
		r.Add(r, one)
		r.FillBytes(sig[:rSize])
		if k1, err = RecoverPubkey(name, hash, sig); err == nil {
			break
		}
	}

	// tampered key can pass verification as well
	if !VerifyBytes(k1, hash, sig, flag) {
		t.Error("Tampered pubkey failed verification")
	}
	return []*ecdsa.PublicKey{k, k1}
}
