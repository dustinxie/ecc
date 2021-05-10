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
				Normal,
				LowerS,
				RecID,
				LowerS | RecID,
			} {
				b, err := SignBytes(privKey, hashed, flag)
				if err != nil {
					t.Errorf("SignBytes failed for %T", curve)
				}

				k := testRecoverPubkey(t, curve.Params(), hashed, b, flag)
				if k != nil {
					if !privKey.PublicKey.Equal(k) {
						t.Errorf("Recovered pubkey %v not equal %v", k, privKey.PublicKey)
					}
				}
			}
		}
	}
}

// returns 2 pubkeys, first is the correct one, second is a key with tampered r
func testRecoverPubkey(t *testing.T, param *elliptic.CurveParams, hash, sig []byte, flag byte) *ecdsa.PublicKey {
	var (
		k, k1 *ecdsa.PublicKey
		err   error
	)

	k, err = RecoverPubkey(param.Name, hash, sig)
	if flag&RecID == 0 {
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
	if _, err = RecoverPubkey(param.Name, hash, sig); err == nil {
		t.Error("RecoverPubkey pass with invalid recovery id")
	}

	// add N to r fails the recovery
	if v <= 1 {
		sig[size-1] = v + 2
		if _, err = RecoverPubkey(param.Name, hash, sig); err == nil {
			t.Error("RecoverPubkey pass with r+N")
		}
	}

	// flipping the v, that is (r, s, v^1) will generate a different key
	sig[size-1] = v ^ 1
	if k1, err = RecoverPubkey(param.Name, hash, sig); err != nil {
		t.Error("RecoverPubkey fail flipping")
	}

	// this key can pass verification as well
	if !VerifyBytes(k1, hash, sig, flag) {
		t.Error("Flipped pubkey failed verification")
	}

	// but not equal to correct key
	if k1.Equal(k) {
		t.Errorf("Flipped pubkey %v equal %v", k1, k)
	}

	// ECDSA signature malleability: (r, N-s, v^1) is also a valid signature
	rSize := (size - 1) / 2
	s := new(big.Int).SetBytes(sig[rSize : 2*rSize])
	s.Sub(param.N, s).FillBytes(sig[rSize : 2*rSize])
	if k1, err = RecoverPubkey(param.Name, hash, sig); err != nil {
		t.Error("RecoverPubkey fail flipping")
	}
	if !k.Equal(k1) {
		t.Errorf("Flipped pubkey %v not equal %v", k, k1)
	}

	return k
}
