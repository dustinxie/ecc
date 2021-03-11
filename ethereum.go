// Copyright (c) 2021 dustinxie. All rights reserved.
//
// Use of this source code is governed by MIT license
// that can be found in the LICENSE file.

package ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
)

// errors
var (
	ErrInvalidLength = errors.New("Invalid hash or signature length")
)

// SignEthereum returns an Ethereum-compatible signature
// The produced signature is in the 65-byte [R || S || V] format
//
// This function is susceptible to chosen plaintext attackes. The
// caller is responsible to ensure that the given hash cannot be
// chosen directly by an attacker. Common solution is to hash any
// input before calculating the signature
func SignEthereum(hash []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	if len(hash) != 32 {
		return nil, ErrInvalidLength
	}
	return SignBytes(priv, hash, LowerS|RecID)
}

// VerifyEthereum verifies an Ethereum signature
// The public key is either compressed (33-byte) or uncompressed (65-byte)
// format, and the signature should have the 64-byte [R || S] format
//
// ECDSA malleability issue:
// For an ECDSA signature (r, s, v), it can be shown that (r, N-s, v^1)
// is also a valid signature that can correctly recover the public key.
// Mathematically, this is not a problem but could cause issue where the
// uniqueness of signature is required for better security
//
// Ethereum handled this issue by requiring the s value to be in the lower
// half of N (the order of the curve) starting the Homestead hard-fork
// see https://eips.ethereum.org/EIPS/eip-2
// To be specific, the value of s needs to satisfy:
// 1 <= s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
// signature with a higher s value will be rejected
//
// For signature before the Homestead hard-fork, call with isHomestead = false
func VerifyEthereum(pubkey, hash, sig []byte, isHomestead bool) bool {
	keyLen := len(pubkey)
	if len(hash) != 32 || len(sig) != 64 {
		return false
	}

	var (
		x, y  *big.Int
		curve = P256k1()
	)
	if keyLen == 33 {
		x, y = UnmarshalCompressed(curve, pubkey)
	} else {
		x, y = elliptic.Unmarshal(curve, pubkey)
	}
	if x == nil || y == nil {
		return false
	}

	pk := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	flag := Normal
	if isHomestead {
		flag = LowerS
	}
	return VerifyBytes(pk, hash, sig, flag)
}

// RecoverEthereum returns the public key of the signer
//
// signature must be the 65-byte [R || S || V] format with
// recovery id as the last byte
func RecoverEthereum(hash, sig []byte) ([]byte, error) {
	if len(hash) != 32 || len(sig) != 65 {
		return nil, ErrInvalidLength
	}
	curve := P256k1()
	pk, err := RecoverPubkey(curve.Params().Name, hash, sig)
	if err != nil {
		return nil, err
	}
	return elliptic.Marshal(curve, pk.X, pk.Y), nil
}
