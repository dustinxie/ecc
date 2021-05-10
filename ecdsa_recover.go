// Copyright (c) 2021 dustinxie. All rights reserved.
//
// Use of this source code is governed by MIT license
// that can be found in the LICENSE file.

package ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

// RecoverPubkey recovers the public key from the signature
func RecoverPubkey(name string, hash, sig []byte) (*ecdsa.PublicKey, error) {
	var (
		curve elliptic.Curve
		A     = big.NewInt(-3)
	)
	switch name {
	case "P-224":
		curve = elliptic.P224()
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	case "P-256k1":
		curve = P256k1()
		A = new(big.Int)
	default:
		return nil, fmt.Errorf("Curve %s is not supported", name)
	}

	// check signature size
	param := curve.Params()
	rSize := (param.BitSize + 7) >> 3
	size := len(sig)
	if size != 2*rSize+1 {
		return nil, fmt.Errorf("Invalid signature size, expecting %d, actual %d", 2*rSize+1, size)
	}

	// check recovery id
	v := sig[size-1]
	if v > 3 {
		return nil, fmt.Errorf("Invalid recovery id %d", v)
	}

	// extract (r, s)
	sig = sig[:size-1]
	r := new(big.Int).SetBytes(sig[:rSize])
	s := new(big.Int).SetBytes(sig[rSize:])

	// verify 0 < r, s < N
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return nil, errZeroParam
	}
	if r.Cmp(param.N) >= 0 || s.Cmp(param.N) >= 0 {
		return nil, fmt.Errorf("Signature (%s, %s) exceeds group order", r.String(), s.String())
	}

	// compute point R = (r, y) = kG
	var y *big.Int
	r, y = computePointFromX(param, A, r, v)
	if y == nil {
		return nil, fmt.Errorf("X-coordinate %s is not on curve %s", r.String(), name)
	}

	// key recovery
	return recoverPubkey(curve, hashToInt(hash, curve), r, y, s)
}

func computePointFromX(param *elliptic.CurveParams, A, x *big.Int, recid byte) (*big.Int, *big.Int) {
	if recid >= 2 {
		x.Add(param.N, x)
		if x.Cmp(param.P) >= 0 {
			return x, nil
		}
	}
	x3 := new(big.Int).Mul(x, x)
	x3.Add(x3, A)       // x² + a
	x3.Mul(x3, x)       // x³ + ax
	x3.Add(x3, param.B) // x³ + ax + b

	if x3.ModSqrt(x3, param.P) == nil {
		return x, nil
	}
	if byte(x3.Bit(0)) != recid&1 {
		x3.Sub(param.P, x3)
	}
	return x, x3
}

func recoverPubkey(curve elliptic.Curve, e, r, y, s *big.Int) (*ecdsa.PublicKey, error) {
	param := curve.Params()
	var w *big.Int
	if in, ok := curve.(invertible); ok {
		w = in.Inverse(r)
	} else {
		w = new(big.Int).ModInverse(r, param.N)
	}

	e.Sub(param.N, e)
	u1 := e.Mul(e, w)
	u1.Mod(u1, param.N)
	u2 := w.Mul(s, w)
	u2.Mod(u2, param.N)

	// Check if implements S1*g + S2*p
	if opt, ok := curve.(combinedMult); ok {
		e, s = opt.CombinedMult(r, y, u1.Bytes(), u2.Bytes())
	} else {
		x1, y1 := curve.ScalarBaseMult(u1.Bytes())
		x2, y2 := curve.ScalarMult(r, y, u2.Bytes())
		e, s = curve.Add(x1, y1, x2, y2)
	}

	if e.Sign() <= 0 || s.Sign() <= 0 {
		return nil, fmt.Errorf("Invalid public key (%s, %s)", s.String(), w.String())
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     e,
		Y:     s,
	}, nil
}
