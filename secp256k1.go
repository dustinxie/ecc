// Copyright (c) 2021 dustinxie. All rights reserved.
//
// Use of this source code is governed by MIT license
// that can be found in the LICENSE file.

package ecc

import (
	"crypto/elliptic"
	"math/big"
)

var secp256k1 secp256k1Curve

type secp256k1Curve struct {
	*CurveParams
}

func initSecp256k1() {
	// See https://www.secg.org/sec2-v2.pdf, section 2.4.1
	// curve equation y² = x³ + 7
	gop256k1 := elliptic.CurveParams{Name: "P-256k1"}
	gop256k1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	gop256k1.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	gop256k1.B = big.NewInt(7)
	gop256k1.Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	gop256k1.Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	gop256k1.BitSize = 256

	secp256k1.CurveParams = &CurveParams{
		CurveParams: gop256k1,
		A:           new(big.Int),
	}
}
