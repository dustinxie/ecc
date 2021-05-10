// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as
// defined in FIPS 186-3.
//
// This implementation derives the nonce from an AES-CTR CSPRNG keyed by:
//
// SHA2-512(priv.D || entropy || hash)[:32]
//
// The CSPRNG key is indifferentiable from a random oracle as shown in
// [Coron], the AES-CTR stream is indifferentiable from a random oracle
// under standard cryptographic assumptions (see [Larsson] for examples).
//
// References:
//   [Coron]
//     https://cs.nyu.edu/~dodis/ps/merkle.pdf
//   [Larsson]
//     https://www.nada.kth.se/kurser/kth/2D1441/semteo03/lecturenotes/assump.pdf
package ecc

// Further references:
//   [NSA]: Suite B implementer's guide to FIPS 186-3
//     https://apps.nsa.gov/iaarchive/library/ia-guidance/ia-solutions-for-classified/algorithm-guidance/suite-b-implementers-guide-to-fips-186-3-ecdsa.cfm
//   [SECG]: SECG, SEC1
//     http://www.secg.org/sec1-v2.pdf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
	"math/big"
)

// A invertible implements fast inverse mod Curve.Params().N
type invertible interface {
	// Inverse returns the inverse of k in GF(P)
	Inverse(k *big.Int) *big.Int
}

// combinedMult implements fast multiplication S1*g + S2*p (g - generator, p - arbitrary point)
type combinedMult interface {
	CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int)
}

const (
	aesIV = "IV for ECDSA CTR"
)

var one = new(big.Int).SetInt64(1)

// randFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method.
// This has better constant-time properties than Euclid's method (implemented
// in math/big.Int.ModInverse) although math/big itself isn't strictly
// constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

var errZeroParam = errors.New("zero parameter")

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the signature as a pair of integers. The security of the private key
// depends on the entropy of rand.
func Sign(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, recid byte, err error) {
	MaybeReadByte(rand)

	// Get min(log2(q) / 2, 256) bits of entropy from rand.
	entropylen := (priv.Curve.Params().BitSize + 7) / 16
	if entropylen > 32 {
		entropylen = 32
	}
	entropy := make([]byte, entropylen)
	_, err = io.ReadFull(rand, entropy)
	if err != nil {
		return
	}

	// Initialize an SHA-512 hash context; digest ...
	md := sha512.New()
	md.Write(priv.D.Bytes()) // the private key,
	md.Write(entropy)        // the entropy,
	md.Write(hash)           // and the input hash;
	key := md.Sum(nil)[:32]  // and compute ChopMD-256(SHA-512),
	// which is an indifferentiable MAC.

	// Create an AES-CTR instance to use as a CSPRNG.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, 0, err
	}

	// Create a CSPRNG that xors a stream of zeros with
	// the output of the AES-CTR instance.
	csprng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	// See [NSA] 3.4.1
	c := priv.PublicKey.Curve
	return sign(priv, &csprng, c, hash)
}

// sign also returns a byte (recovery id) for public key recovery
// let (x, y) be the co-ordinate of point R = k*G
// recid = 0: x = r, y is even
// recid = 1: x = r, y is odd
// recid = 2: x = r+N, y is even
// recid = 3: x = r+N, y is odd
func sign(priv *ecdsa.PrivateKey, csprng *cipher.StreamReader, c elliptic.Curve, hash []byte) (r, s *big.Int, recid byte, err error) {
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, 0, errZeroParam
	}
	var k, kInv, y *big.Int
	for {
		for {
			k, err = randFieldElement(c, *csprng)
			if err != nil {
				r = nil
				return
			}

			if in, ok := priv.Curve.(invertible); ok {
				kInv = in.Inverse(k)
			} else {
				kInv = fermatInverse(k, N) // N != 0
			}

			r, y = priv.Curve.ScalarBaseMult(k.Bytes())
			if r.Cmp(N) == 1 {
				// note this is exceedingly rare, the chance of happening is (P-N)/P
				// for example, it is roughly 1/2^128 for P256-k1
				recid = 2
			} else {
				recid = 0
			}
			r.Mod(r, N)
			if r.Sign() != 0 {
				recid += byte(y.Bit(0))
				break
			}
		}

		e := hashToInt(hash, c)
		s = new(big.Int).Mul(priv.D, r)
		s.Add(s, e)
		s.Mul(s, kInv)
		s.Mod(s, N) // N != 0
		if s.Sign() != 0 {
			break
		}
	}

	return
}

// SignASN1 signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the ASN.1 encoded signature. The security of the private key
// depends on the entropy of rand.
func SignASN1(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	return priv.Sign(rand, hash, nil)
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func Verify(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool {
	// See [NSA] 3.4.2
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	return verify(pub, c, hash, r, s)
}

func verify(pub *ecdsa.PublicKey, c elliptic.Curve, hash []byte, r, s *big.Int) bool {
	e := hashToInt(hash, c)
	var w *big.Int
	N := c.Params().N
	if in, ok := c.(invertible); ok {
		w = in.Inverse(s)
	} else {
		w = new(big.Int).ModInverse(s, N)
	}

	u1 := e.Mul(e, w)
	u1.Mod(u1, N)
	u2 := w.Mul(r, w)
	u2.Mod(u2, N)

	// Check if implements S1*g + S2*p
	var x, y *big.Int
	if opt, ok := c.(combinedMult); ok {
		x, y = opt.CombinedMult(pub.X, pub.Y, u1.Bytes(), u2.Bytes())
	} else {
		x1, y1 := c.ScalarBaseMult(u1.Bytes())
		x2, y2 := c.ScalarMult(pub.X, pub.Y, u2.Bytes())
		x, y = c.Add(x1, y1, x2, y2)
	}

	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

// VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the
// public key, pub. Its return value records whether the signature is valid.
func VerifyASN1(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	return ecdsa.VerifyASN1(pub, hash, sig)
}

type zr struct {
	io.Reader
}

// Read replaces the contents of dst with zeros.
func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}

// signing options
const (
	Normal byte = 0
	LowerS byte = 1 // return (r, s) with s <= N/2
	RecID  byte = 2 // return recovery id in addition to (r, s)
)

const (
	normalSigLength  byte = 16
	invalidSigLength byte = 255
)

// SignBytes returns the signature in bytes
func SignBytes(priv *ecdsa.PrivateKey, hash []byte, flag byte) ([]byte, error) {
	r, s, v, err := Sign(rand.Reader, priv, hash)
	if err != nil {
		return nil, err
	}

	// in case of LowerS, enforce s <= N/2 to prevent signature malleability
	param := priv.Curve.Params()
	if (flag&LowerS) != 0 && s.Cmp(new(big.Int).Rsh(param.N, 1)) > 0 {
		s.Sub(param.N, s)
		v ^= 1
	}

	// ECDSA returns 0 < r, s < N
	rSize := (param.BitSize + 7) >> 3
	sig := make([]byte, 2*rSize, 2*rSize+1)
	r.FillBytes(sig[:rSize])
	s.FillBytes(sig[rSize:])

	if (flag & RecID) != 0 {
		sig = append(sig, v)
	}
	return sig, nil
}

// VerifyBytes verifies the signature in bytes
func VerifyBytes(pub *ecdsa.PublicKey, hash, sig []byte, flag byte) bool {
	param := pub.Curve.Params()
	r, s, v := decodeSigBytes(param, sig)
	if v == invalidSigLength {
		return false
	}
	if (flag & RecID) != 0 {
		if v > 3 {
			return false
		}
	} else {
		if v != normalSigLength {
			return false
		}
	}

	// in case of LowerS, verify s <= N/2
	if (flag&LowerS) != 0 && s.Cmp(new(big.Int).Rsh(param.N, 1)) == 1 {
		return false
	}
	return ecdsa.Verify(pub, hash, r, s)
}

func decodeSigBytes(param *elliptic.CurveParams, sig []byte) (r, s *big.Int, recid byte) {
	rSize := (param.BitSize + 7) >> 3

	switch len(sig) {
	case 2 * rSize:
		recid = normalSigLength
	case 2*rSize + 1:
		// recovery id is the last byte of sig bytes
		recid = sig[len(sig)-1]
	default:
		// invalid sig length
		recid = invalidSigLength
	}

	// get (r, s) from sig bytes
	r = new(big.Int).SetBytes(sig[:rSize])
	s = new(big.Int).SetBytes(sig[rSize : 2*rSize])
	return
}
