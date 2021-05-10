# secp256k1
Golang native implementation of the secp256k1 elliptic curve

[![LICENSE](https://img.shields.io/badge/License-Apache%202.0-turquise.svg)](LICENSE)
[![Go version](https://img.shields.io/badge/Go-1.15-turquise.svg)]()
[![Go Report card](https://goreportcard.com/badge/github.com/dustinxie/ecc)](https://goreportcard.com/report/github.com/dustinxie/ecc)
[![Go Reference](https://pkg.go.dev/badge/github.com/dustinxie/ecc.svg)](https://pkg.go.dev/github.com/dustinxie/ecc)
---
## Features
- Based on Golang's native `crypto/ecdsa` and `crypto/elliptic` package, no
external dependency at all 
- Full compatible with the secp256k1 signature in [go-ethereum](https://github.com/ethereum/go-ethereum)

## Motivation
Golang's `elliptic.Curve` implements the short-form Weierstrass curve y² = x³ +
ax + b, but only with a = -3, which are the case for NIST-recommended curves
P224, P256,P384, and P521. For a general curve with a != -3, one would have to
rely on external packages, which is quite an inconvenience.

For example, a very popular curve is secp256k1 with equation y² = x³ + 7, used
by many crypto projects such as Bitcoin and Ethereum. In order to use it, one
would usually need to import for example [go-ethereum](https://github.com/ethereum/go-ethereum),
which is a very large package with many dependencies.

This package provides a secp256k1 implementation solely based on Golang's native
code. No external dependency is introduced.

## How to use
Package's `P256k1()` method returns a `elliptic.Curve` that implements the
secp256k1 curve, use it the same way as you would use other curves in the
`ecdsa` package.

Or use package's `SignBytes()` and `VerifyBytes()` API that signs/verifies the
signature as a byte-stream. See example below:
```go
package anyname

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	
	"github.com/dustinxie/ecc"
)

func signVerify(msg []byte) error {
	// generate secp256k1 private key
	p256k1 := ecc.P256k1()
	privKey, err := ecdsa.GenerateKey(p256k1, rand.Reader)
	if err != nil {
		// handle error
		return err
	}
	
	// sign message
	hash := sha256.Sum256(msg)
	sig, err := ecc.SignBytes(privKey, hash[:], ecc.Normal)
	if err != nil {
		return err
	}
	
	// verify message
	if !ecc.VerifyBytes(&privKey.PublicKey, hash[:], sig, ecc.Normal) {
		return fmt.Errorf("failed to verify secp256k1 signature")
	}
	return nil
}
```

### Signing options
The package provides 2 additional signing options:
- To tackle the ECDSA signature malleability issue (see "Rationale" in
[here](https://eips.ethereum.org/EIPS/eip-2)), pass the flag `LowerS` to
signing API. This ensures the resulting `s` value in the signature is less
than or equal to half of N (the order of the curve)
```go
// generate 64-byte signature R || S, with s <= N/2
sig, err := ecc.SignBytes(privKey, hash, ecc.LowerS)
if err != nil {
	return err
}

if !ecc.VerifyBytes(&privKey.PublicKey, hash, sig, ecc.LowerS) {
	return fmt.Errorf("failed to verify secp256k1 signature")
}
return nil
```
- To return the one-byte recovery ID that can be used to recover public key from
the signature, pass the flag `RecID` to signing API
```go
// generate 65-byte signature R || S || V
sig, err := ecc.SignBytes(privKey, hash, ecc.RecID)
if err != nil {
	return err
}

if !ecc.VerifyBytes(&privKey.PublicKey, hash, sig, ecc.RecID) {
	return fmt.Errorf("failed to verify secp256k1 signature")
}
```
the resulting 65-byte signature allows you to recover public key from it:
```go
pubKey, err := RecoverPubkey("P-256k1", hash, sig)
if err != nil {
	return err
}

if !pubKey.Equal(&privKey.PublicKey) {
	return fmt.Errorf("recovered public key not equal to signing public key")
}
return nil
```
The recommendation is to always enable `ecc.LowerS` option when signing any
message. And finally, you can pass both flags to signing API:
```go
sig, err := ecc.SignBytes(privKey, hash, ecc.LowerS | ecc.RecID)
```

### Full Ethereum compatibility
Package also provides the following 3 API that are fully compatible with the
official [go-ethereum](https://github.com/ethereum/go-ethereum). They are
actually just a wrapper of our API using proper options.
```go
func SignEthereum(hash []byte, priv *ecdsa.PrivateKey) ([]byte, error)

func VerifyEthereum(pubkey, hash, sig []byte, isHomestead bool) bool

func RecoverEthereum(hash, sig []byte) ([]byte, error)
```
