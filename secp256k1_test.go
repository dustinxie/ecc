// Copyright (c) 2021 dustinxie. All rights reserved.
//
// Use of this source code is governed by MIT license
// that can be found in the LICENSE file.

package ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func TestP256k1Signature(t *testing.T) {
	// the first-ever bitcoin transaction: Satoshi transferred 10BTC to Hal Finney in block 170
	// See https://www.blockchain.com/btc/tx/f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
	// use it as a test case to verify P256-k1 signature

	// raw transaction bytes
	// See https://blockchain.info/rawtx/f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16?format=hex
	rawTx := "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"

	// decode public key
	// 0x41 = 65, followed by 65-byte uncompressed public key
	Pkscript, _ := hex.DecodeString("410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac")
	p256k1 := P256k1()
	x, y := elliptic.Unmarshal(p256k1, Pkscript[1:1+int(Pkscript[0])])
	if x == nil || y == nil {
		t.Error("failed to unmarshal public key")
	}
	pubkey := &ecdsa.PublicKey{
		Curve: p256k1,
		X:     x,
		Y:     y,
	}

	// decode (r, s) from signature
	Sigscript := "4847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901"
	SigscriptBytes, _ := hex.DecodeString(Sigscript)
	// bitcoin signature is DER-encoded:
	// 0x48: size of signature script
	// 0x47: length of data to follow
	// 0x30: marker of start
	// 0x44: length of remaining signature
	// 0x02: marker for r value
	// 0x20: length of r value
	// followed by : 32-byte r value
	r := new(big.Int).SetBytes(SigscriptBytes[6:38])
	// 0x02: marker for s value
	// 0x20: length of s value
	// followed by : 32-byte s value
	s := new(big.Int).SetBytes(SigscriptBytes[40:SigscriptBytes[0]])
	// last byte of Sigscript = 0x01, meaning the hash type = SIGHASH_ALL
	sigtype := SigscriptBytes[len(SigscriptBytes)-1]

	// construct the transaction input to calculate its hash
	// See https://en.bitcoin.it/wiki/OP_CHECKSIG for a detailed explanation
	pos := strings.Index(rawTx, Sigscript)
	afterSig, _ := hex.DecodeString(rawTx[pos+len(Sigscript):])
	txToHash, _ := hex.DecodeString(rawTx[:pos])
	// insert public key script
	txToHash = append(txToHash, byte(len(Pkscript)))
	txToHash = append(txToHash, Pkscript...)
	txToHash = append(txToHash, afterSig...)
	// append sigtype as 4-byte
	txToHash = append(txToHash, []byte{sigtype, 0, 0, 0}...)
	// SHA256 twice to get the hash
	hash := sha256.Sum256(txToHash)
	hash = sha256.Sum256(hash[:])

	// verify the signature
	if !ecdsa.Verify(pubkey, hash[:], r, s) {
		t.Error("failed to verify P256-k1 signature")
	}
}
