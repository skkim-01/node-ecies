/*
	*** USING DEFALUT OPTION ONLY! ***
	ref) https://github.com/bin-y/standard-ecies/blob/master/main.js

*/

package node_ecies

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"

	"github.com/fomichev/secp256k1"
)

var curve = secp256k1.SECP256K1()

type ECDHPublicKey struct {
	Curve elliptic.Curve
	X     *big.Int
	Y     *big.Int
}

type ECDHPrivateKey struct {
	D []byte
}

func GenerateKey() (*ECDHPrivateKey, *ECDHPublicKey, error) {
	var d []byte
	var x, y *big.Int
	var err error

	// currently fix p256
	d, x, y, err = elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pri := &ECDHPrivateKey{
		D: d,
	}

	pub := &ECDHPublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return pri, pub, nil
}

func FromBase64ToPrivateKey(strBase64Key string) *ECDHPrivateKey {
	decodeString, err := base64.StdEncoding.DecodeString(strBase64Key)
	if nil != err {
		return nil
	}

	pri := &ECDHPrivateKey{
		D: decodeString,
	}
	return pri
}

func FromBytesToPrivateKey(bytePriKey []byte) *ECDHPrivateKey {
	pri := &ECDHPrivateKey{
		D: bytePriKey,
	}
	return pri
}

func (pri *ECDHPrivateKey) ToBytes() []byte {
	return pri.D
}

func (pri *ECDHPrivateKey) ToBase64() string {
	return base64.StdEncoding.EncodeToString(pri.D[:])
}

func FromBase64ToPublicKey(strBase64Key string) *ECDHPublicKey {
	retv, err := base64.StdEncoding.DecodeString(strBase64Key)
	if nil != err {
		return nil
	}
	return unmarshal(retv)
}

func FromBytesToPublicKey(bytePubKey []byte) *ECDHPublicKey {
	return unmarshal(bytePubKey)
}

func (pub *ECDHPublicKey) ToBytes() []byte {
	return elliptic.Marshal(curve, pub.X, pub.Y)
}

func (pub *ECDHPublicKey) ToBase64() string {
	bytePubkey := elliptic.Marshal(curve, pub.X, pub.Y)
	return base64.StdEncoding.EncodeToString(bytePubkey[:])
}

func unmarshal(data []byte) *ECDHPublicKey {
	x, y := elliptic.Unmarshal(curve, data)
	if x == nil || y == nil {
		return nil
	}

	key := &ECDHPublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return key
}

func (pri *ECDHPrivateKey) sharedSecret(pub *ECDHPublicKey) []byte {
	x, _ := curve.ScalarMult(pub.X, pub.Y, pri.D)

	return x.Bytes()
}
