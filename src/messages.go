/*
	*** USING FIXED OPTION ONLY! ***
	ref) https://github.com/bin-y/standard-ecies/blob/master/main.js

	/// node js option
	 const options = {
      hashName: 'sha256',
      hashLength: 32,
      macName: 'sha256',
      macLength: 32,
      curveName: 'secp256k1',
      symmetricCypherName: 'aes-128-cbc',
      iv: randombytes(16),
      keyFormat: 'uncompressed',
      s1: null,
      s2: null
    }

	*** CIPHER STRUCT IS CHANGED ***
	[ R | c | D ] 	-> 	  [ iv | R | c | D ]
*/

package node_ecies

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

var IV_LENGTH int = 16
var PUBLIC_KEY_LENGTH int = 65
var HMAC_LENGTH int = 32
var PUBLIC_KEY_END_POS int = IV_LENGTH + PUBLIC_KEY_LENGTH

// EncryptWithBase64 : encrypt plainbyte / return cipherbyte base64 string
func EncryptWithBase64(pub *ECDHPublicKey, plainData []byte, iv []byte) (string, error) {
	byteRes, err := Encrypt(pub, plainData, iv)
	if nil != err {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(byteRes[:]), nil
}

// Encrypt : encrypt plainbyte / return cipherbyte
func Encrypt(pub *ECDHPublicKey, plainData []byte, iv []byte) (byteRetv []byte, errRetv error) {
	//recover
	defer func() {
		if r := recover(); r != nil {
			byteRetv = nil
			errRetv = errors.New(fmt.Sprint(r))
		}
	}()

	templatePrivate, templatePub, _ := GenerateKey()

	// create sharedsecret : generated private/local public key
	R := templatePub.ToBytes()
	byteSharedSecret := templatePrivate.sharedSecret(pub)

	// uses KDF to derive a symmetric encryption and a MAC keys:
	// Ke || Km = KDF(S || S1)
	// hash option : sha256 - s1 : using empty buffer
	sha256HashedSecret := sha256.Sum256(byteSharedSecret)
	// Ke
	encryptionKey := sha256HashedSecret[0 : len(sha256HashedSecret)/2]
	// Km
	macKey := sha256HashedSecret[len(sha256HashedSecret)/2:]

	// encrypte plain text
	// c = E(Ke; m);
	cipherData, err := CBCEncrypterAES(encryptionKey, plainData, iv)
	if nil != err {
		return nil, err
	}

	// computes the tag of encrypted message and S2:
	// d = MAC(Km; c || S2)
	// mac option : sha256 - s2 : using empty buffer
	mac := hmac.New(sha256.New, macKey)
	mac.Write(cipherData)
	D := mac.Sum(nil)

	// return [iv | R | c | D]
	retv := []byte{}
	retv = append(iv, R...)
	retv = append(retv, cipherData...)
	retv = append(retv, D...)

	return retv, nil
}

/// cipher data structure
// parse [ iv | R | c | D ]
// cipherData[0] ~ cipherData[15] : iv
// cipherData[16] ~ cipherData[81] : template key
// cipherData[82] ~ cipherData[end-32] : cipherdata
// cipherData[end-32] ~ cipherData[end] : hmac

// DecryptBase64 : decrypt cipher base64 string / return plain byte
func DecryptBase64(pri *ECDHPrivateKey, strBase64 string) ([]byte, error) {
	cipherData, err := base64.StdEncoding.DecodeString(strBase64)
	if nil != err {
		return nil, err
	}
	return Decrypt(pri, cipherData)
}

// Decrypt : dcerypt cipher data / return plain byte
func Decrypt(pri *ECDHPrivateKey, cipherData []byte) (byteRetv []byte, errRetv error) {
	// recover
	defer func() {
		if r := recover(); nil != r {
			byteRetv = nil
			errRetv = errors.New(fmt.Sprint(r))
		}
	}()

	// parse cipher
	iv := cipherData[0:IV_LENGTH]
	R := cipherData[IV_LENGTH:PUBLIC_KEY_END_POS]
	c := cipherData[PUBLIC_KEY_END_POS : len(cipherData)-HMAC_LENGTH]
	msgTag := cipherData[len(cipherData)-HMAC_LENGTH:]

	// parse cipherData to templatePubKey
	templatePubKey := FromBytesToPublicKey(R)

	// create sharedsecret : generate: local private/template public key
	byteSharedSecret := pri.sharedSecret(templatePubKey)

	// derives keys the same way as Alice did:
	// Ke || Km = KDF(S || S1)
	sha256HashedSecret := sha256.Sum256(byteSharedSecret)
	// Ke
	encryptionKey := sha256HashedSecret[0 : len(sha256HashedSecret)/2]
	// Km
	macKey := sha256HashedSecret[len(sha256HashedSecret)/2:]

	// computes the tag of encrypted message and S2:
	// d = MAC(Km; c || S2)
	// mac option : sha256 - s2 : using empty buffer
	mac := hmac.New(sha256.New, macKey)
	mac.Write(c)
	keyTag := mac.Sum(nil)

	// outputs failed if d != MAC(Km; c || S2);
	if false == equalConstTime(msgTag, keyTag) {
		return nil, errors.New("Decrypt: Bad MAC")
	}

	return CBCDecrypterAES(encryptionKey, c, iv)
}

// equalConstTime : Compare two buffers in constant time to prevent timing attacks.
func equalConstTime(msgTag, keyTag []byte) bool {
	if len(msgTag) != len(keyTag) {
		return false
	}

	var result byte
	for i := 0; i < len(msgTag); i++ {
		result |= msgTag[i] ^ keyTag[i]
	}

	if result == 0 {
		return true
	} else {
		return false
	}
}
