package node_ecies

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

func CBCEncrypterAES(key []byte, data []byte, iv []byte) ([]byte, error) {
	paddedData := PKCS7Padding(data, aes.BlockSize)
	if len(paddedData)%aes.BlockSize != 0 {
		return nil, errors.New("invalid block size: PKCS7Padded data")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipherData := make([]byte, len(paddedData))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherData, paddedData)

	return cipherData, nil
}

func CBCDecrypterAES(key []byte, data []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)

	return PKCS7UnPadding(data), nil
}

// Use PKCS7 to fill, IOS is also 7
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
