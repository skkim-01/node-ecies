package main

import (
	"fmt"

	node_ecies "github.com/skkim-01/node-ecies/src"
)

func main() {
	privateKey, publicKey, err := node_ecies.GenerateKey()
	if nil != err {
		fmt.Println(err)
		return
	}

	fmt.Println("### original keypair ###")
	fmt.Println("pri:", privateKey.ToBase64())
	fmt.Println("pub:", publicKey.ToBase64())

	copiedPublicKey := node_ecies.FromBytesToPublicKey(publicKey.ToBytes())
	copiedPrivateKey := node_ecies.FromBase64ToPrivateKey(privateKey.ToBase64())

	fmt.Println("### copied keypair ###")
	fmt.Println("pri:", copiedPrivateKey.ToBase64())
	fmt.Println("pub:", copiedPublicKey.ToBase64())
	fmt.Println()

	plainMsg := []byte("test messages")
	// iv length : must 16
	iv := []byte("0123456789012345")
	fmt.Println("plainMsg:", string(plainMsg))

	// encrypt
	cipherMsg, err := node_ecies.EncryptWithBase64(publicKey, plainMsg, iv)
	if nil != err {
		fmt.Println(err)
		return
	}

	fmt.Println("Encrypt:", cipherMsg)

	decryptedBytes, err := node_ecies.DecryptBase64(copiedPrivateKey, cipherMsg)
	if nil != err {
		fmt.Println(err)
		return
	}

	fmt.Println("DecryptMsg:", string(decryptedBytes))
}
