package main

// for this import to work libssl-dev needs to be installed
import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"

	"github.com/spacemonkeygo/openssl"
)

//var dhParameters = `-----BEGIN DH PARAMETERS-----
//MIIBCAKCAQEAilXHGRQHES6bNnqu5OFQ18pURTULGaUW9K1BcyHkrqtrFvWImadT
//0Na5hDp6Qp4OAX924zLPJ39qhCQxkoQssC/+EBd8GWRWmFpjGre+mD8b/7GVP0JN
///6Dhr579NIcB+NIztSMXxUBZEpb+MTXyh6pIG5CSdd3I/PrL9ldjLB96eCddXBr0
//GFLhczEOOP9p/Uo5hWRyiMhCmPS7yRcucXvmi2j3ORxtqj+H+RMM+JWaRkppiEk1
//DJcmIyQmqgCuJscu37jDVLNWBXWGpXjS7OozGn74mp15QfrrE2xj/uWDW6p/uahH
//4ZIa39+e0K+cGyynl438SOcK6Min66svUwIBAg==
//-----END DH PARAMETERS-----`

func initialize() bool {
	//	dh, error := openssl.LoadDHParametersFromPEM([]byte(dhParameters))
	//if error != nil {
	//fmt.Printf("Could not load DH parameters")
	//return false
	//}
	privatekey, error := openssl.GenerateECKey(openssl.Prime256v1)
	if error != nil {
		fmt.Printf("Could not generate private key")
		return false
	}
	privatekeybytes, _ := privatekey.MarshalPKCS1PrivateKeyPEM()
	fmt.Println(string(privatekeybytes))

	privatekey2, error := openssl.GenerateECKey(openssl.Prime256v1)
	if error != nil {
		fmt.Printf("Could not generate private key")
		return false
	}
	privatekeybytes2, _ := privatekey2.MarshalPKCS1PrivateKeyPEM()
	fmt.Println(string(privatekeybytes2))

	publickeybytes, error := privatekey.MarshalPKIXPublicKeyPEM()
	if error != nil {
		fmt.Printf("Could not generate public key")
		return false
	}
	fmt.Println(string(publickeybytes))

	publickeybytes2, error := privatekey2.MarshalPKIXPublicKeyPEM()
	if error != nil {
		fmt.Printf("Could not generate public key")
		return false
	}
	fmt.Println(string(publickeybytes2))

	publickey, error := openssl.LoadPublicKeyFromPEM(publickeybytes)
	if error != nil {
		fmt.Printf("Could not generate public key")
		return false
	}

	publickey2, error := openssl.LoadPublicKeyFromPEM(publickeybytes2)
	if error != nil {
		fmt.Printf("Could not generate public key")
		return false
	}

	sharedSecret, error := openssl.DeriveSharedSecret(privatekey, publickey2)
	if error != nil {
		fmt.Printf("Could not derive shared secret")
		return false
	}
	//fmt.Println(string(sharedSecret))
	fmt.Println(len(sharedSecret))

	sharedSecret2, error := openssl.DeriveSharedSecret(privatekey2, publickey)
	if error != nil {
		fmt.Printf("Could not derive shared secret")
		return false
	}

	fmt.Println(base64.URLEncoding.EncodeToString(sharedSecret))
	fmt.Println(base64.URLEncoding.EncodeToString(sharedSecret2))

	encrypt("This is a text", sharedSecret)
	encrypt("This is a text", sharedSecret2)

	return false
}

func encrypt(text string, sharedSecret []byte) {
	// https://gist.github.com/manishtpatel/8222606
	plaintext := []byte(text)
	block, _ := aes.NewCipher(sharedSecret)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	fmt.Println(base64.URLEncoding.EncodeToString(ciphertext))
}

func main() {
	initialize()
}
