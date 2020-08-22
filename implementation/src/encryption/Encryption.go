package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"errors"
	"onion/logger"
)

// Encrypt encrypts a plaintext using AES with the given key
// An IV will be regenerated every time and prepended to the encrypted data
// adapted from https://golang.org/src/crypto/cipher/example_test.go
func Encrypt(key []byte, text []byte) ([]byte, error) {
	plaintext := []byte(text)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		logger.Error.Println("Invalid key")
		return nil, errors.New("InvalidArgumentError")
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	rand.Read(iv)
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
}

// Decrypt decrypts a ciphertext using AES with the given key
// It assumes that the first 16 bytes of the ciphertext are the IV
// adapted from https://golang.org/src/crypto/cipher/example_test.go
func Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		logger.Error.Println("Invalid key")
		return nil, errors.New("InvalidArgumentError")
	}
	if len(ciphertext) < aes.BlockSize {
		logger.Error.Println("Ciphertext too short")
		return nil, errors.New("InvalidArgumentError")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

func EncryptAsymmetric(publicKey *rsa.PublicKey, text []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, text, nil)
	if err != nil {
		logger.Error.Println("Could not encrypt text with public key")
		return nil, errors.New("CryptoError")
	}
	return ciphertext, nil
}

func DecryptAsymmetric(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		logger.Error.Println("Could not decrypt text with private key")
		return nil, errors.New("CryptoError")
	}
	return plaintext, nil
}
