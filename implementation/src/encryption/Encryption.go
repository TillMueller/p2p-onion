package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"errors"
	"onion/logger"
	"strconv"
)

// Encrypt encrypts a plaintext using AES with the given key
// An IV will be regenerated every time and prepended to the encrypted data
// adapted from https://golang.org/src/crypto/cipher/example_test.go
func Encrypt(key []byte, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error.Println("Invalid key")
		return nil, errors.New("InvalidArgumentError")
	}
	ciphertext := make([]byte, aes.BlockSize+len(text))
	_, err = rand.Read(ciphertext[:aes.BlockSize])
	if err != nil {
		logger.Error.Println("Could not read random IV")
		return nil, errors.New("CryptoError")
	}
	stream := cipher.NewCFBEncrypter(block, ciphertext[:aes.BlockSize])
	stream.XORKeyStream(ciphertext[aes.BlockSize:], text)
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
		logger.Error.Println("Ciphertext too short (expected >= " + strconv.Itoa(aes.BlockSize) + ", got " + strconv.Itoa(len(ciphertext)) + ")")
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
