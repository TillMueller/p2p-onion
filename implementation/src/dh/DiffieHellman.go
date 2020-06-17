package dh

import (
	"errors"
	"onion/logger"
	"github.com/spacemonkeygo/openssl"
)

// GenKeyPair generates a public/private keypair
func GenKeyPair() ([]byte, []byte, error) {
	privatekey, err := openssl.GenerateECKey(openssl.Prime256v1)
	if err != nil {
		return nil, nil, errors.New("Could not generate private key")
	}

	privateKeyBytes, _ := privatekey.MarshalPKCS1PrivateKeyPEM()
	publicKeyBytes, err := privatekey.MarshalPKIXPublicKeyPEM()
	if err != nil {
		return nil, nil, errors.New("Could not extract public key")
	}

	return privateKeyBytes, publicKeyBytes, nil
}

// DeriveSharedSecret creates a shared secret from a public and a private key pair
func DeriveSharedSecret(privateKeyBytes []byte, publicKeyBytes []byte) ([]byte, error) {
	privateKey, err := openssl.LoadPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		logger.Error.Println("Could not load private key")
		return nil, errors.New("internalError")
	}

	publicKey, err := openssl.LoadPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		logger.Error.Println("Could not load public key")
		return nil, errors.New("internalError")
	}

	sharedSecret, error := openssl.DeriveSharedSecret(privateKey, publicKey)
	if error != nil {
		logger.Error.Println("Could not derive shared secret")
		return nil, errors.New("internalError")
	}
	return sharedSecret, nil
}
