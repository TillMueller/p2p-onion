package dh

import (
	"errors"

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
func DeriveSharedSecret(publicKeyBytes []byte, privateKeyBytes []byte) ([]byte, error) {
	privateKey, err := openssl.LoadPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return nil, errors.New("Could not load private key")
	}

	publicKey, err := openssl.LoadPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, errors.New("Could not load public key")
	}

	sharedSecret, error := openssl.DeriveSharedSecret(privateKey, publicKey)
	if error != nil {
		return nil, errors.New("Could not derive shared secret")
	}
	return sharedSecret, nil
}
