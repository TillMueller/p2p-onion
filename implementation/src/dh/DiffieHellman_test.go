package dh

import (
	"bytes"
	"testing"
)

func TestGenKeyPair(t *testing.T) {
	PEMPrivateKeyLength := 227
	PEMPublicKeyLength := 178
	emptyByteSlicePrivate := make([]byte, PEMPrivateKeyLength)
	emptyByteSlicePublic := make([]byte, PEMPublicKeyLength)

	privateKeyBytes, publicKeyBytes, error := GenKeyPair()
	if error != nil || len(privateKeyBytes) != PEMPrivateKeyLength || len(publicKeyBytes) != PEMPublicKeyLength || bytes.Equal(privateKeyBytes, emptyByteSlicePrivate) || bytes.Equal(publicKeyBytes, emptyByteSlicePublic) {
		t.Errorf("Diffie Hellman keypair is not generated properly")
	}
}

func TestDeriveSharedSecret(t *testing.T) {
	privateKeyBytes0, publicKeyBytes0, error0 := GenKeyPair()
	privateKeyBytes1, publicKeyBytes1, error1 := GenKeyPair()
	if error0 != nil || error1 != nil {
		t.Errorf("Could not generate keypairs to test shared secret derivation")
		return
	}
	sharedSecret0, error2 := DeriveSharedSecret(privateKeyBytes0, publicKeyBytes1)
	sharedSecret1, error3 := DeriveSharedSecret(privateKeyBytes1, publicKeyBytes0)
	if error2 != nil || error3 != nil {
		t.Errorf("Could not derive shared secret from keypairs")
		return
	}
	if !bytes.Equal(sharedSecret0, sharedSecret1) {
		t.Errorf("Derived shared secrets are not equal")
	}
}
