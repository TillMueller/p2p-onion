package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	err := loadConfig("config.ini")
	if err != nil {
		t.Errorf("Could not load config")
	}
	// TODO test all the config values we loaded / needed
}

// TODO create a better way of having a test key and test message available here so that this test works even when either / both are not available
func TestLoadAndUsePrivateKey(t *testing.T) {
	if loadPrivateKeyFile("hostkey_testingonly.pem") != nil {
		t.Errorf("Loading private key file failed")
		return
	}
	// Test decryption with private key; message created by running "echo "This is a test" | openssl rsautl -encrypt -oaep -pubin -inkey hostkey_pub.pem > message.encrypted"
	bytes, err := ioutil.ReadFile("message.encrypted")
	if err != nil {
		t.Errorf("Loading encrypted message failed")
		return
	}
	out, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, PrivateKey, bytes, nil)
	if err != nil {
		t.Errorf("Decrypting message failed")
		return
	}
	fmt.Println(string(out))
	// Test encryption with public key; check by running "openssl rsautl -decrypt -in message2.encrypted -oaep -out plaintext.txt -inkey hostkey_testingonly.pem"
	encrypted, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, &PrivateKey.PublicKey, []byte("An encrypted response"), nil)
	err = ioutil.WriteFile("message2.encrypted", encrypted, 0644)
	if err != nil {
		t.Errorf("Could not write decryption test")
	}
}
