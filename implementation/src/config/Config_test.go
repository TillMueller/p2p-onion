package config

import (
	"fmt"
	"io/ioutil"
	"onion/encryption"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	err := LoadConfig("config.ini")
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
	out, err := encryption.DecryptAsymmetric(PrivateKey, bytes)
	if err != nil {
		t.Errorf("Decrypting message failed")
		return
	}
	fmt.Println(string(out))
	// Test encryption with public key; check by running "openssl rsautl -decrypt -in message2.encrypted -oaep -out plaintext.txt -inkey hostkey_testingonly.pem"
	encrypted, _ := encryption.EncryptAsymmetric(&PrivateKey.PublicKey, []byte("An encrypted response"))
	err = ioutil.WriteFile("message2.encrypted", encrypted, 0644)
	if err != nil {
		t.Errorf("Could not write decryption test")
	}
}

