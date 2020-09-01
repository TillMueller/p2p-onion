package onionlayer

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"onion/config"
	"testing"
	"time"
)

func TestBuildTunnelSingleHopPeer2(t *testing.T) {
	config.P2p_hostname = "localhost"
	config.P2p_port = 65505
	keyFileContent, _ := ioutil.ReadFile("peer2_testing.pem")
	privateKeyPem, _ := pem.Decode(keyFileContent)
	config.PrivateKey, _ = x509.ParsePKCS1PrivateKey(privateKeyPem.Bytes)
	Initialize()
	time.Sleep(15 * time.Second)
}