package onionlayer

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"onion/config"
	"testing"
	"time"
)

func TestBuildTunnelSingleHopPeer5(t *testing.T) {
	config.P2p_hostname = "localhost"
	config.P2p_port = 65508
	keyFileContent, _ := ioutil.ReadFile("peer5_testing.pem")
	privateKeyPem, _ := pem.Decode(keyFileContent)
	config.PrivateKey, _ = x509.ParsePKCS1PrivateKey(privateKeyPem.Bytes)
	initialize()
	time.Sleep(5 * time.Second)
}