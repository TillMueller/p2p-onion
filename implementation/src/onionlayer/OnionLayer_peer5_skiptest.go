package onionlayer

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io/ioutil"
	"net"
	"onion/api"
	"onion/config"
	"strconv"
	"testing"
	"time"
)

func connectToApi(t *testing.T) {
	conn, err := net.Dial("tcp", "localhost:65509")
	if err != nil {
		t.Errorf("Could not connect to api")
		return
	}
	for {
		msgType, msgBuf, err := api.ReceiveAPIMessage(conn)
		if err != nil {
			t.Errorf("Could not receive API message")
			return
		}
		if msgType != api.ONION_TUNNEL_INCOMING {
			t.Errorf("Unexpected message type: " + strconv.Itoa(int(msgType)))
			return
		}
		tunnelID := binary.BigEndian.Uint32(msgBuf[:4])
		tunnelIDBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tunnelIDBuf, tunnelID)
		t.Log("Sending reply backwards through tunnel")
		err = api.SendAPIMessage(conn, api.ONION_TUNNEL_DATA, append(tunnelIDBuf, []byte("I am sending a message through some tunnels")...))
		if err != nil {
			t.Errorf("Could not send api message")
			return
		}
	}
}

func TestBuildTunnelSingleHopPeer5(t *testing.T) {
	config.P2p_hostname = "localhost"
	config.P2p_port = 65508
	config.ApiAddress = "localhost:65509"
	keyFileContent, _ := ioutil.ReadFile("peer5_testing.pem")
	privateKeyPem, _ := pem.Decode(keyFileContent)
	config.PrivateKey, _ = x509.ParsePKCS1PrivateKey(privateKeyPem.Bytes)
	err := Initialize()
	if err != nil {
		t.Errorf("Coud not initialize onion module")
		return
	}
	err = api.Initialize()
	if err != nil {
		t.Errorf("Coud not initialize api module")
		return
	}
	go connectToApi(t)
	time.Sleep(30 * time.Second)
}