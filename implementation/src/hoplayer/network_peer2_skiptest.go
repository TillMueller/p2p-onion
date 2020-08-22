package hoplayer

import (
	"testing"
	"time"
)

func callbackDummyPeer2(data []byte) {}

func TestDiffieHellmanExchangePeer2(t *testing.T) {
	udpconn, err := SetPacketReceiver("localhost:65503", callbackDummyPeer2)
	if err != nil {
		t.Errorf("Could not create listening address")
		return
	}
	time.Sleep(3 * time.Second)
	SendPacket(udpconn, "localhost:65502", []byte("a response"))
	SendPacket(udpconn, "localhost:65502", []byte("more responses"))
}

func TestResetPeer2(t *testing.T) {
	_, err := SetPacketReceiver("localhost:65505", callbackDummyPeer2)
	if err != nil {
		t.Errorf("Could not create listening address")
		return
	}
	time.Sleep(2 * time.Second)
	clearPeerInformation("127.0.0.1:65504")
	time.Sleep(8 * time.Second)
}
