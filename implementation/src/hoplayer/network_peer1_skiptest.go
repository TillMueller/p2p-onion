package hoplayer

import (
	"testing"
	"time"
)

func callbackDummyPeer1(n int, data []byte) {}

func TestDiffieHellmanExchangePeer1(t *testing.T) {
	udpconn, err := SetPacketReceiver("localhost:65502", callbackDummyPeer1)
	if err != nil {
		t.Errorf("Could not create listening address")
		return
	}
	time.Sleep(1 * time.Second)
	SendPacket(udpconn, "localhost:65503", []byte("test message"))
	SendPacket(udpconn, "localhost:65503", []byte("and another one"))
	time.Sleep(3 * time.Second)
}

func TestResetPeer1(t *testing.T) {
	udpconn, err := SetPacketReceiver("localhost:65504", callbackDummyPeer1)
	if err != nil {
		t.Errorf("Could not create listening address")
		return
	}
	time.Sleep(1 * time.Second)
	SendPacket(udpconn, "localhost:65505", []byte("test message"))
	time.Sleep(3 * time.Second)
	SendPacket(udpconn, "localhost:65505", []byte("and another one"))
	time.Sleep(3 * time.Second)
	SendPacket(udpconn, "localhost:65505", []byte("last message"))
}
