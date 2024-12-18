package hoplayer

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

func TestPadPacketLongThrownOut(t *testing.T) {
	myslice := make([]byte, 1281) // == packetLength + 1
	_, err := padPacket(myslice)
	if err == nil {
		t.Errorf("padPacket does not throw out packet that is too long")
	}
}

func TestPadPacketValidInput(t *testing.T) {
	const length = 700 // some number < packetLength
	myslice := make([]byte, length)
	rand.Read(myslice)
	packet, err := padPacket(myslice)
	if err != nil {
		t.Errorf("padPacket errors on valid input")
		return
	}
	if !bytes.Equal(packet[0:length], myslice[0:length]) {
		t.Errorf("padPacket does not retain original packet content")
	}
}
func callbackDummy(addr *net.UDPAddr, data []byte) {}

//unfinished
func TestDiffieHellmanExchange(t *testing.T) {
	udpconn1, err := SetPacketReceiver("localhost:65500", callbackDummy)
	if err != nil {
		t.Errorf("Could not create listening address")
		return
	}
	SetPacketReceiver("localhost:65501", callbackDummy)
	SendPacket(udpconn1, "localhost:65501", []byte("test message"))
	SendPacket(udpconn1, "localhost:65501", []byte("and another one"))
	time.Sleep(time.Second)
}
