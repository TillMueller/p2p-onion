package main

import (
	"bytes"
	"crypto/rand"
	"testing"
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
	}
	if bytes.Compare(packet[0:length], myslice[0:length]) != 0 {
		t.Errorf("padPacket does not retain original packet content")
	}
}

func callbackDummy(n int, data []byte) {}

//unfinished
func TestDiffieHellmanExchange(t *testing.T) {
	var udpconn1, _ = SubscribeTo("localhost:65500", callbackDummy)
	SubscribeTo("localhost:65501", callbackDummy)
	SendPacket(udpconn1, "localhost:65501", []byte("test message"))
	SendPacket(udpconn1, "localhost:65501", []byte("and another one"))
}
