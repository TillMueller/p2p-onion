package main

import (
	"testing"
	"time"
)

func callbackDummy(n int, data []byte) {}

func TestDiffieHellmanExchange(t *testing.T) {
	udpconn, _ := SubscribeTo("localhost:65501", callbackDummy)
	time.Sleep(3 * time.Second)
	SendPacket(udpconn, "localhost:65500", []byte("a response"))
	SendPacket(udpconn, "localhost:65500", []byte("more responses"))
}
