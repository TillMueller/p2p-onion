package main

import (
	"testing"
	"time"
)

func callbackDummy(n int, data []byte) {}

func TestDiffieHellmanExchange(t *testing.T) {
	udpconn, _ := SubscribeTo("localhost:65500", callbackDummy)
	time.Sleep(1 * time.Second)
	SendPacket(udpconn, "localhost:65501", []byte("test message"))
	SendPacket(udpconn, "localhost:65501", []byte("and another one"))
	time.Sleep(3 * time.Second)
}
