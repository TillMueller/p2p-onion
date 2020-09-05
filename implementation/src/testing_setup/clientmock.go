package testing_setup

import (
	"bytes"
	"encoding/binary"
	"net"
	"onion/api"
	"strconv"
)

var api_address = "localhost:65510"
// we only mock one client
var conn net.Conn

func InitializeClient() {
	if t == nil {
		panic("Initialize RPS mock with T first")
	}
	var err error
	conn, err = net.Dial("tcp", api_address)
	if err != nil {
		t.Errorf("Could not connect to api")
		return
	}
	defer conn.Close()
	handleIncomingAPIMessages()
}

func handleIncomingAPIMessages() {
	for {
		msgType, msgBuf, err := api.ReceiveAPIMessage(conn)
		if err != nil {
			t.Errorf("Could not receive API message")
			return
		}
		switch msgType {
		case api.ONION_TUNNEL_INCOMING:
			tunnelID := binary.BigEndian.Uint32(msgBuf[:4])
			tunnelIDBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(tunnelIDBuf, tunnelID)
			t.Log("Sending reply backwards through tunnel")
			err = api.SendAPIMessage(conn, api.ONION_TUNNEL_DATA, append(tunnelIDBuf, []byte("I am sending a message through some tunnels")...))
			if err != nil {
				t.Errorf("Could not send api message")
				return
			}
		case api.ONION_TUNNEL_DATA:
			tunnelID := binary.BigEndian.Uint32(msgBuf[:4])
			t.Log("Got data from tunnel " + strconv.Itoa(int(tunnelID)) + ": " + string(msgBuf[4:]))
		case api.ONION_TUNNEL_READY:
			tunnelID := binary.BigEndian.Uint32(msgBuf[:4])
			t.Log("Tunnel is ready: " + strconv.Itoa(int(tunnelID)))
			if !bytes.Equal(msgBuf[4:], getHostKey(lastPeer)) {
				t.Errorf("Got wrong hostkey back")
			}
		}
	}
}

func BuildTunnelTest() {
	if conn == nil {
		t.Errorf("API connection is nil")
		return
	}
	msgBuf := make([]byte, 4)
	binary.BigEndian.PutUint16(msgBuf[:2], 0)
	binary.BigEndian.PutUint16(msgBuf[2:4], 65508)
	msgBuf = append(msgBuf, net.IPv4(127, 0, 0, 1).To4()...)
	msgBuf = append(msgBuf, getHostKey(4)...)
	msg, err := api.BuildAPIMessage(api.ONION_TUNNEL_BUILD, msgBuf)
	if err != nil {
		t.Errorf("Could not build API message")
		return
	}
	t.Log("Sending ONION_TUNNEL_BUILD message to API")
	_, err = conn.Write(msg)
	if err != nil {
		t.Errorf("Could not send API message")
		return
	}
}