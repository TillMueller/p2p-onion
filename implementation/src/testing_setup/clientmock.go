package testing_setup

import (
	"bytes"
	"encoding/binary"
	"net"
	"onion/api"
	"strconv"
	"sync"
	"time"
)

type connections struct {
	data map[string]net.Conn
	mutex sync.Mutex
}
var conns = connections{
	data: make(map[string]net.Conn),
}

func InitializeClient(apiAddress string) {
	if t == nil {
		panic("Initialize RPS mock with T first")
	}
	var err error
	conn, err := net.Dial("tcp", apiAddress)
	if err != nil {
		t.Errorf("Could not connect to api: " + err.Error())
		return
	}
	conns.mutex.Lock()
	conns.data[apiAddress] = conn
	conns.mutex.Unlock()
	defer conn.Close()
	handleIncomingAPIMessages(conn)
}

func handleIncomingAPIMessages(conn net.Conn) {
	apiConnString := "[API CONNECTION " + conn.RemoteAddr().String() + "] "
	for {
		msgType, msgBuf, err := api.ReceiveAPIMessage(conn)
		if err != nil {
			t.Log(apiConnString + "Could not receive API message, connection closed?")
			return
		}
		switch msgType {
		case api.ONION_TUNNEL_INCOMING:
			tunnelID := binary.BigEndian.Uint32(msgBuf[:4])
			tunnelIDBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(tunnelIDBuf, tunnelID)
			t.Log(apiConnString + "Sending reply backwards through tunnel")
			err = api.SendAPIMessage(conn, api.ONION_TUNNEL_DATA, append(tunnelIDBuf, []byte("I am sending a message through some tunnels")...))
			if err != nil {
				t.Errorf(apiConnString + "Could not send api message")
				return
			}
		case api.ONION_TUNNEL_DATA:
			tunnelID := binary.BigEndian.Uint32(msgBuf[:4])
			t.Log(apiConnString + "Got data from tunnel " + strconv.Itoa(int(tunnelID)) + ": " + string(msgBuf[4:]))
		case api.ONION_TUNNEL_READY:
			tunnelID := binary.BigEndian.Uint32(msgBuf[:4])
			t.Log(apiConnString + "Tunnel is ready: " + strconv.Itoa(int(tunnelID)))
			if !bytes.Equal(msgBuf[4:], getHostKey(destinationPeer)) {
				t.Errorf(apiConnString + "Got wrong hostkey back")
			}
			time.Sleep(5 * time.Second)
			err := api.SendAPIMessage(conn, api.ONION_TUNNEL_DESTROY, msgBuf[:4])
			if err != nil {
				t.Errorf(apiConnString + "Could not send api message")
			}
		case api.ONION_ERROR:
			t.Log(apiConnString + "Got ONION_ERROR for tunnel ID " + strconv.Itoa(int(binary.BigEndian.Uint32(msgBuf[:4]))))
		}
	}
}

func BuildTunnelTest(apiAddress string) {
	conns.mutex.Lock()
	conn := conns.data[apiAddress]
	conns.mutex.Unlock()
	apiConnString := "[API CONNECTION " + conn.RemoteAddr().String() + "] "
	if conn == nil {
		t.Errorf(apiConnString + "API connection is nil")
		return
	}
	msgBuf := make([]byte, 4)
	binary.BigEndian.PutUint16(msgBuf[:2], 0)
	binary.BigEndian.PutUint16(msgBuf[2:4], 65508)
	msgBuf = append(msgBuf, net.IPv4(127, 0, 0, 1).To4()...)
	msgBuf = append(msgBuf, getHostKey(4)...)
	msg, err := api.BuildAPIMessage(api.ONION_TUNNEL_BUILD, msgBuf)
	if err != nil {
		t.Errorf(apiConnString + "Could not build API message")
		return
	}
	t.Log(apiConnString + "Sending ONION_TUNNEL_BUILD message to API")
	_, err = conn.Write(msg)
	if err != nil {
		t.Errorf(apiConnString + "Could not send API message")
		return
	}
}

func CoverTrafficTest(apiAddress string) {
	conns.mutex.Lock()
	conn := conns.data[apiAddress]
	conns.mutex.Unlock()
	apiConnString := "[API CONNECTION " + conn.RemoteAddr().String() + "] "
	if conn == nil {
		t.Errorf(apiConnString + "API connection is nil")
		return
	}
	msgBuf := make([]byte, 4)
	binary.BigEndian.PutUint16(msgBuf[:2], 50000)
	binary.BigEndian.PutUint16(msgBuf[2:4], 0)
	msg, err := api.BuildAPIMessage(api.ONION_COVER, msgBuf)
	if err != nil {
		t.Errorf(apiConnString + "Could not build API message")
		return
	}
	t.Log(apiConnString + "Sending ONION_COVER message to API")
	_, err = conn.Write(msg)
	if err != nil {
		t.Errorf(apiConnString + "Could not send API message")
		return
	}
}