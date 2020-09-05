package testing_setup

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"io"
	"io/ioutil"
	"net"
	"strconv"
	"testing"
)

var lastPeer = 4
var addressString = "localhost:65530"
var t *testing.T

func getPeerFolderPath(n int) string {
	return "testing_setup/peer" + strconv.Itoa(n)
}

func getHostKey(n int) []byte {
	pubkey, err := ioutil.ReadFile(getPeerFolderPath(n) + "/pubkey.der")
	if err != nil {
		t.Errorf(err.Error())
	}
	return pubkey
}

func destinationKey() *rsa.PublicKey {
	publickey, err := x509.ParsePKCS1PublicKey(getHostKey(lastPeer))
	if err != nil {
		t.Errorf(err.Error())
	}
	return publickey
}

func getRspHeader(n int) []byte {
	rspStart := make([][]byte, 3)
	rspStart[0] = []byte{
		0x0, 0x0, 0x2, 0x1d, // 2 bytes size, 2 bytes RPS PEER (541) in big endian
		0x0, 0x0, 0x1, 0x0, // 2 bytes port (unused), 1 byte number of ports in map (1), 1 port reserved and last bit indicated IP version (IPv4 = 0)
		0x2, 0x30, 0xff, 0xe1, // 2 bytes onion app id (560) in big endian, 2 bytes the port it listens on (65505) in big endian
		0x7f, 0x0, 0x0, 0x1, // 4 bytes peer IPv4 address (127.0.0.1)
	}
	rspStart[1] = []byte{
		0x0, 0x0, 0x2, 0x1d, // 2 bytes size, 2 bytes RPS PEER (541) in big endian
		0x0, 0x0, 0x1, 0x0, // 2 bytes port (unused), 1 byte number of ports in map (1), 1 port reserved and last bit indicated IP version (IPv4 = 0)
		0x2, 0x30, 0xff, 0xe2, // 2 bytes onion app id (560) in big endian, 2 bytes the port it listens on (65506) in big endian
		0x7f, 0x0, 0x0, 0x1, // 4 bytes peer IPv4 address (127.0.0.1)
	}
	rspStart[2] = []byte{
		0x0, 0x0, 0x2, 0x1d, // 2 bytes size, 2 bytes RPS PEER (541) in big endian
		0x0, 0x0, 0x1, 0x0, // 2 bytes port (unused), 1 byte number of ports in map (1), 1 port reserved and last bit indicated IP version (IPv4 = 0)
		0x2, 0x30, 0xff, 0xe3, // 2 bytes onion app id (560) in big endian, 2 bytes the port it listens on (65506) in big endian
		0x7f, 0x0, 0x0, 0x1, // 4 bytes peer IPv4 address (127.0.0.1)
	}
	return rspStart[n]
}

func getPeerDetails(n int) []byte {
	pubkey := getHostKey(n + 1)
	rspStart := getRspHeader(n)
	totalLength := len(rspStart) + len(pubkey)
	binary.BigEndian.PutUint16(rspStart[:2], uint16(totalLength))
	fullRsp := make([]byte, totalLength)
	copy(fullRsp[:len(rspStart)], rspStart)
	copy(fullRsp[len(rspStart):totalLength], pubkey)
	return fullRsp
}

func serveRPS() {
	listenConn, _ := net.Listen("tcp", addressString)
	defer listenConn.Close()
	counter := 0
	for {
		conn, _ := listenConn.Accept()
		lengthTypeBuf := make([]byte, 4)
		_, _ = io.ReadFull(conn, lengthTypeBuf)
		rspLength := binary.BigEndian.Uint16(lengthTypeBuf[:2])
		rspType := binary.BigEndian.Uint16(lengthTypeBuf[2:4])
		rspBuf := make([]byte, rspLength-4)
		_, _ = io.ReadFull(conn, rspBuf)
		if rspLength != 4 || rspType != 540 {
			t.Errorf("Got malformed request")
			return
		}
		// prepare response
		_, _ = conn.Write(getPeerDetails(counter))
		conn.Close()
		counter++
		if counter == 3 {
			counter = 0
		}
	}
}

func InitializeRPS(tt *testing.T) {
	t = tt
	serveRPS()
}
