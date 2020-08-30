package api

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"net"
	"onion/config"
	"strconv"
	"testing"
	"time"
)

func listenAndRespond(expectedMessage []byte, response []byte, port int, t *testing.T) {
	listenConn, err := net.Listen("tcp", "127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Errorf("Cannot create listen port")
		return
	}
	defer listenConn.Close()
	conn, err := listenConn.Accept()
	if err != nil {
		t.Errorf("Cannot accept new connection")
		return
	}
	defer conn.Close()
	msgBuf := make([]byte, len(expectedMessage))
	n, err := conn.Read(msgBuf)
	if err != nil || n != len(expectedMessage) {
		t.Errorf("Cannot read message or message has wrong length")
		return
	}
	if bytes.Equal(expectedMessage, msgBuf) {
		t.Errorf("Got different message than the expected one")
		return
	}
	n, err = conn.Write(response)
	if err != nil || n != len(response) {
		t.Errorf("Cannot write response or sent response has wrong length")
		return
	}
}

// TODO create more complicated tests / tests with invalid responses
func TestRPSQueryValidSimple(t *testing.T) {
	config.RpsAddress = "127.0.0.1:65510"
	expectedMessage := []byte {
		0x0, 0x4, 0x1c, 0x2,	// 2 bytes size (4 bytes), 2 bytes RPS QUERY (540)
	}
	rspStart := []byte {
		0x0, 0x0, 0x2, 0x1d,	// 2 bytes size, 2 bytes RPS PEER (541) in big endian
		0x0, 0x0, 0x1, 0x0,		// 2 bytes port (unused), 1 byte number of ports in map (1), 1 port reserved and last bit indicated IP version (IPv4 = 0)
		0x2, 0x30, 0xc5, 0x44,	// 2 bytes onion app id (560) in big endian, 2 bytes the port it listens on (50500) in big endian
		0x7f, 0x0, 0x0, 0x1,	// 4 bytes peer IPv4 address (127.0.0.1)
	}
	pubkey := []byte {
		0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00, 0xce, 0xa3, 0xa7, 0xa0, 0x64, 0x6a, 0x03,
		0xbb, 0x86, 0x8a, 0xc5, 0x6c, 0xf6, 0x42, 0xdf, 0xe2, 0xb2, 0xe8, 0xc0, 0x05, 0x51, 0x2a, 0xab,
		0xf8, 0x08, 0x07, 0x2b, 0xc7, 0x8c, 0x3f, 0x12, 0xd9, 0x32, 0x85, 0xd8, 0x06, 0xaf, 0xcd, 0xff,
		0x60, 0x3c, 0x41, 0xac, 0xe6, 0xe8, 0xaf, 0x81, 0x57, 0x83, 0xa7, 0x80, 0x9d, 0xa1, 0xae, 0x1b,
		0xd2, 0x59, 0x04, 0x38, 0x0c, 0x05, 0x2c, 0xc5, 0x01, 0xa7, 0x82, 0x87, 0xa5, 0x2d, 0xad, 0x3d,
		0xcb, 0xaa, 0x09, 0x67, 0xe9, 0xf6, 0x3f, 0xb3, 0xfc, 0xce, 0x2d, 0x8e, 0x12, 0xb7, 0x23, 0x8f,
		0x83, 0xfc, 0x2a, 0x8d, 0x31, 0xac, 0xdd, 0x82, 0x41, 0xe4, 0xfd, 0x87, 0xf6, 0x35, 0xa1, 0xc4,
		0x56, 0x3c, 0xbd, 0x69, 0x9a, 0x16, 0x2e, 0xc3, 0x92, 0x19, 0x32, 0x6a, 0x84, 0xa8, 0x78, 0x38,
		0x63, 0x43, 0xf5, 0xb1, 0x5a, 0xd1, 0x57, 0x27, 0x41, 0xf5, 0x3a, 0xb6, 0x0a, 0x5c, 0xc2, 0x5f,
		0x5b, 0xa0, 0x6c, 0xfd, 0xb3, 0x1d, 0xbc, 0x41, 0x03, 0x93, 0x0f, 0x90, 0xbe, 0x47, 0x7a, 0xbb,
		0x66, 0x4f, 0x72, 0x8e, 0xac, 0xf6, 0x81, 0x20, 0x41, 0x14, 0x51, 0x39, 0x24, 0x50, 0x93, 0x7f,
		0x7c, 0x7a, 0xa5, 0xbd, 0x76, 0x1d, 0xa3, 0xa5, 0x79, 0xa0, 0xbb, 0x9a, 0x47, 0xc9, 0x08, 0x1a,
		0x57, 0xdb, 0x59, 0x70, 0x19, 0xb2, 0xb2, 0x99, 0xc5, 0xa5, 0xcd, 0xa8, 0x5c, 0x05, 0x8d, 0xf8,
		0x55, 0x5f, 0x4c, 0xa0, 0x47, 0xa8, 0x78, 0x8e, 0xeb, 0x13, 0x23, 0xff, 0x3c, 0x83, 0x29, 0x40,
		0xdf, 0xb9, 0xbe, 0x99, 0x0a, 0xe0, 0x92, 0xf9, 0x43, 0xfa, 0xf5, 0x07, 0x98, 0x52, 0x60, 0xdb,
		0x3e, 0x32, 0xa1, 0x9e, 0x24, 0x6e, 0x49, 0x70, 0xb9, 0xcb, 0x82, 0x98, 0x13, 0x54, 0x39, 0x46,
		0x1b, 0x06, 0x54, 0x37, 0x93, 0x25, 0x8f, 0x90, 0x81, 0x52, 0xc5, 0x02, 0x4b, 0x94, 0x73, 0xfc,
		0x1a, 0x80, 0xfe, 0x52, 0x68, 0xcb, 0x74, 0xb1, 0xee, 0x8c, 0x70, 0x91, 0xb3, 0x40, 0x2b, 0xfd,
		0x59, 0x95, 0xfb, 0xb4, 0x4d, 0xcf, 0x00, 0x9b, 0xb8, 0x5e, 0xaf, 0xea, 0x23, 0xf9, 0x7d, 0x10,
		0x63, 0xe9, 0x13, 0x6d, 0xb4, 0xa9, 0xfc, 0x31, 0x07, 0x16, 0x15, 0x88, 0x3e, 0x94, 0x00, 0x5b,
		0xfd, 0x7f, 0x63, 0x1f, 0xaa, 0x50, 0xc7, 0x1b, 0xa8, 0x5d, 0x4b, 0x3a, 0x4e, 0xd2, 0xdf, 0x9e,
		0xbd, 0xe1, 0x00, 0x29, 0x45, 0xbc, 0x3b, 0xe5, 0x51, 0xaa, 0x3c, 0xcc, 0x2c, 0x3b, 0x4d, 0x19,
		0xe6, 0xaf, 0x92, 0xd7, 0x4b, 0xfe, 0xbf, 0x35, 0x1b, 0x9a, 0xac, 0x3d, 0x7a, 0x64, 0xf4, 0x03,
		0x1a, 0x9e, 0xa7, 0x6c, 0xe5, 0x6e, 0xc1, 0x6b, 0x7b, 0x6e, 0xc7, 0xa9, 0x84, 0xd5, 0x89, 0x15,
		0x66, 0xb1, 0xec, 0x80, 0xbc, 0x3d, 0xa1, 0xab, 0xd9, 0xbb, 0x57, 0x26, 0x18, 0xfa, 0xf0, 0x77,
		0xf6, 0xcd, 0xa0, 0xaa, 0x14, 0x8d, 0x9f, 0xf0, 0xac, 0x67, 0xd4, 0x15, 0x38, 0x45, 0xce, 0x96,
		0xb2, 0x8b, 0x76, 0xb7, 0xe7, 0xf8, 0x65, 0x87, 0xed, 0x1a, 0xb4, 0x17, 0xc7, 0xf8, 0xb2, 0xb8,
		0xcf, 0xfe, 0xea, 0xdc, 0x24, 0xe8, 0xb4, 0x17, 0x5f, 0x83, 0xcb, 0x3e, 0x0d, 0xc2, 0xd7, 0xe6,
		0x37, 0x51, 0xaa, 0x58, 0xa5, 0x89, 0x55, 0xe4, 0x4f, 0x88, 0xba, 0x1b, 0x7d, 0x78, 0x87, 0x6a,
		0x20, 0x43, 0xf9, 0x05, 0xca, 0xff, 0xb6, 0x2e, 0x17, 0xc4, 0x96, 0x23, 0x5d, 0xb9, 0xd1, 0x15,
		0x4f, 0x13, 0xcc, 0x34, 0x92, 0xe2, 0xfc, 0xc7, 0x97, 0x89, 0xf2, 0x51, 0xe9, 0xb5, 0x5a, 0xa1,
		0xa5, 0x17, 0x31, 0x24, 0x7b, 0x25, 0xf3, 0xdf, 0x85, 0xc7, 0x81, 0x6a, 0x8a, 0x22, 0xb4, 0xa0,
		0xb6, 0x75, 0xcd, 0x3c, 0x85, 0xbd, 0x27, 0xb2, 0x47, 0x02, 0x03, 0x01, 0x00, 0x01,
	}
	totalLength := len(rspStart) + len(pubkey)
	binary.BigEndian.PutUint16(rspStart[:2], uint16(totalLength))
	fullRsp := make([]byte, totalLength)
	copy(fullRsp[:len(rspStart)], rspStart)
	copy(fullRsp[len(rspStart):totalLength], pubkey)
	go listenAndRespond(expectedMessage, fullRsp, 65510, t)
	time.Sleep(1 * time.Second)
	err, peerAddress, peerAddressIsIPv6, peerOnionPort, peerHostKey := RPSQuery()
	if err != nil {
		t.Errorf("Got error from RPSQuery: " + err.Error())
		return
	}
	if peerAddressIsIPv6 {
		t.Error("Address is wrongly labeled IPv6")
		return
	}
	if peerAddress.String() != "127.0.0.1" {
		t.Errorf("Received wrong IP address: Expected 127.0.0.1, got " + peerAddress.String())
		return
	}
	if peerOnionPort != 50500 {
		t.Errorf("Received wrong port: Expected 50500, got " + strconv.Itoa(int(peerOnionPort)))
		return
	}
	testPubkey, err := x509.ParsePKCS1PublicKey(pubkey)
	if err != nil {
		t.Errorf("Could not parse testing hostkey")
		return
	}
	if !bytes.Equal(peerHostKey.N.Bytes(), testPubkey.N.Bytes()) || peerHostKey.E != testPubkey.E {
		t.Errorf("Parsed hostkey is not equal to testing hostkey")
		return
	}
}