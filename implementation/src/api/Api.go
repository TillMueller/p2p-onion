package api

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"onion/config"
	"onion/logger"
	"strconv"
)

const (
	LENGTH_OF_SIZE   = 2
	LENGTH_OF_TYPE   = 2
	LENGTH_OF_HEADER = LENGTH_OF_SIZE + LENGTH_OF_TYPE
	RPS_QUERY        = 540
	RPS_PEER         = 541
	ONION_APP_ID = 560
)

// Important: This function takes a message without the size or type bytes because it automatically adds those to the
// front of the message. All fields therefore need to be shifted by four bytes.
func sendAPIMessage(conn net.Conn, msgType uint16, msgBuf []byte) error {
	totalLength := len(msgBuf) + LENGTH_OF_HEADER
	fullMsgBuf := make([]byte, totalLength)
	binary.BigEndian.PutUint16(fullMsgBuf[:LENGTH_OF_SIZE], uint16(totalLength))
	binary.BigEndian.PutUint16(fullMsgBuf[LENGTH_OF_SIZE:LENGTH_OF_HEADER], msgType)
	n := copy(fullMsgBuf[LENGTH_OF_HEADER:], msgBuf)
	if n != len(msgBuf) {
		logger.Error.Println("Could not copy complete message to outgoing message buffer")
		return errors.New("InternalError")
	}
	n, err := conn.Write(fullMsgBuf)
	if err != nil || n != totalLength {
		logger.Error.Println("Could not send API message or sent message has wrong length")
		return errors.New("networkError")
	}
	return nil
}

// Important: This function returns a message without the size  or type bytes because it automatically removes them from
// the front of the message. All fields are therefore shifted by four bytes.
func receiveAPIMessage(conn net.Conn) (err error, rspType uint16, rspMsgBuf []byte) {
	lengthTypeBuf := make([]byte, LENGTH_OF_HEADER)
	n, err := io.ReadFull(conn, lengthTypeBuf)
	if err != nil || n != LENGTH_OF_HEADER {
		logger.Error.Println("Error reading size and type from incoming API message")
		return errors.New("networkError"),0,nil
	}
	rspLength := binary.BigEndian.Uint16(lengthTypeBuf[:LENGTH_OF_SIZE])
	rspType = binary.BigEndian.Uint16(lengthTypeBuf[LENGTH_OF_SIZE:LENGTH_OF_HEADER])
	rspBuf := make([]byte, rspLength - LENGTH_OF_HEADER)
	n, err = io.ReadFull(conn, rspBuf)
	if err != nil || n != int(rspLength - LENGTH_OF_HEADER) {
		logger.Error.Println("Error reading incoming API message of size " + strconv.Itoa(int(rspLength)) + " (read size: " + strconv.Itoa(n) + ")")
		return errors.New("networkError"),0,nil
	}
	return nil, rspType, rspBuf
}

func RPSQuery() (err error, peerAddress net.IP, peerAddressIsIPv6 bool, peerOnionPort uint16, peerHostkey *rsa.PublicKey) {
	logger.Info.Println("Soliciting random peer")
	conn, err := net.Dial("tcp", config.RpsAddress)
	if err != nil {
		logger.Error.Println("Could not connect to RPS module at " + config.RpsAddress + " (error: " + err.Error() + ")")
		return errors.New("networkError"), nil, false, 0, nil
	}
	defer conn.Close()
	err = sendAPIMessage(conn, RPS_QUERY, nil)
	if err != nil {
		logger.Error.Println("Could not send RPS QUERY message to RPS module")
		return errors.New("networkError"), nil, false, 0, nil
	}
	err, rspType, rspBuf := receiveAPIMessage(conn)
	if err != nil {
		logger.Error.Println("Could not receive RPS QUERY response")
		return errors.New("networkError"), nil, false, 0, nil
	}
	// Check if response is a RPS PEER message
	if rspType != RPS_PEER {
		logger.Error.Println("RPS response is not of type RPS PEER, expected type " + strconv.Itoa(RPS_PEER) + " but got type " + strconv.Itoa(int(rspType)) + " instead")
		return errors.New("APIError"), nil, false, 0, nil
	}
	// Get port of remote onion module by looking through the port table RPS has sent
	peerOnionPort = 0
	portmapSize := rspBuf[2]
	for i := 0; i < int(portmapSize); i++ {
		lineStart := (i + 1) * 4
		appId := binary.BigEndian.Uint16(rspBuf[lineStart:lineStart + 2])
		if appId == ONION_APP_ID {
			peerOnionPort = binary.BigEndian.Uint16(rspBuf[lineStart + 2:lineStart + 4])
			break
		}
	}
	if peerOnionPort == 0 {
		logger.Error.Println("RPS response did not contain a port for the onion module")
		return errors.New("APIError"), nil, false, 0, nil
	}
	portmapEnd := (int(portmapSize) + 1) * 4
	// Check if the IP address is an IPv6 address
	peerAddressIsIPv6 = rspBuf[3] & 1 == 1
	// Extract IP address depending on its length
	var ipAddressLength int
	if peerAddressIsIPv6 {
		ipAddressLength = 16
	} else {
		ipAddressLength = 4
	}
	ipAddressEnd := portmapEnd + ipAddressLength
	peerAddress = rspBuf[portmapEnd:ipAddressEnd]
	peerHostkey, err = x509.ParsePKCS1PublicKey(rspBuf[ipAddressEnd:])
	if err != nil {
		logger.Error.Println("Could not parse peer public key from RPS response")
		return errors.New("internalError"), nil, false, 0, nil
	}
	logger.Info.Println("RPS peer solicited with IP " + peerAddress.String() + " and port " + strconv.Itoa(int(peerOnionPort)))
	return nil, peerAddress, peerAddressIsIPv6, peerOnionPort, peerHostkey
}