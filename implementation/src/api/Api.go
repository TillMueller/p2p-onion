package sendingapi

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"onion/config"
	"onion/logger"
	"onion/onioninterface"
	"onion/storage"
	"strconv"
)

const (
	LENGTH_OF_SIZE   = 2
	LENGTH_OF_TYPE   = 2
	LENGTH_OF_HEADER = LENGTH_OF_SIZE + LENGTH_OF_TYPE
	RPS_QUERY        = 540
	RPS_PEER         = 541
	ONION_APP_ID     = 560

	ONION_TUNNEL_BUILD    = 560
	ONION_TUNNEL_READY    = 561
	ONION_TUNNEL_INCOMING = 562
	ONION_TUNNEL_DESTROY  = 563
	ONION_TUNNEL_DATA     = 564
	ONION_ERROR           = 565
	ONION_CONVER          = 566
)

var apiConnections = storage.InitApiConnections()

func sendApiErrorMessage(conn net.Conn, requestType uint16, tunnelID uint32) {
	msgBuf := make([]byte, 8)
	binary.BigEndian.PutUint16(msgBuf[:2], requestType)
	binary.BigEndian.PutUint16(msgBuf[2:4], 0)
	binary.BigEndian.PutUint32(msgBuf[4:8], tunnelID)
	err := SendAPIMessage(conn, ONION_ERROR, msgBuf)
	if err != nil {
		logger.Error.Println("Could not send error message to API connection " + conn.RemoteAddr().String())
	}
}

func handleApiMessage(conn net.Conn, msgType uint16, msgBuf []byte) {
	switch msgType {
	case ONION_TUNNEL_DATA:
		tunnelID := binary.BigEndian.Uint32(msgBuf[:4])
		data := msgBuf[4:]
		err := packagecommunicator.OnionLayerSendData(tunnelID, data)
		if err != nil {
			logger.Error.Println("Could not send data as requested by ONION_TUNNEL_DATA command")
			sendApiErrorMessage(conn, msgType, tunnelID)
		}
	default:
		// TODO disconnect this API connection
	}
}

func handleApiConnection(conn net.Conn) {
	apiConn := &storage.ApiConnection{
		Connection: conn,
	}
	storage.AddApiConnection(apiConnections, apiConn)
	for {
		msgType, msgBuf, err := ReceiveAPIMessage(conn)
		if err != nil {
			logger.Warning.Println("Could not receive message from API connection: " + conn.RemoteAddr().String())
			continue
		}
		go handleApiMessage(conn, msgType, msgBuf)
		// TODO read from this sendingapi connection
		// TODO come up with a way to kill these API connections
	}
}

func listenApi(listenConn net.Listener) {
	defer listenConn.Close()
	logger.Info.Println("Listening on API address " + config.ApiAddress)
	for {
		conn, err := listenConn.Accept()
		if err != nil {
			logger.Warning.Println("Could not accept connection: " + err.Error())
		}
		go handleApiConnection(conn)
	}
}

func Initialize() error {
	listenConn, err := net.Listen("tcp", config.ApiAddress)
	if err != nil {
		logger.Error.Println("Could not open API listening connection")
		return errors.New("networkError")
	}
	go listenApi(listenConn)
	return nil
}

func buildAPIMessage(msgType uint16, msgBuf []byte) ([]byte, error) {
	totalLength := len(msgBuf) + LENGTH_OF_HEADER
	fullMsgBuf := make([]byte, totalLength)
	binary.BigEndian.PutUint16(fullMsgBuf[:LENGTH_OF_SIZE], uint16(totalLength))
	binary.BigEndian.PutUint16(fullMsgBuf[LENGTH_OF_SIZE:LENGTH_OF_HEADER], msgType)
	n := copy(fullMsgBuf[LENGTH_OF_HEADER:], msgBuf)
	if n != len(msgBuf) {
		logger.Error.Println("Could not copy complete message to outgoing message buffer")
		return nil, errors.New("InternalError")
	}
	return fullMsgBuf, nil
}

func SendAllAPIConnections(msgType uint16, msgBuf []byte) error {
	fullMsgBuf, err := buildAPIMessage(msgType, msgBuf)
	if err != nil {
		logger.Error.Println("Could not build API message for all API connections")
		return errors.New("InternalError")
	}
	storage.SendAllApiConnections(apiConnections, fullMsgBuf)
	return nil
}

// Important: This function takes a message without the size or type bytes because it automatically adds those to the
// front of the message. All fields therefore need to be shifted by four bytes.
func SendAPIMessage(conn net.Conn, msgType uint16, msgBuf []byte) error {
	fullMsgBuf, err := buildAPIMessage(msgType, msgBuf)
	if err != nil {
		logger.Error.Println("Could not build API message for single API connection")
		return errors.New("InternalError")
	}
	n, err := conn.Write(fullMsgBuf)
	if err != nil || n != len(fullMsgBuf) {
		logger.Error.Println("Could not send API message or sent message has wrong length")
		return errors.New("networkError")
	}
	return nil
}

// Important: This function returns a message without the size or type bytes because it automatically removes them from
// the front of the message. All fields are therefore shifted by four bytes.
// TODO if an API connection misbehaves disconnect it immediately
func ReceiveAPIMessage(conn net.Conn) (rspType uint16, rspMsgBuf []byte, err error) {
	lengthTypeBuf := make([]byte, LENGTH_OF_HEADER)
	n, err := io.ReadFull(conn, lengthTypeBuf)
	if err != nil || n != LENGTH_OF_HEADER {
		logger.Error.Println("Error reading size and type from incoming API message")
		return 0, nil, errors.New("networkError")
	}
	rspLength := binary.BigEndian.Uint16(lengthTypeBuf[:LENGTH_OF_SIZE])
	rspType = binary.BigEndian.Uint16(lengthTypeBuf[LENGTH_OF_SIZE:LENGTH_OF_HEADER])
	rspBuf := make([]byte, rspLength-LENGTH_OF_HEADER)
	n, err = io.ReadFull(conn, rspBuf)
	if err != nil || n != int(rspLength-LENGTH_OF_HEADER) {
		logger.Error.Println("Error reading incoming API message of size " + strconv.Itoa(int(rspLength)) + " (read size: " + strconv.Itoa(n) + ")")
		return 0, nil, errors.New("networkError")
	}
	return rspType, rspBuf, nil
}

func RPSQuery() (err error, peerAddress net.IP, peerAddressIsIPv6 bool, peerOnionPort uint16, peerHostkey *rsa.PublicKey) {
	logger.Info.Println("Soliciting random peer")
	conn, err := net.Dial("tcp", config.RpsAddress)
	if err != nil {
		logger.Error.Println("Could not connect to RPS module at " + config.RpsAddress + " (error: " + err.Error() + ")")
		return errors.New("networkError"), nil, false, 0, nil
	}
	defer conn.Close()
	err = SendAPIMessage(conn, RPS_QUERY, nil)
	if err != nil {
		logger.Error.Println("Could not send RPS QUERY message to RPS module")
		return errors.New("networkError"), nil, false, 0, nil
	}
	rspType, rspBuf, err := ReceiveAPIMessage(conn)
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
		appId := binary.BigEndian.Uint16(rspBuf[lineStart : lineStart+2])
		if appId == ONION_APP_ID {
			peerOnionPort = binary.BigEndian.Uint16(rspBuf[lineStart+2 : lineStart+4])
			break
		}
	}
	if peerOnionPort == 0 {
		logger.Error.Println("RPS response did not contain a port for the onion module")
		return errors.New("APIError"), nil, false, 0, nil
	}
	portmapEnd := (int(portmapSize) + 1) * 4
	// Check if the IP address is an IPv6 address
	peerAddressIsIPv6 = rspBuf[3]&1 == 1
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
	logger.Info.Println("RPS peer solicited with IPv6 " + strconv.FormatBool(peerAddressIsIPv6) + " IP " + peerAddress.String() + " and port " + strconv.Itoa(int(peerOnionPort)))
	return nil, peerAddress, peerAddressIsIPv6, peerOnionPort, peerHostkey
}
