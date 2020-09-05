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
	"onion/storage"
	"strconv"
	"time"
)

const (
	LENGTH_OF_SIZE       = 2
	LENGTH_OF_TYPE       = 2
	LENGTH_OF_HEADER     = LENGTH_OF_SIZE + LENGTH_OF_TYPE
	// TODO move these two to config?
	COVER_CHUNK_SIZE     = 1000
	COVER_SLEEP_DURATION = 30 * time.Millisecond

	RPS_QUERY    = 540
	RPS_PEER     = 541
	ONION_APP_ID = 560

	ONION_TUNNEL_BUILD    = 560
	ONION_TUNNEL_READY    = 561
	ONION_TUNNEL_INCOMING = 562
	ONION_TUNNEL_DESTROY  = 563
	ONION_TUNNEL_DATA     = 564
	ONION_ERROR           = 565
	ONION_COVER           = 566
)

var apiConnections = storage.InitApiConnections()
var tunnelApiConnections = storage.InitTunnelApiConnections()
var onionLayerHandler func(uint16, []byte) (uint32, []byte, error)

func RegisterOnionLayerHandler(callback func(uint16, []byte) (uint32, []byte, error)) {
	onionLayerHandler = callback
}

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

func handleApiMessage(apiConn *storage.ApiConnection, msgType uint16, msgBuf []byte) {
	switch msgType {
	case ONION_TUNNEL_BUILD:
		tunnelID, resp, err := onionLayerHandler(msgType, msgBuf)
		if err != nil {
			logger.Error.Println("Could not handle ONION_TUNNEL_BUILD from " + apiConn.Connection.RemoteAddr().String() + ", sending ONION_ERROR")
			sendApiErrorMessage(apiConn.Connection, msgType, tunnelID)
			return
		}
		// only the creator of the tunnel is allowed to send data into it
		storage.AddTunnelApiConnection(tunnelApiConnections, tunnelID, apiConn)
		// tunnel was created successfully, send ONION_TUNNEL_READY
		err = SendAPIMessage(apiConn.Connection, ONION_TUNNEL_READY, resp)
		if err != nil {
			logger.Error.Println("Could not send ONION_TUNNEL_READY message to " + apiConn.Connection.RemoteAddr().String() + ", attempting to send ONION_ERROR")
			// attempting to send an API error message even though it is very likely to fail as well
			sendApiErrorMessage(apiConn.Connection, msgType, tunnelID)
			return
		}
	case ONION_TUNNEL_DESTROY:
		tunnelID := binary.BigEndian.Uint32(msgBuf[:4])
		listEmpty := storage.RemoveTunnelApiConnection(tunnelApiConnections, tunnelID, apiConn)
		if listEmpty {
			logger.Info.Println("No more API connections for tunnel " + strconv.Itoa(int(tunnelID)) + ", destroying it")
			tunnelID, _, err := onionLayerHandler(msgType, msgBuf)
			if err != nil {
				logger.Error.Println("Could not handle ONION_TUNNEL_DESTROY from " + apiConn.Connection.RemoteAddr().String() + ", sending ONION_ERROR")
				sendApiErrorMessage(apiConn.Connection, msgType, tunnelID)
				return
			}
		}
	case ONION_TUNNEL_DATA:
		tunnelID := binary.BigEndian.Uint32(msgBuf[:4])
		if !storage.ExistsTunnelApiConnection(tunnelApiConnections, tunnelID, apiConn) {
			logger.Warning.Println("Connection " + apiConn.Connection.RemoteAddr().String() + " tried to send on unknown or disallowed tunnel " + strconv.Itoa(int(tunnelID)) + ", closing API connection")
			removeAllTunnelAPIConnections(apiConn)
			storage.RemoveApiConnection(apiConnections, apiConn)
			return
		}
		tunnelID, _, err := onionLayerHandler(msgType, msgBuf)
		if err != nil {
			logger.Error.Println("Could not handle ONION_TUNNEL_DATA from " + apiConn.Connection.RemoteAddr().String() + ", sending ONION_ERROR")
			sendApiErrorMessage(apiConn.Connection, msgType, tunnelID)
			return
		}
	case ONION_COVER:
		_, _, err := onionLayerHandler(msgType, msgBuf)
		if err != nil {
			logger.Error.Println("Could not handle ONION_COVER from " + apiConn.Connection.RemoteAddr().String() + ", sending ONION_ERROR")
			sendApiErrorMessage(apiConn.Connection, msgType, 0)
			return
		}
	default:
		logger.Warning.Println("Got unexpected message type " + strconv.Itoa(int(msgType)) + ", terminating API connection")
		removeAllTunnelAPIConnections(apiConn)
		storage.RemoveApiConnection(apiConnections, apiConn)
	}
}

func removeAllTunnelAPIConnections(apiConn *storage.ApiConnection) {
	tunnelsToRemove := storage.RemoveApiConnectionFromAllTunnels(tunnelApiConnections, apiConn)
	for _, v := range tunnelsToRemove {
		logger.Info.Println("Misbehaving connection was last connection for tunnel " + strconv.Itoa(int(v)) + ", destroying the tunnel")
		tunnelIDBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tunnelIDBuf, v)
		_, _, err := onionLayerHandler(ONION_TUNNEL_DESTROY, tunnelIDBuf)
		if err != nil {
			logger.Warning.Println("Could not remove tunnel " + strconv.Itoa(int(v)) + " from misbehaving API connection")
		}
	}
}

func handleApiConnection(conn net.Conn) {
	logger.Info.Println("New API connection from " + conn.RemoteAddr().String())
	apiConn := &storage.ApiConnection{
		Connection:   conn,
		RequestClose: false,
	}
	defer conn.Close()
	defer logger.Info.Println("Closing API connection to " + conn.RemoteAddr().String())
	storage.AddApiConnection(apiConnections, apiConn)
	for {
		msgType, msgBuf, err := ReceiveAPIMessage(conn)
		if apiConn.RequestClose {
			logger.Info.Println("Got request to close API connection to " + conn.RemoteAddr().String())
			return
		}
		if err != nil && err.Error() == "DisconnectedError" {
			logger.Info.Println("Removing API connection at " + apiConn.Connection.RemoteAddr().String())
			removeAllTunnelAPIConnections(apiConn)
			storage.RemoveApiConnection(apiConnections, apiConn)
			return
		}
		if err != nil {
			logger.Warning.Println("Could not receive message from API connection: " + conn.RemoteAddr().String())
			continue
		}
		go handleApiMessage(apiConn, msgType, msgBuf)
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

func OnionTunnelIncoming(tunnelID uint32) error {
	// everyone may interact with an incoming tunnel
	conns := storage.GetAllAPIConnections(apiConnections)
	for _, value := range conns {
		logger.Info.Println("Adding connection " + value.Connection.RemoteAddr().String() + " as allowed for tunnel " + strconv.Itoa(int(tunnelID)))
		storage.AddTunnelApiConnection(tunnelApiConnections, tunnelID, value)
	}
	// send ONION_TUNNEL_INCOMING API message to all connections
	tunnelIDBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(tunnelIDBuf, tunnelID)
	err := sendAllAPIConnections(conns, ONION_TUNNEL_INCOMING, tunnelIDBuf)
	if err != nil {
		logger.Error.Println("Could not send API message to all connections for ONION_TUNNEL_INCOMING")
		return errors.New("APIError")
	}
	return nil
}

func SendTunnelApiConnections(tunnelID uint32, msgType uint16, data []byte) error {
	msgBuf, err := buildAPIMessage(msgType, data)
	if err != nil {
		logger.Error.Println("Could not build message to send to all API connections of tunnel " + strconv.Itoa(int(tunnelID)))
		return errors.New("APIError")
	}
	storage.SendTunnelApiConnections(tunnelApiConnections, tunnelID, msgBuf)
	return nil
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

func sendAllAPIConnections(conns []*storage.ApiConnection, msgType uint16, msgBuf []byte) error {
	fullMsgBuf, err := buildAPIMessage(msgType, msgBuf)
	if err != nil {
		logger.Error.Println("Could not build API message for all API connections")
		return errors.New("InternalError")
	}
	storage.SendAllApiConnections(conns, fullMsgBuf)
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
func ReceiveAPIMessage(conn net.Conn) (rspType uint16, rspMsgBuf []byte, err error) {
	lengthTypeBuf := make([]byte, LENGTH_OF_HEADER)
	n, err := io.ReadFull(conn, lengthTypeBuf)
	if err == io.EOF {
		logger.Info.Println("API connection at " + conn.RemoteAddr().String() + " disconnected")
		return 0, nil, errors.New("DisconnectedError")
	}
	if err != nil || n != LENGTH_OF_HEADER {
		logger.Error.Println("Error reading size and type from incoming API message")
		return 0, nil, errors.New("NetworkError")
	}
	rspLength := binary.BigEndian.Uint16(lengthTypeBuf[:LENGTH_OF_SIZE])
	rspType = binary.BigEndian.Uint16(lengthTypeBuf[LENGTH_OF_SIZE:LENGTH_OF_HEADER])
	rspBuf := make([]byte, rspLength-LENGTH_OF_HEADER)
	n, err = io.ReadFull(conn, rspBuf)
	if err != nil || n != int(rspLength-LENGTH_OF_HEADER) {
		logger.Error.Println("Error reading incoming API message of size " + strconv.Itoa(int(rspLength)) + " (read size: " + strconv.Itoa(n) + ")")
		return 0, nil, errors.New("NetworkError")
	}
	return rspType, rspBuf, nil
}

func RPSQuery() (err error, peerAddress net.IP, peerAddressIsIPv6 bool, peerOnionPort uint16, peerHostkey *rsa.PublicKey) {
	logger.Info.Println("Soliciting random peer")
	conn, err := net.Dial("tcp", config.RpsAddress)
	if err != nil {
		logger.Error.Println("Could not connect to RPS module at " + config.RpsAddress + " (error: " + err.Error() + ")")
		return errors.New("NetworkError"), nil, false, 0, nil
	}
	defer conn.Close()
	err = SendAPIMessage(conn, RPS_QUERY, nil)
	if err != nil {
		logger.Error.Println("Could not send RPS QUERY message to RPS module")
		return errors.New("NetworkError"), nil, false, 0, nil
	}
	rspType, rspBuf, err := ReceiveAPIMessage(conn)
	if err != nil {
		logger.Error.Println("Could not receive RPS QUERY response")
		return errors.New("NetworkError"), nil, false, 0, nil
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
