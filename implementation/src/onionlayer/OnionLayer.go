package onionlayer

import (
	"container/list"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"net"
	"onion/api"
	"onion/config"
	"onion/dh"
	"onion/encryption"
	"onion/hoplayer"
	"onion/logger"
	"onion/storage"
	"strconv"
	"time"
)

const (
	// TODO move timeout to config?
	// timeout
	RESP_TIMEOUT              = 5 * time.Second
	TUNNEL_INACTIVITY_TIMEOUT = 10 * time.Second
	PUBKEY_LENGTH             = 178

	MSG_KEYXCHG     uint8 = 0x00
	MSG_KEYXCHGRESP uint8 = 0x01
	MSG_EXTEND      uint8 = 0x02
	MSG_COMPLETE    uint8 = 0x03
	MSG_COMPLETED   uint8 = 0x04
	MSG_FORWARD     uint8 = 0x05
	MSG_DATA        uint8 = 0x06
	// TODO send destroy message to initiator if no connection and destination wants this tunnel
	// 	initiator then removes the tunnel as if someone sent TUNNEL DESTROY to it
	MSG_DESTROY   uint8 = 0x07
	MSG_KEEPALIVE uint8 = 0x08

	LOCAL_FORWARDER string = "_localhost_"
)

// TODO create cleanup function that e.g. closes the UDP connection when the program exits
// TODO if we ever get an unexpected message from a peer, send a reset and forget that peer / disconnect it (can we get tunnels etc. by peer address?)

var tunnels = storage.InitTunnels()
var notifyGroups = storage.InitNotifyGroups()
var forwarders = storage.InitForwarders()

// This list is only used to avoid TPort collisions (the tuple (peerAddressString, TPort) is assumed to be unique)
var peerTPorts = storage.InitPeerTPorts()
var udpconn *net.UDPConn

func handleAPIRequest(conn net.Conn, msgType uint16, data []byte) error {
	switch msgType {
	case api.ONION_TUNNEL_DATA:
		tunnelID := binary.BigEndian.Uint32(data[:4])
		err := sendData(tunnelID, data[4:])
		if err != nil {
			logger.Error.Println("Could not send data into tunnel " + strconv.Itoa(int(tunnelID)) + " as requested by API")
			return errors.New("OnionError")
		}
	default:
		logger.Error.Println("Got unknown API message type: " + strconv.Itoa(int(msgType)) + " from " + conn.RemoteAddr().String())
		return errors.New("ArgumentError")
	}
	return nil
}

func Initialize() error {
	listeningAddress := config.P2p_hostname + ":" + strconv.Itoa(config.P2p_port)
	var err error
	udpconn, err = hoplayer.SetPacketReceiver(listeningAddress, handleIncomingPacket)
	if err != nil {
		logger.Error.Println("Could not set packet receiver")
		return errors.New("NetworkError")
	}
	api.RegisterOnionLayerHandler(handleAPIRequest)
	logger.Info.Println("OnionLayer has been initialized")
	return nil
}

// generate a random 32 bit unsigned integer from the crypto/rand pseudo random number generator
func generateRandomUInt32() (result uint32, err error) {
	buffer := make([]byte, 4)
	n, err := rand.Read(buffer)
	if err != nil || n != 4 {
		logger.Error.Println("Crypto random reader returned error or read wrong number of bytes")
		return 0, errors.New("CryptoError")
	}
	result = binary.LittleEndian.Uint32(buffer)
	return result, nil
}

func generateAndClaimUnusedTPort(peerAddress string) (result uint32, err error) {
	for result, err = generateRandomUInt32(); err != nil || storage.AddPeerTPort(peerTPorts, peerAddress, result) != nil; result, err = generateRandomUInt32() {
		if err != nil {
			logger.Error.Println("Could not generate new random TPort")
			return 0, errors.New("InternalError")
		}
	}
	return result, nil
}

func peerAddressToString(address net.IP, addressIsIPv6 bool, port uint16) string {
	if addressIsIPv6 {
		return "[" + address.String() + "]:" + strconv.Itoa(int(port))
	} else {
		return address.String() + ":" + strconv.Itoa(int(port))
	}
}

func getPeerIdentifier(peerAddress string, tunnelID uint32) (identifier string) {
	return peerAddress + ":" + strconv.Itoa(int(tunnelID))
}

func watchForwarder(forwarder *storage.Forwarder) {
	removeForwarder := false
	for {
		if removeForwarder {
			// TODO remove the tunnel and potential TPorts that belong to this forwarder
			var hop *storage.Hop
			if forwarder.TType == storage.TUNNEL_TYPE_INITIATOR {
				hop = forwarder.NextHop
			} else {
				hop = forwarder.PreviousHop
			}
			forwarderIdentifier := getPeerIdentifier(hop.Address, hop.TPort)
			logger.Info.Println("Removing watcher and forwarder for " + forwarderIdentifier)
			storage.DeleteForwarder(forwarders, forwarderIdentifier)
			break
		}
		// check if last message has been too long ago
		timeSinceLastMsg := time.Now().Sub(forwarder.LastMessageTime)
		if timeSinceLastMsg > TUNNEL_INACTIVITY_TIMEOUT {
			logger.Warning.Println("Tunnel timed out after " + strconv.FormatFloat(timeSinceLastMsg.Seconds(), 'g', 0, 64) + " seconds")
			removeForwarder = true
		}
		// check if it has been requested to remove this forwarder
		if forwarder.RemoveForwarder {
			removeForwarder = true
		}
	}
}

func encryptAndAddSeqNum(forwarder *storage.Forwarder, forwarderIdentifier string, data []byte) ([]byte, error) {
	seqNumBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(seqNumBuf, forwarder.SendingSeqNum)
	forwarder.SendingSeqNum++
	msgBuf := append(seqNumBuf, data...)
	encryptedPacket, err := encryption.Encrypt(forwarder.SharedSecret, msgBuf)
	if err != nil {
		logger.Error.Println("Could not encrypt packet from " + forwarderIdentifier)
		return nil, errors.New("CryptoError")
	}
	return encryptedPacket, nil
}

func decryptAndCheckSeqNum(forwarder *storage.Forwarder, forwarderIdentifier string, data []byte) ([]byte, error) {
	msg, err := encryption.Decrypt(forwarder.SharedSecret, data)
	if err != nil {
		logger.Error.Println("Could not decrypt message from known peer " + forwarderIdentifier)
		return nil, errors.New("CryptoError")
	}
	seqNum := binary.BigEndian.Uint32(msg[0:4])
	// check sequence number
	if forwarder.ReceivingSeqNum > seqNum {
		logger.Warning.Println("Got message with repeating sequence number from peer " + forwarderIdentifier + " (expected " + strconv.Itoa(int(forwarder.ReceivingSeqNum)) + ", got " + strconv.Itoa(int(seqNum)) + ")")
		return nil, errors.New("ProtocolError")
	}
	if forwarder.ReceivingSeqNum < seqNum {
		logger.Info.Println("Received sequence number higher " + strconv.Itoa(int(seqNum)) + " than expected sequence number " + strconv.Itoa(int(forwarder.ReceivingSeqNum)) + ", assuming missed packets (peer " + forwarderIdentifier + ")")
	}
	forwarder.ReceivingSeqNum = seqNum + 1
	return msg[4:], nil
}

func handleIncomingPacket(addr *net.UDPAddr, data []byte) {
	if len(data) < 10 {
		logger.Warning.Println("Received packet is too short (size " + strconv.Itoa(len(data)) + ")")
		return
	}
	// find the local forwarder this packet is meant for
	tPort := binary.BigEndian.Uint32(data[:4])
	peerAddressString := peerAddressToString(addr.IP, addr.IP.To4() == nil, uint16(addr.Port))
	forwarderIdentifier := getPeerIdentifier(peerAddressString, tPort)
	forwarder, exists := storage.GetForwarder(forwarders, forwarderIdentifier)
	if !exists {
		// seq num is unencrypted on the onion layer for KEYXCHG
		seqNum := binary.BigEndian.Uint32(data[4:8])
		// TODO
		// if it is not a keyxchg, answer with a reset message
		logger.Info.Println("Got unknown TPort / address combination, assuming KEYXCHG: " + forwarderIdentifier)
		privateKey, publicKey, err := dh.GenKeyPair()
		if err != nil {
			logger.Error.Println("Could not generate keypair for KEYXCHGRESP for peer " + forwarderIdentifier)
			return
		}
		encryptedPeerPublicKey := data[9:]
		logger.Info.Println("Got encrypted DH nonce of length " + strconv.Itoa(len(encryptedPeerPublicKey)))
		peerPublicKey, err := encryption.DecryptAsymmetric(config.PrivateKey, encryptedPeerPublicKey)
		if err != nil {
			logger.Error.Println("Could not decrypt peer public key - wrong key?")
			return
		}
		if len(peerPublicKey) != PUBKEY_LENGTH {
			logger.Error.Println("Got public key of wrong size from peer " + forwarderIdentifier + " (got length " + strconv.Itoa(len(peerPublicKey)) + ")")
			return
		}
		sharedSecret, err := dh.DeriveSharedSecret(privateKey, peerPublicKey)
		if err != nil {
			logger.Error.Println("Could not derivce shared secret from KEYXCHG message from peer " + forwarderIdentifier)
			return
		}
		newForwarder := &storage.Forwarder{
			NextHop: nil,
			PreviousHop: &storage.Hop{
				TPort:   tPort,
				Address: peerAddressString,
			},
			TType:           storage.TUNNEL_TYPE_HOP_OR_DESTINATION,
			ReceivingSeqNum: seqNum + 1,
			SendingSeqNum:   0,
			DHPublicKey:     peerPublicKey,
			DHPrivateKey:    privateKey,
			SharedSecret:    sharedSecret,
			LastMessageTime: time.Now(),
			RemoveForwarder: false,
		}
		storage.SetForwarder(forwarders, forwarderIdentifier, newForwarder)
		logger.Info.Println("Created new forwarder with identifier " + forwarderIdentifier)
		go watchForwarder(forwarder)
		// generate KEYXCHGRESP
		respBuf := make([]byte, 5)
		binary.BigEndian.PutUint32(respBuf[0:4], newForwarder.SendingSeqNum)
		newForwarder.SendingSeqNum++
		respBuf[4] = MSG_KEYXCHGRESP
		respBuf = append(respBuf, publicKey...)
		err = sendMessage(newForwarder, false, respBuf)
		if err != nil {
			logger.Error.Println("Could not send KEYXCHGRESP message")
			return
		}
		return
	}
	// update forwarders last message time
	forwarder.LastMessageTime = time.Now()
	// check forwarder type, this could be a KEYXCHGRESP
	switch forwarder.TType {
	case storage.TUNNEL_TYPE_INITIATOR:
		// get tunnel
		tunnel, exists := storage.GetTunnel(tunnels, forwarder.TunnelID)
		if !exists {
			logger.Error.Println("Could not find tunnel by ID even though I am the initiator: " + strconv.Itoa(int(forwarder.TunnelID)))
			return
		}
		data = data[4:]
		if tunnel.Peers.Len() != 1 {
			// decrypt all but the last hop since it might not be encrypted if it is a KEYXCHGRESP
			for cur := tunnel.Peers.Front(); cur != nil && cur.Next() != nil; cur = cur.Next() {
				curPeer, typeCheck := cur.Value.(*storage.OnionPeer)
				if !typeCheck {
					logger.Error.Println("Got wrong type from peers list; message from " + forwarderIdentifier)
					return
				}
				logger.Info.Println("Decrypting message with curPeer " + curPeer.Address)
				decryptedMsg, err := encryption.Decrypt(curPeer.SharedSecret, data)
				if err != nil {
					logger.Warning.Println("Could not decrypt message from peer " + forwarderIdentifier + " at curPeer " + curPeer.Address)
					return
				}
				// check sequence number
				seqNum := binary.BigEndian.Uint32(decryptedMsg[:4])
				if seqNum < curPeer.ReceivingSeqNum {
					logger.Warning.Println("Got message with repeating sequence number from " + forwarderIdentifier +
						" (got " + strconv.Itoa(int(seqNum)) + ", expected " + strconv.Itoa(int(curPeer.ReceivingSeqNum)) + ")")
					return
				}
				if seqNum > curPeer.ReceivingSeqNum {
					logger.Warning.Println("Got sequence number higher than expected, some packets are probably " +
						"missing from " + forwarderIdentifier + " at curPeer " + curPeer.Address + " (expected " +
						strconv.Itoa(int(curPeer.ReceivingSeqNum)) + ", got " + strconv.Itoa(int(seqNum)) + ")")
				}
				curPeer.ReceivingSeqNum = seqNum + 1
				data = decryptedMsg[4:]
			}
		}
		// get the last hop in the tunnel, to see if we're still waiting for a key exchange with it
		lastPeer, typeCheck := tunnel.Peers.Back().Value.(*storage.OnionPeer)
		if !typeCheck {
			logger.Error.Println("Got wrong type from tunnel hop list")
			return
		}
		if lastPeer.SharedSecret == nil {
			// no shared secret, we therefore expect that we just got a KEYXCHGRESP
			logger.Info.Println("Got message from hop with no shared secret, assuming KEYXCHGRESP")
			seqNum := binary.BigEndian.Uint32(data[:4])
			if data[4] != MSG_KEYXCHGRESP {
				logger.Warning.Println("Expected KEYXCHGRESP but got message of type " + strconv.Itoa(int(data[4])))
				return
			}
			logger.Info.Println("Got DH public key for tunnel " + strconv.Itoa(int(forwarder.TunnelID)) + " of length " + strconv.Itoa(len(data[5:])))
			lastPeer.ReceivingSeqNum = seqNum + 1
			lastPeer.DHPublicKey = data[5:]
			storage.BroadcastNotifyGroup(notifyGroups, strconv.Itoa(int(forwarder.TunnelID)))
			return
		} else {
			decryptedMsg, err := encryption.Decrypt(lastPeer.SharedSecret, data)
			if err != nil {
				logger.Warning.Println("Could not decrypt message from destination peer " + lastPeer.Address)
				return
			}
			// check sequence number
			seqNum := binary.BigEndian.Uint32(decryptedMsg[:4])
			if seqNum < lastPeer.ReceivingSeqNum {
				logger.Warning.Println("Got message with repeating sequence number from " + forwarderIdentifier +
					" (got " + strconv.Itoa(int(seqNum)) + ", expected " + strconv.Itoa(int(lastPeer.ReceivingSeqNum)) + ")")
				return
			}
			if seqNum > lastPeer.ReceivingSeqNum {
				logger.Warning.Println("Got sequence number higher than expected, some packets are probably " +
					"missing from " + forwarderIdentifier + " at curPeer " + lastPeer.Address + " (expected " +
					strconv.Itoa(int(lastPeer.ReceivingSeqNum)) + ", got " + strconv.Itoa(int(seqNum)) + ")")
			}
			lastPeer.ReceivingSeqNum = seqNum + 1
			decryptedMsg = decryptedMsg[4:]
			switch decryptedMsg[0] {
			case MSG_COMPLETED:
				tunnelIDString := strconv.Itoa(int(forwarder.TunnelID))
				logger.Info.Println("Got COMPLETED message for tunnel " + tunnelIDString)
				tunnel.Completed = true
				storage.BroadcastNotifyGroup(notifyGroups, tunnelIDString)
			case MSG_DATA:
				logger.Info.Println("Got DATA as initiator: " + string(decryptedMsg[1:]))
				// TODO send data to API
			default:
				logger.Warning.Println("Got wrong message type from tunnel " + strconv.Itoa(int(forwarder.TunnelID)) +
					", expected COMPLETED or DATA, got " + strconv.Itoa(int(decryptedMsg[0])))
				return
			}
		}
	case storage.TUNNEL_TYPE_HOP_OR_DESTINATION:
		// we had our key exchange and now we find out whether we're the last hop or an intermediate
		// decrypt
		msg, err := decryptAndCheckSeqNum(forwarder, forwarderIdentifier, data[4:])
		if err != nil {
			logger.Error.Println("Could not decrypt message from peer or sequence number invalid " + forwarderIdentifier)
			return
		}
		switch msg[0] {
		case MSG_EXTEND:
			forwarder.TType = storage.TUNNEL_TYPE_HOP
			// extract data from message
			peerAddressIsIPv6 := msg[1] == 0x1
			ipEnd := ipLength(peerAddressIsIPv6) + 2
			var peerAddress net.IP = msg[2:ipEnd]
			onionPort := binary.BigEndian.Uint16(msg[ipEnd : ipEnd+2])
			encryptedNonce := msg[ipEnd+2:]
			nextHopAddress := peerAddressToString(peerAddress, peerAddressIsIPv6, onionPort)
			logger.Info.Println("Got EXTEND message with data: peerAddressIsIPv6: " + strconv.FormatBool(peerAddressIsIPv6) + ", peerAddress: " + peerAddress.String() + ", onionPort: " + strconv.Itoa(int(onionPort)))
			// store this peer as our next hop
			tPort, err := generateAndClaimUnusedTPort(nextHopAddress)
			if err != nil {
				logger.Error.Println("Could not generate TPort for next hop")
				return
			}
			forwarder.NextHop = &storage.Hop{
				TPort:   tPort,
				Address: nextHopAddress,
			}
			newForwarderIdentifier := getPeerIdentifier(nextHopAddress, tPort)
			// since we're working with pointers we should now just have a second entry pointing to the same forwarder
			storage.SetForwarder(forwarders, newForwarderIdentifier, forwarder)
			logger.Info.Println("Created new forwarder with identifier " + newForwarderIdentifier)
			// create KEYXCHG message and send it to the peer given
			msgBuf := make([]byte, 5)
			binary.BigEndian.PutUint32(msgBuf[0:4], 0)
			msgBuf[4] = MSG_KEYXCHG
			msgBuf = append(msgBuf, encryptedNonce...)
			err = sendMessage(forwarder, true, msgBuf)
			if err != nil {
				logger.Warning.Println("Could not forward KEYXCHG to peer " + nextHopAddress)
				return
			}
			return
		case MSG_COMPLETE:
			logger.Info.Println("Got COMPLETE message from " + forwarderIdentifier)
			forwarder.TType = storage.TUNNEL_TYPE_DESTINATION
			tunnelID, err := generateAndClaimUnusedTPort(LOCAL_FORWARDER)
			if err != nil {
				logger.Error.Println("Could not generate tunnelID for incoming tunnel")
				return
			}
			tunnel := &storage.Tunnel{
				Completed:           true,
				Initiator:           false,
				ForwarderIdentifier: forwarderIdentifier,
			}
			storage.SetTunnel(tunnels, tunnelID, tunnel)
			// this is not the prettiest solution, but since the destination never has a next hop it should work fine
			forwarder.NextHop = &storage.Hop{
				TPort:   tunnelID,
				Address: LOCAL_FORWARDER,
			}
			msgBuf, err := encryptAndAddSeqNum(forwarder, forwarderIdentifier, []byte{MSG_COMPLETED})
			if err != nil {
				logger.Error.Println("Could not encrypt COMPLETED message for forwarder " + forwarderIdentifier)
				return
			}
			err = sendMessage(forwarder, false, msgBuf)
			if err != nil {
				logger.Error.Println("Could not send COMPLETED message")
				return
			}
			tunnelIDBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(tunnelIDBuf, tunnelID)
			logger.Info.Println("Broadcasting new tunnel with ID " + strconv.Itoa(int(tunnelID)) + " to all API connections")
			err = api.SendAllAPIConnections(api.ONION_TUNNEL_INCOMING, tunnelIDBuf)
			if err != nil {
				logger.Error.Println("Could not send API message to all connections for ONION_TUNNEL_INCOMING")
				return
			}
		default:
			logger.Error.Println("Got unexpected message type, expecting EXTEND or COMPLETE: " + strconv.Itoa(int(msg[0])))
			return
		}
	case storage.TUNNEL_TYPE_HOP:
		// send forward or backwards?
		matchesPrevious := (forwarder.PreviousHop.Address == peerAddressString) && (forwarder.PreviousHop.TPort == tPort)
		matchesNext := (forwarder.NextHop.Address == peerAddressString) && (forwarder.NextHop.TPort == tPort)
		if matchesPrevious {
			// send forward
			decryptedMsg, err := decryptAndCheckSeqNum(forwarder, forwarderIdentifier, data[4:])
			if err != nil {
				logger.Error.Println("Could not decrypt message or sequence number invalid from peer " + forwarderIdentifier)
				return
			}
			switch decryptedMsg[0] {
			case MSG_FORWARD:
				// add our tPort and send along to next hop
				logger.Info.Println("Sending forward in tunnel data from " + forwarderIdentifier + " (initial length " + strconv.Itoa(len(data[4:])) + ") of length " + strconv.Itoa(len(decryptedMsg)))
				err := sendMessage(forwarder, true, decryptedMsg[1:])
				if err != nil {
					logger.Error.Println("Could not forward data from " + forwarderIdentifier)
					return
				}
				return
			default:
				logger.Error.Println("Got non-forward message as hop from " + forwarderIdentifier)
				return
			}
		} else if matchesNext {
			// put our own layer around it, add tPort and send to previous hop
			encryptedMsg, err := encryptAndAddSeqNum(forwarder, forwarderIdentifier, data[4:])
			if err != nil {
				logger.Error.Println("Could not encrypt message from " + forwarderIdentifier)
				return
			}
			logger.Info.Println("Sending backward in tunnel data from " + forwarderIdentifier + " (initial length " + strconv.Itoa(len(data[4:])) + ") of length " + strconv.Itoa(len(encryptedMsg)))
			err = sendMessage(forwarder, false, encryptedMsg)
			if err != nil {
				logger.Error.Println("Could not send data from " + forwarderIdentifier + " backwards through tunnel")
				return
			}
			return
		} else {
			logger.Error.Println("Incoming packet matches neither previous nor next hop (from " + forwarderIdentifier + ")")
			return
		}
	case storage.TUNNEL_TYPE_DESTINATION:
		decryptedMsg, err := decryptAndCheckSeqNum(forwarder, forwarderIdentifier, data[4:])
		if err != nil {
			logger.Error.Println("Could not decrypt message or sequence number invalid from peer " + forwarderIdentifier)
			return
		}
		switch decryptedMsg[0] {
		case MSG_DATA:
			// get tunnel ID from forwarder
			tunnelID := forwarder.NextHop.TPort
			logger.Info.Println("Got DATA from tunnel with ID " + strconv.Itoa(int(tunnelID)) + ": " + string(decryptedMsg[1:]))
			// TODO broadcast data to the API connections (ONION TUNNEL DATA)
		default:
			logger.Error.Println("Got unexpected message type as tunnel destination (expected MSG_DATA): " + strconv.Itoa(int(decryptedMsg[0])))
			return
		}
	}
}

func ipLength(addressIsIPv6 bool) int {
	if addressIsIPv6 {
		return net.IPv6len
	} else {
		return net.IPv4len
	}
}

// sendMessage assumes that data is an encrypted packet with the following fields:
// seqNum, msgType, data
func sendMessage(forwarder *storage.Forwarder, sendForward bool, data []byte) error {
	var hop *storage.Hop
	if sendForward {
		hop = forwarder.NextHop
	} else {
		hop = forwarder.PreviousHop
	}
	msgBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(msgBuf[0:4], hop.TPort)
	msgBuf = append(msgBuf, data...)
	logger.Info.Println("Sending packet with TPort " + strconv.Itoa(int(hop.TPort)) + " to address " + hop.Address)
	err := hoplayer.SendPacket(udpconn, hop.Address, msgBuf)
	if err != nil {
		logger.Error.Println("Could not send message to " + hop.Address)
		return errors.New("NetworkError")
	}
	return nil
}

// sendIntoTunnel expects a message like [msgType, data...]
func sendIntoTunnel(tunnelID uint32, data []byte, skipLast bool) error {
	tunnel, exists := storage.GetTunnel(tunnels, tunnelID)
	if !exists {
		logger.Error.Println("Could not find tunnel to send packet into")
		return errors.New("ArgumentError")
	}
	// wrap message once for each hop (in reverse order)
	msgBuf := data
	for cur := tunnel.Peers.Back(); cur != nil; cur = cur.Prev() {
		if skipLast && cur.Next() == nil {
			continue
		}
		curHop, typeCheck := cur.Value.(*storage.OnionPeer)
		if !typeCheck {
			logger.Error.Println("Got object of wrong type from peer list")
			return errors.New("InternalError")
		}
		// header
		curHeaderBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(curHeaderBuf[:4], curHop.SendingSeqNum)
		curHop.SendingSeqNum++
		if !(cur.Next() == nil || (skipLast && cur.Next().Next() == nil)) {
			logger.Info.Println("Adding MSG_FORWARD for hop " + curHop.Address)
			curHeaderBuf = append(curHeaderBuf, MSG_FORWARD)
		}
		msgBuf = append(curHeaderBuf, msgBuf...)
		var err error
		msgBuf, err = encryption.Encrypt(curHop.SharedSecret, msgBuf)
		if err != nil {
			logger.Error.Println("Could not encrypt message for hop " + curHop.Address)
			return errors.New("CryptoError")
		}
	}
	if tunnel.Peers.Front() == nil {
		logger.Error.Println("Trying to send packet into tunnel with no hops")
		return errors.New("ArgumentError")
	}
	firstHop, typeCheck := tunnel.Peers.Front().Value.(*storage.OnionPeer)
	if !typeCheck {
		logger.Error.Println("Got object of wrong type from peer list")
		return errors.New("InternalError")
	}
	sendToAddress := firstHop.Address
	// get forwarder
	forwarder, exists := storage.GetForwarder(forwarders, tunnel.ForwarderIdentifier)
	if !exists {
		logger.Error.Println("Could not find forwarder with identifier " + tunnel.ForwarderIdentifier + " for tunnel " + strconv.Itoa(int(tunnelID)))
		return errors.New("internalError")
	}
	tPortBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(tPortBuf, forwarder.NextHop.TPort)
	msgBuf = append(tPortBuf, msgBuf...)
	err := hoplayer.SendPacket(udpconn, sendToAddress, msgBuf)
	if err != nil {
		logger.Error.Println("Packet could not be sent to peer " + sendToAddress)
		return errors.New("NetworkError")
	}
	return nil
}

// BuildTunnel (blocking) creates an onion tunnel with the given final peer. If the build is successful the function
// returns the ID of the tunnel that was built as a uint32. If it was not successful, the ID is 0 and error is set.
// BuildTunnel exits on error, so if the creation was unsuccessful it may be tried again by calling BuildTunnel again.
// Onion messages have this format:
// 0        8        16        24        32
// [---------------TPort------------------]
// [------------SequenceNumber------------]
// [msgType||----------------data---------]
// [--------------contd. data-------------]
// message Types:
//		- 0x00 KEYXCHG		Indicates that the message data contains a Diffie-Hellman nonce encrypted with the receiving hosts public key. Response of type KEYXCHGRESP expected.
//		- 0x01 KEYXCHGRESP	Indicates that the message data contains a Diffie-Hellman nonce encrypted with the receiving hosts public key. May only be sent in response to KEYXCHG.
// For every peer we store the following data:
//		- a symmetric key used for encryption of onion layer messages
//		- the TPort used to indentify this tunnel with the peer
//		-
func BuildTunnel(finalHopAddress net.IP, finalHopAddressIsIPv6 bool, finalHopPort uint16, finalHopHostKey *rsa.PublicKey) (tunnelID uint32, err error) {
	// DONE
	// - get the public key of the final hop -> We get this as part of the "ONION TUNNEL BUILD" message
	// TODO
	//		- get two peers to use as hops including their respective public keys and onion addresses / ports -> RPS gives us all this information
	//		- generate diffie hellman nonce and encrypt it with the first hop's public key
	//		- generate a tunnel ID to use towards the first hop and a tunnel ID to use towards the API
	//		- send to first hop: tunnel ID, IP version / IP of next hop, encrypted DH nonce
	//		- wait for response; if response does not happen within a certain timeframe (e.g. one second) we can either resend or choose a new hop
	//		- derive ephemeral symmetric key for this hop
	//		- do the same for the second and third hop
	//		- enable keepalive messages (or is this already required before?)
	//		- make API send message that tunnel creation was successful (what can we do in case of failure?)

	for tunnelID, err = generateRandomUInt32(); err != nil || storage.ExistsTunnel(tunnels, tunnelID); tunnelID, err = generateRandomUInt32() {
		if err != nil {
			logger.Error.Println("Could not generate new random tunnelID")
			return 0, errors.New("InternalError")
		}
	}
	destinationPeerAddress := peerAddressToString(finalHopAddress, finalHopAddressIsIPv6, finalHopPort)

	sourceForwarder := &storage.Forwarder{
		NextHop:     nil,
		PreviousHop: nil,
		TType:       storage.TUNNEL_TYPE_INITIATOR,
		TunnelID:    tunnelID,
		RemoveForwarder: false,
	}
	curTunnel := &storage.Tunnel{
		Peers:     list.New(),
		Completed: false,
		Initiator: true,
	}
	storage.SetTunnel(tunnels, tunnelID, curTunnel)
	for curTunnel.Peers.Len() < config.Intermediate_hops+1 {
		logger.Info.Println("Building tunnel (ID " + strconv.Itoa(int(tunnelID)) + "), got " + strconv.Itoa(curTunnel.Peers.Len()) + " of " + strconv.Itoa(config.Intermediate_hops) + " hops")
		var peerAddress net.IP
		var peerAddressIsIPv6 bool
		var peerOnionPort uint16
		var peerHostkey *rsa.PublicKey
		var peerAddressString string
		if curTunnel.Peers.Len() == config.Intermediate_hops {
			logger.Info.Println("Adding final peer (destination) to tunnel " + strconv.Itoa(int(tunnelID)))
			peerAddress = finalHopAddress
			peerAddressIsIPv6 = finalHopAddressIsIPv6
			peerOnionPort = finalHopPort
			peerHostkey = finalHopHostKey
			peerAddressString = peerAddressToString(peerAddress, peerAddressIsIPv6, peerOnionPort)
		} else {
			var err error
			err, peerAddress, peerAddressIsIPv6, peerOnionPort, peerHostkey = api.RPSQuery()
			if err != nil {
				logger.Warning.Println("Could not solicit peer from RPS")
				continue
			}
			peerAddressString = peerAddressToString(peerAddress, peerAddressIsIPv6, peerOnionPort)
			skipPeer := false
			for cur := curTunnel.Peers.Front(); cur != nil; cur = cur.Next() {
				curHop, typeCheck := cur.Value.(*storage.OnionPeer)
				if !typeCheck {
					logger.Warning.Println("Got object of wrong type from peer list")
					continue
				}
				if curHop.Address == peerAddressString || curHop.Address == destinationPeerAddress {
					skipPeer = true
					break
				}
			}
			if skipPeer {
				logger.Warning.Println("Peer solicited from RPS is already part of the tunnel or the destination, skipping: " + peerAddressString)
				continue
			}
		}
		logger.Info.Println("Attempting to add peer at address " + peerAddressString + " to tunnel " + strconv.Itoa(int(tunnelID)))
		// Generate DH nonce, encrypt it and send KEYXCHG to this peer
		privateKey, publicKey, err := dh.GenKeyPair()
		if err != nil {
			logger.Warning.Println("Could not generate keypair")
			continue
		}
		curPeer := &storage.OnionPeer{
			Address:         peerAddressString,
			ReceivingSeqNum: 0,
			Hostkey:         peerHostkey,
			DHPrivateKey:    privateKey,
		}
		curTunnel.Peers.PushBack(curPeer)
		// encrypt DH nonce with the peer's public key
		encryptedNonce, err := encryption.EncryptAsymmetric(peerHostkey, publicKey)
		if err != nil {
			logger.Warning.Println("Could not encrypt DH nonce with hosts public key, peer " + peerAddressString)
			continue
		}
		// special case for the first hop since we can set the tport and have to send KEYXCHG instead of EXTEND
		if curTunnel.Peers.Len() <= 1 {
			curPeer.SendingSeqNum = 0
			tPortReverse, err := generateAndClaimUnusedTPort(peerAddressString)
			if err != nil {
				logger.Warning.Println("Could not generate TPort for communication with first hop: " + peerAddressString)
				continue
			}
			msgBuf := make([]byte, 5)
			binary.BigEndian.PutUint32(msgBuf[0:4], curPeer.SendingSeqNum)
			curPeer.SendingSeqNum++
			msgBuf[4] = MSG_KEYXCHG
			msgBuf = append(msgBuf, encryptedNonce...)
			sourceForwarder.NextHop = &storage.Hop{
				TPort:   tPortReverse,
				Address: peerAddressString,
			}
			forwarderIdentifier := getPeerIdentifier(peerAddressString, tPortReverse)
			storage.SetForwarder(forwarders, forwarderIdentifier, sourceForwarder)
			curTunnel.ForwarderIdentifier = forwarderIdentifier
			logger.Info.Println("Created new forwarder with identifier " + forwarderIdentifier)
			err = sendMessage(sourceForwarder, true, msgBuf)
			if err != nil {
				logger.Warning.Println("Could not send DH keyexchange to peer " + peerAddressString)
				continue
			}
		} else {
			curPeer.SendingSeqNum = 1
			var peerAddressIsIPv6Byte byte
			if peerAddressIsIPv6 {
				peerAddressIsIPv6Byte = 1
			} else {
				peerAddressIsIPv6Byte = 0
			}
			onionPortBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(onionPortBytes, peerOnionPort)
			var msgBuf []byte
			msgBuf = append(msgBuf, MSG_EXTEND, peerAddressIsIPv6Byte)
			if peerAddressIsIPv6 {
				// copy 16 bytes
				msgBuf = append(msgBuf, peerAddress.To16()...)
			} else {
				// copy 4 bytes
				msgBuf = append(msgBuf, peerAddress.To4()...)
			}
			msgBuf = append(msgBuf, onionPortBytes...)
			msgBuf = append(msgBuf, encryptedNonce...)
			err = sendIntoTunnel(tunnelID, msgBuf, true)
			if err != nil {
				logger.Warning.Println("Could not send extend message to peer " + peerAddressString)
				continue
			}
		}
		// Five second timeout, so the response might not be there afterwards
		// If it is here: awesome, carry on. If it is not: Remove new peer from hop list (last element) and if the list
		// is then empty (so it was the first peer) also reset sourceForwarder.NextHop
		tunnelIDString := strconv.Itoa(int(tunnelID))
		storage.WaitForNotifyGroup(notifyGroups, tunnelIDString, RESP_TIMEOUT)
		storage.CleanupNotifyGroup(notifyGroups, tunnelIDString)
		// if we got a response then the DH public key of the last hop is now set
		if curPeer.DHPublicKey == nil {
			// response timed out, clear data and try another peer
			logger.Info.Println("KEYXCHG message to peer " + peerAddressString + " timed out, trying another peer")
			curTunnel.Peers.Remove(curTunnel.Peers.Back())
			if curTunnel.Peers.Len() == 0 {
				sourceForwarder.NextHop = nil
			}
			continue
		}
		logger.Info.Println("Got KEYXCHGRESP from " + peerAddressString + ", deriving shared secret")
		sharedSecret, err := dh.DeriveSharedSecret(curPeer.DHPrivateKey, curPeer.DHPublicKey)
		if err != nil {
			logger.Warning.Println("Could not derive shared secret for peer " + peerAddressString)
			curTunnel.Peers.Remove(curTunnel.Peers.Back())
			if curTunnel.Peers.Len() == 0 {
				sourceForwarder.NextHop = nil
			}
			continue
		}
		curPeer.SharedSecret = sharedSecret
		logger.Info.Println("Successfully added peer " + peerAddressString + " to tunnel " + strconv.Itoa(int(tunnelID)))
	}
	destinationHop, typeCheck := curTunnel.Peers.Back().Value.(*storage.OnionPeer)
	if !typeCheck {
		logger.Error.Println("Got wrong type from peers list")
		return 0, errors.New("InternalError")
	}
	curTunnel.Destination = destinationHop
	// send COMPLETE to last hop and wait for COMPLETED
	logger.Info.Println("Sending COMPLETE to destination peer")
	err = sendIntoTunnel(tunnelID, []byte{MSG_COMPLETE}, false)
	if err != nil {
		logger.Error.Println("Could not send COMPLETE to destination peer")
		return 0, errors.New("NetworkError")
	}
	tunnelIDString := strconv.Itoa(int(tunnelID))
	storage.WaitForNotifyGroup(notifyGroups, tunnelIDString, RESP_TIMEOUT)
	storage.CleanupNotifyGroup(notifyGroups, tunnelIDString)
	if !curTunnel.Completed {
		// we did not receive a COMPLETED message, tunnel build was therefore a failure
		// TODO cleanup tunnel and send failure to API
		// TODO remove added data from tunnels, forwarders and peerTPorts
		logger.Error.Println("Did not receive COMPLETE message in time, assuming tunnel is broken")
		return 0, errors.New("TunnelError")
	}
	sourceForwarder.LastMessageTime = time.Now()
	go watchForwarder(sourceForwarder)
	// TODO start keepalive sending routine
	// TODO notify API that tunnel is ready
	logger.Info.Println("Tunnel with ID " + strconv.Itoa(int(tunnelID)) + " built successfully")
	return tunnelID, nil
}

func sendData(tunnelID uint32, data []byte) error {
	tunnel, exists := storage.GetTunnel(tunnels, tunnelID)
	if !exists {
		logger.Error.Println("Could not get tunnel by ID " + strconv.Itoa(int(tunnelID)))
		return errors.New("ArgumentError")
	}
	if tunnel.Initiator {
		// we're the tunnel's initiator, so wrap the data and then send it into the tunnel
		msgBuf := append([]byte{MSG_DATA}, data...)
		err := sendIntoTunnel(tunnelID, msgBuf, false)
		if err != nil {
			logger.Error.Println("Could not send data into tunnel: " + strconv.Itoa(int(tunnelID)))
			return errors.New("TunnelError")
		}
	} else {
		// we're the tunnel destination
		forwarder, exists := storage.GetForwarder(forwarders, tunnel.ForwarderIdentifier)
		if !exists {
			logger.Error.Println("Could not find forwarder for tunnel ID " + strconv.Itoa(int(tunnelID)) + " with identifier " + tunnel.ForwarderIdentifier)
			return errors.New("InternalError")
		}
		msgBuf := append([]byte{MSG_DATA}, data...)
		msgBuf, err := encryptAndAddSeqNum(forwarder, tunnel.ForwarderIdentifier, msgBuf)
		if err != nil {
			logger.Error.Println("Could not encrypt DATA message for forwarder " + tunnel.ForwarderIdentifier)
			return errors.New("CryptoError")
		}
		err = sendMessage(forwarder, false, msgBuf)
		if err != nil {
			logger.Error.Println("Could not send DATA message")
			return errors.New("NetworkError")
		}
	}
	return nil
}

// func destroyTunnel()
// TODO
