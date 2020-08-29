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
	RESP_TIMEOUT  = 5 * time.Second
	PUBKEY_LENGTH = 178

	MSG_KEYXCHG     uint8 = 0x00
	MSG_KEYXCHGRESP uint8 = 0x01
	MSG_EXTEND      uint8 = 0x02
	MSG_COMPLETE    uint8 = 0x03
	MSG_COMPLETED	uint8 = 0x04
	MSG_FORWARD     uint8 = 0x05
	MSG_DATA        uint8 = 0x06

	LOCAL_FORWARDER string = "_localhost_"
)

// TODO create cleanup function that e.g. closes the UDP connection when the program exits
// TODO register receiver for incoming onion packets on config-defined port; maybe in init for this module?
// TODO think about how to identify peers - we could also have a list of peers in each tunnel and then identify them with a (tunnelID, index) tuple
// DONE we're going to need a way of notifying a currently waiting instance of BuildTunnel (or any other function that requires responses) when a response for it comes in:
// 		- One possible way would be a list and notifications like in the HopLayer
//		- Alternatively the waiting instance creates a channel where we send the message when it arrives

var tunnels = storage.InitTunnels()
var notifyGroups = storage.InitNotifyGroups()
var forwarders = storage.InitForwarders()

// This list is only used to avoid TPort collisions (the tuple (peerAddressString, TPort) is assumed to be unique)
var peerTPorts = storage.InitPeerTPorts()
var udpconn *net.UDPConn

func initialize() {
	listeningAddress := config.P2p_hostname + ":" + strconv.Itoa(config.P2p_port)
	var err error
	udpconn, err = hoplayer.SetPacketReceiver(listeningAddress, handleIncomingPacket)
	if err != nil {
		logger.Error.Println("Could not set packet receiver")
		return
	}
	logger.Info.Println("OnionLayer has been initialized")
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

func decryptAndCheckSeqNum(forwarder *storage.Forwarder, forwarderIdentifier string, data []byte) ([]byte, error) {
	msg, err := encryption.Decrypt(forwarder.SharedSecret, data)
	if err != nil {
		logger.Error.Println("Could not decrypt message from known peer " + forwarderIdentifier)
		return nil, errors.New("CryptoError")
	}
	seqNum := binary.BigEndian.Uint32(msg[0:4])
	// check sequence number
	if forwarder.ReceivingSeqNum > seqNum {
		logger.Warning.Println("Got message with repeating sequence number from peer " + forwarderIdentifier)
		return nil, errors.New("ProtocolError")
	}
	if forwarder.ReceivingSeqNum < seqNum {
		logger.Info.Println("Received sequence number higher " + strconv.Itoa(int(seqNum)) + " than expected sequence number" + strconv.Itoa(int(forwarder.ReceivingSeqNum)) + ", assuming missed packets (peer " + forwarderIdentifier + ")")
	}
	forwarder.ReceivingSeqNum = seqNum + 1
	return msg[5:], nil
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
		// this is an unknown peer address / tport combination, so a new tunnel is being built
		// we expect a keyxchg now and need create a new forwarder, then answer with a keyxchgresp
		// if it is not a keyxch, answer with a reset message
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
			ReceivingSeqNum: seqNum,
			SendingSeqNum:   0,
			DHPublicKey:     peerPublicKey,
			DHPrivateKey:    privateKey,
			SharedSecret:    sharedSecret,
		}
		storage.SetForwarder(forwarders, forwarderIdentifier, newForwarder)
		// generate KEYXCHGRESP
		respBuf := make([]byte, 5)
		binary.BigEndian.PutUint32(respBuf[0:4], newForwarder.SendingSeqNum)
		respBuf[4] = MSG_KEYXCHGRESP
		respBuf = append(respBuf, publicKey...)
		err = sendMessage(newForwarder, false, respBuf)
		if err != nil {
			logger.Error.Println("Could not send KEYXCHGRESP message")
			return
		}
		return
	}
	// check forwarder type, this could be a KEYXCHGRESP
	switch forwarder.TType {
	case storage.TUNNEL_TYPE_INITIATOR:
		// get tunnel
		tunnel, exists := storage.GetTunnel(tunnels, forwarder.TunnelID)
		if !exists {
			logger.Error.Println("Could not find tunnel by ID even though I am the initiator: " + strconv.Itoa(int(forwarder.TunnelID)))
			return
		}
		if tunnel.Peers.Len() != 1 {
			// TODO decrypt packet layer by layer to get to the real message
			logger.Error.Println("NOT IMPLEMENTED: KEYXCHGRESP from non-first hop")
			return
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
			seqNum := binary.BigEndian.Uint32(data[4:8])
			if data[8] != MSG_KEYXCHGRESP {
				logger.Warning.Println("Expected KEYXCHGRESP but got message of type " + strconv.Itoa(int(data[8])))
				return
			}
			logger.Info.Println("Got DH public key for tunnel " + strconv.Itoa(int(forwarder.TunnelID)) + " of length " + strconv.Itoa(len(data[9:])))
			lastPeer.ReceivingSeqNum = seqNum
			lastPeer.DHPublicKey = data[9:]
			storage.BroadcastNotifyGroup(notifyGroups, strconv.Itoa(int(forwarder.TunnelID)))
			return
		} else {
			// TODO we're a tunnel initiator and just got a message from the tunnel => decrypt and handle
		}
	case storage.TUNNEL_TYPE_HOP_OR_DESTINATION:
		// we had our key exchange and now we find out whether we're the last hop or an intermediate
		// decrypt
		msg, err := decryptAndCheckSeqNum(forwarder, forwarderIdentifier, data)
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
			forwarder.TType = storage.TUNNEL_TYPE_DESTINATION
			// TODO
		default:
			logger.Error.Println("Got unexpected message type, expecting EXTEND or COMPLETE: " + strconv.Itoa(int(msg[0])))
			return
		}
	case storage.TUNNEL_TYPE_HOP:
		decryptedMsg, err := decryptAndCheckSeqNum(forwarder, forwarderIdentifier, data[4:])
		if err != nil {
			logger.Error.Println("Could not decrypt message or sequence number invalid from peer " + forwarderIdentifier)
			return
		}
		switch decryptedMsg[0] {
		case MSG_FORWARD:
			// send forward or backwards?
			sendForward := forwarder.NextHop.TPort == tPort
			if sendForward {
				// peel onion layer, add our tPort and send along
				
			}
		default:
			logger.Error.Println("Got non-forward message as hop from " + forwarderIdentifier)
			return
		}
	case storage.TUNNEL_TYPE_DESTINATION:
		// TODO send data to API connections
	}
}

func ipLength(addressIsIPv6 bool) int {
	if addressIsIPv6 {
		return net.IPv4len
	} else {
		return net.IPv6len
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
	err := hoplayer.SendPacket(udpconn, hop.Address, msgBuf)
	if err != nil {
		logger.Error.Println("Could not send message to " + hop.Address)
		return errors.New("NetworkError")
	}
	return nil
}

// sendIntoTunnel expects a message like [msgType, data...]
func sendIntoTunnel(tunnelID uint32, data []byte) error {
	tunnel, exists := storage.GetTunnel(tunnels, tunnelID)
	if !exists {
		logger.Error.Println("Could not find tunnel to send packet into")
		return errors.New("ArgumentError")
	}

	// wrap message once for each hop (in reverse order)
	msgBuf := data
	for cur := tunnel.Peers.Back(); cur != nil; cur = cur.Prev() {
		curHop, typeCheck := cur.Value.(*storage.OnionPeer)
		if !typeCheck {
			logger.Error.Println("Got object of wrong type from peer list")
			return errors.New("InternalError")
		}
		// header
		curHeaderBuf := make([]byte, 5)
		binary.BigEndian.PutUint32(curHeaderBuf[:4], curHop.SendingSeqNum)
		curHop.SendingSeqNum++
		curHeaderBuf[4] = MSG_FORWARD
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
	tPortBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(tPortBuf, tunnel.TPort)
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
	destinationPeer := storage.OnionPeer{
		Address:         destinationPeerAddress,
		Hostkey:         finalHopHostKey,
		ReceivingSeqNum: 0,
		SendingSeqNum:   0,
	}

	sourceForwarder := &storage.Forwarder{
		NextHop:     nil,
		PreviousHop: nil,
		TType:       storage.TUNNEL_TYPE_INITIATOR,
		TunnelID:    tunnelID,
	}
	curTunnel := &storage.Tunnel{
		Peers:       list.New(),
		Destination: &destinationPeer,
	}
	storage.SetTunnel(tunnels, tunnelID, curTunnel)
	for curTunnel.Peers.Len() < config.Intermediate_hops {
		logger.Info.Println("Building tunnel (ID " + strconv.Itoa(int(tunnelID)) + "), got " + strconv.Itoa(curTunnel.Peers.Len()) + " of " + strconv.Itoa(config.Intermediate_hops) + " hops")
		err, peerAddress, peerAddressIsIPv6, peerOnionPort, peerHostkey := api.RPSQuery()
		if err != nil {
			logger.Warning.Println("Could not solicit peer from RPS")
			continue
		}
		peerAddressString := peerAddressToString(peerAddress, peerAddressIsIPv6, peerOnionPort)
		skipPeer := false
		for cur := curTunnel.Peers.Front(); cur != nil; cur = cur.Next() {
			curHop, typeCheck := cur.Value.(*storage.OnionPeer)
			if !typeCheck {
				logger.Warning.Println("Got object of wrong type from peer list")
				continue
			}
			if curHop.Address == peerAddressString {
				skipPeer = true
				break
			}
		}
		if skipPeer {
			logger.Warning.Println("Peer solicited from RPS is already part of the tunnel, skipping: " + peerAddressString)
			continue
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
			Hostkey:         peerHostkey,
			ReceivingSeqNum: 0,
			SendingSeqNum:   0,
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
			tPortReverse, err := generateAndClaimUnusedTPort(peerAddressString)
			if err != nil {
				logger.Warning.Println("Could not generate TPort for communication with first hop: " + peerAddressString)
				continue
			}
			curTunnel.TPort = tPortReverse
			msgBuf := make([]byte, 5)
			binary.BigEndian.PutUint32(msgBuf[0:4], curPeer.SendingSeqNum)
			msgBuf[4] = MSG_KEYXCHG
			msgBuf = append(msgBuf, encryptedNonce...)
			sourceForwarder.NextHop = &storage.Hop{
				TPort:   tPortReverse,
				Address: peerAddressString,
			}
			storage.SetForwarder(forwarders, getPeerIdentifier(peerAddressString, tPortReverse), sourceForwarder)
			err = sendMessage(sourceForwarder, true, msgBuf)
			if err != nil {
				logger.Warning.Println("Could not send DH keyexchange to peer " + peerAddressString)
				continue
			}
		} else {
			// TODO extend tunnel
			var peerAddressIsIPv6Byte byte
			if peerAddressIsIPv6 {
				peerAddressIsIPv6Byte = 0
			} else {
				peerAddressIsIPv6Byte = 1
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
			err = sendIntoTunnel(tunnelID, msgBuf)
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
			continue
		}
		curPeer.SharedSecret = sharedSecret
		logger.Info.Println("Successfully added peer " + peerAddressString + " to tunnel " + strconv.Itoa(int(tunnelID)))
	}
	return tunnelID, nil
}

// func destroyTunnel()
