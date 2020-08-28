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
	MSG_FORWARD     uint8 = 0x04
	MSG_DATA        uint8 = 0x05

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

func init() {
	listeningAddress := config.P2p_hostname + ":" + strconv.Itoa(config.P2p_port)
	var err error
	udpconn, err = hoplayer.SetPacketReceiver(listeningAddress, handleIncomingPacket)
	if err != nil {
		logger.Error.Println("Could not set packet receiver")
		return
	}
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
		logger.Info.Println("Got unknown tport / address combination, assuming KEYXCHG or KEYXCHGRESP: " + forwarderIdentifier)
		switch data[8] {
		case MSG_KEYXCHG:
			privateKey, publicKey, err := dh.GenKeyPair()
			if err != nil {
				logger.Error.Println("Could not generate keypair for KEYXCHGRESP for peer " + forwarderIdentifier)
				return
			}
			peerPublicKey := data[9:]
			if len(peerPublicKey) != PUBKEY_LENGTH {
				logger.Error.Println("Got public key of wrong size from peer " + forwarderIdentifier)
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
				DHPublicKey:     publicKey,
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
		case MSG_KEYXCHGRESP:

		default:
			logger.Warning.Println("Unknown tport / address combination did not contain KEYXCHG or KEYXCHGRESP, sending reset message")
			// TODO answer with reset message
			return
		}
	}
	msg, err := encryption.Decrypt(forwarder.SharedSecret, data)
	if err != nil {
		logger.Error.Println("Could not decrypt message from known peer " + forwarderIdentifier)
		return
	}
	seqNum := binary.BigEndian.Uint32(msg[0:4])
	// check sequence number
	if forwarder.ReceivingSeqNum > seqNum {
		logger.Warning.Println("Got message with repeating sequence number from peer " + forwarderIdentifier)
		return
	}
	if forwarder.ReceivingSeqNum < seqNum {
		logger.Info.Println("Received sequence number higher " + strconv.Itoa(int(seqNum)) + " than expected sequence number" + strconv.Itoa(int(forwarder.ReceivingSeqNum)) + ", assuming missed packets (peer " + forwarderIdentifier + ")")
	}
	forwarder.ReceivingSeqNum++
	msgId := msg[5]
	// TODO
	switch msgId {
	case MSG_EXTEND:

	case MSG_COMPLETE:

	case MSG_FORWARD:

	case MSG_DATA:

	default:
		logger.Error.Println("Got unknown message type " + strconv.Itoa(int(msgId)) + " from peer " + forwarderIdentifier)
		return
	}
}

func ipLength(addressIsIPv6 bool) int {
	if addressIsIPv6 {
		return 16
	} else {
		return 4
	}
}

// sendMessage assumes that data is an encrypted packet with the following fields:
// seqNum, msgType, data
func sendMessage(forwarder *storage.Forwarder, sendFoward bool, data []byte) error {
	var hop *storage.Hop
	if sendFoward {
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

func sendIntoTunnel(tunnelID uint32, hops *list.List, finalPeer *storage.OnionPeer, data []byte) error {
	// wrap message once for each hop (in reverse order)
	msgBuf := data
	for cur := hops.Back(); cur != nil; cur = cur.Prev() {
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
	var sendToAddress string
	tPortBuf := make([]byte, 4)
	localForwarder, exists := storage.GetForwarder(forwarders, getPeerIdentifier(LOCAL_FORWARDER, tunnelID))
	if !exists {
		logger.Error.Println("Could not find local forwarder for tunnelID " + strconv.Itoa(int(tunnelID)))
		return errors.New("InternalError")
	}
	binary.BigEndian.PutUint32(tPortBuf, localForwarder.NextHop.TPort)
	if hops.Front() != nil {
		firstHop, typeCheck := hops.Front().Value.(*storage.OnionPeer)
		if !typeCheck {
			logger.Error.Println("Got object of wrong type from peer list")
			return errors.New("InternalError")
		}
		sendToAddress = firstHop.Address
	} else {
		sendToAddress = finalPeer.Address
	}
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

	sourceForwarder := storage.Forwarder{
		NextHop:     nil,
		PreviousHop: nil,
		TType:       storage.TUNNEL_TYPE_INITIATOR,
	}
	curTunnel := storage.Tunnel{Peers: list.New(), Destination: &destinationPeer}
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
		peerIdentifier := getPeerIdentifier(peerAddressString, tunnelID)
		curPeer := storage.OnionPeer{
			Address:         peerAddressString,
			Hostkey:         peerHostkey,
			ReceivingSeqNum: 0,
			SendingSeqNum:   0,
			DHPublicKey:     publicKey,
			DHPrivateKey:    privateKey,
		}
		// encrypt DH nonce with the peer's public key
		encryptedNonce, err := encryption.EncryptAsymmetric(peerHostkey, publicKey)
		if err != nil {
			logger.Warning.Println("Could not encrypt DH nonce with hosts public key, peer " + peerAddressString)
			continue
		}
		// special case for the first hop since we can set the tport and have to send KEYXCHG instead of EXTEND
		if curTunnel.Peers.Len() == 0 {
			tPortReverse, err := generateAndClaimUnusedTPort(peerAddressString)
			if err != nil {
				logger.Warning.Println("Could not generate TPort for communication with first hop: " + peerAddressString)
				continue
			}
			msgBuf := make([]byte, 1)
			msgBuf[0] = MSG_KEYXCHG
			msgBuf = append(msgBuf, encryptedNonce...)
			sourceForwarder.NextHop = &storage.Hop{
				TPort:   tPortReverse,
				Address: peerAddressString,
			}
			err = sendMessage(&sourceForwarder, true, msgBuf)
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
			err = sendIntoTunnel(tunnelID, curTunnel.Peers, &curPeer, msgBuf)
			if err != nil {
				logger.Warning.Println("Could not send extend message to peer " + peerAddressString)
				continue
			}
		}
		// Five second timeout, so the response might not be there afterwards
		// If it is here: awesome, carry on. If it is not: Choose another hop
		storage.WaitForNotifyGroup(notifyGroups, forwarderIdentifier, RESP_TIMEOUT)
		storage.CleanupNotifyGroup(notifyGroups, forwarderIdentifier)
		// TODO
	}
	return tunnelID, nil
}

// func destroyTunnel()
