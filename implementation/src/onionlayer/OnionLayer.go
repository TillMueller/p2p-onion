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
	connect_timeout = 2 * time.Second

	MSG_KEYXCHG     uint8 = 0x00
	MSG_KEYXCHGRESP uint8 = 0x01
)

// TODO create cleanup function that e.g. closes the UDP connection when the program exits
// TODO register receiver for incoming onion packets on config-defined port; maybe in init for this module?
// TODO think about how to identify peers - we could also have a list of peers in each tunnel and then identify them with a (tunnelID, index) tuple
// DONE we're going to need a way of notifying a currently waiting instance of BuildTunnel (or any other function that requires responses) when a response for it comes in:
// 		- One possible way would be a list and notifications like in the HopLayer
//		- Alternatively the waiting instance creates a channel where we send the message when it arrives

var openDHs = storage.InitKeyPairs()
var tunnels = storage.InitTunnels()
var peers = storage.InitPeers()
var notifyGroups = storage.InitNotifyGroups()
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
		logger.Error.Println("Crypto random reader returned error")
		return 0, errors.New("CryptoError")
	}
	result = binary.LittleEndian.Uint32(buffer)
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

func nextSequenceNumber(peerAddress net.IP, peerOnionPort uint16, TPort uint32) int {
	// TODO store and retrieve sequence number for the given peer in the given tunnel
	return 0
}

func handleIncomingPacket(addr *net.UDPAddr, data []byte) {
	if len(data) < 10 {
		logger.Warning.Println("Received packet is too short (size " + strconv.Itoa(len(data)) + ")")
		return
	}
	tunnelID := binary.BigEndian.Uint32(data[:4])
	seqNum := binary.BigEndian.Uint32(data[4:8])
	// get peer to check sequence number
	addressString := peerAddressToString(addr.IP, addr.IP.To4() == nil, uint16(addr.Port))
	peerIdentifier := getPeerIdentifier(addressString, tunnelID)
	peer, exists := storage.GetPeer(peers, peerIdentifier)
	if !exists {
		logger.Warning.Println("Got message from unknown peer with identifier " + peerIdentifier)
		return
	}
	// check sequence number
	if peer.ReceivingSeqNum > seqNum {
		logger.Warning.Println("Got message with repeating sequence number from peer with identifier " + peerIdentifier)
		return
	}
	if peer.ReceivingSeqNum < seqNum {
		logger.Info.Println("Received sequence number higher " + strconv.Itoa(int(seqNum)) + " than expected sequence number" + strconv.Itoa(int(peer.ReceivingSeqNum)) + ", assuming missed packets (peer ID " + peerIdentifier + ")")
	}
	msgId := data[9]
	switch msgId {
	case MSG_KEYXCHG:

	case MSG_KEYXCHGRESP:

	}
}

func sendMessage(peer *storage.OnionPeer, msgType uint8, data []byte) error {
	msgBuf := make([]byte, len(data)+9)
	binary.BigEndian.PutUint32(msgBuf[:4], peer.TPort)
	binary.BigEndian.PutUint32(msgBuf[4:8], peer.SendingSeqNum)
	peer.SendingSeqNum++
	msgBuf[8] = msgType
	n := copy(msgBuf[9:], data)
	if n != len(data) {
		logger.Error.Println("Could not copy complete contents to message")
		return errors.New("internalError")
	}
	err := hoplayer.SendPacket(udpconn, peer.Address, data)
	if err != nil {
		logger.Error.Println("Packet could not be sent to peer " + peer.Address)
		return errors.New("networkError")
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

	tunnelID, err = generateRandomUInt32()
	if err != nil {
		logger.Error.Println("Could not generate new random tunnelID")
		return 0, errors.New("InternalError")
	}
	destTPort, err := generateRandomUInt32()
	if err != nil {
		logger.Error.Println("Could not generate random TPort for final peer")
		return 0, errors.New("InternalError")
	}
	destinationPeer := storage.OnionPeer{
		TPort:           destTPort,
		Address:         peerAddressToString(finalHopAddress, finalHopAddressIsIPv6, finalHopPort),
		Hostkey:         finalHopHostKey,
		ReceivingSeqNum: 0,
		SendingSeqNum:   0,
	}
	curTunnel := storage.Tunnel{Hops: list.New(), Destination: &destinationPeer}
	for curTunnel.Hops.Len() < config.Intermediate_hops {
		logger.Info.Println("Building tunnel (ID " + strconv.Itoa(int(tunnelID)) + "), got " + strconv.Itoa(curTunnel.Hops.Len()) + " of " + strconv.Itoa(config.Intermediate_hops) + " hops")
		err, peerAddress, peerAddressIsIPv6, peerOnionPort, peerHostkey := api.RPSQuery()
		if err != nil {
			logger.Warning.Println("Could not solicit peer from RPS")
			continue
		}
		logger.Info.Println("Attempting to add peer at address " + peerAddress.String() + ":" + strconv.Itoa(int(peerOnionPort)) + " to tunnel " + strconv.Itoa(int(tunnelID)))
		// Generate DH nonce, encrypt it and send KEYXCHG to this peer
		privateKey, publicKey, err := dh.GenKeyPair()
		if err != nil {
			logger.Warning.Println("Could not generate keypair")
			continue
		}
		peerAddressString := peerAddressToString(peerAddress, peerAddressIsIPv6, peerOnionPort)
		peerIdentifier := getPeerIdentifier(peerAddressString, tunnelID)
		storage.SetKeyPairsValue(openDHs, peerIdentifier, storage.KeyPair{PrivateKey: privateKey, PublicKey: publicKey})
		peerTPort, err := generateRandomUInt32()
		if err != nil {
			logger.Warning.Println("Could not generate random TPort")
			continue
		}
		curPeer := storage.OnionPeer{
			TPort:           peerTPort,
			Address:         peerAddressString,
			Hostkey:         peerHostkey,
			ReceivingSeqNum: 0,
			SendingSeqNum:   0,
		}
		// encrypt DH nonce with the peer's public key
		encryptedNonce, err := encryption.EncryptAsymmetric(peerHostkey, privateKey)
		err = sendMessage(&curPeer, MSG_KEYXCHG, encryptedNonce)
		// Two seconds timeout, so the response might not be there afterwards
		storage.WaitForNotifyGroup(notifyGroups, peerIdentifier, connect_timeout)
		storage.CleanupNotifyGroup(notifyGroups, peerIdentifier)
	}
	return tunnelID, nil
}

// func destroyTunnel()
