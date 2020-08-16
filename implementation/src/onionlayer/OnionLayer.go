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
	"onion/logger"
	"strconv"
)

const (
	MSG_KEYXCHG     uint8 = 0x00
	MSG_KEYXCHGRESP uint8 = 0x01
)

// TODO register receiver for incoming onion packets on config-defined port; maybe in init for this module?
// TODO think about how to identify peers - we could also have a list of peers in each tunnel and then identify them with a (tunnelID, index) tuple
// TODO we're going to need a way of notifying a currently waiting instance of BuildTunnel (or any other function that requires responses) when a response for it comes in:
// 		- One possible way would be a list and notifications like in the HopLayer
//		- Alternatively the waiting instance creates a channel where we send the message when it arrives

// generate a random 32 bit unsigned integer from the crypto/rand pseudo random number generator
func generateRandomUInt32() (err error, result uint32) {
	buffer := make([]byte, 4)
	n, err := rand.Read(buffer)
	if err != nil || n != 4 {
		logger.Error.Println("Crypto random reader returned error")
		return errors.New("CryptoError"), 0
	}
	result = binary.LittleEndian.Uint32(buffer)
	return nil, result
}

func nextSequenceNumber(peerAddress net.IP, peerOnionPort uint16, TPort uint32) {
	// TODO store and retrieve sequence number for the given peer in the given tunnel
}

func sendMessage(peerAddress net.IP, peerOnionPort uint16, TPort uint32, msgType uint8, data []byte) error {
	// TODO Retrieve required values (e.g. sequence number) for this tunnel / peer, craft the message and send it
	return nil
}

// BuildTunnel (blocking) creates an onion tunnel with the given final peer. If the build is successful the function
// returns the ID of the tunnel that was built as a uint32. If it was not successful, the ID is 0 and error is set.
// BuildTunnel exits on error, so if the creation was unsuccessful it may be tried again by calling BuildTunnel again.
// Onion messages have this format:
// 0		8		16		24		32
// [---------------TPort-------------]
// [-----------SequenceNumber--------]
// [msgType||-------------data-------]
// [------------contd. data----------]
// message Types:
//		- 0x00 KEYXCHG		Indicates that the message data contains a Diffie-Hellman nonce encrypted with the receiving hosts public key. Response of type KEYXCHGRESP expected.
//		- 0x01 KEYXCHGRESP	Indicates that the message data contains a Diffie-Hellman nonce encrypted with the receiving hosts public key. May only be sent in response to KEYXCHG.
func BuildTunnel(finalHopAddress net.IP, finalHopAddressIsIPv6 bool, finalHopPort int, finalHopHostKey *rsa.PublicKey) (err error, tunnelID uint32) {
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

	err, tunnelID = generateRandomUInt32()
	if err != nil {
		logger.Error.Println("Could not generate new random tunnelID")
		return errors.New("InternalError"), 0
	}
	tunnelHops := list.New()
	for tunnelHops.Len() < config.Intermediate_hops {
		err, peerAddress, peerAddressIsIPv6, peerOnionPort, peerHostkey := api.RPSQuery()
		if err != nil {
			logger.Warning.Println("Could not solicit peer from RPS")
			continue
		}
		logger.Info.Println("Attempting to add peer at address " + peerAddress.String() + ":" + strconv.Itoa(int(peerOnionPort)) + " to tunnel " + strconv.Itoa(int(tunnelID)))

	}
	return nil, tunnelID
}

// func destroyTunnel()
