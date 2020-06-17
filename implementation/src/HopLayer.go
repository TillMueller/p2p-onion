package main

import (
	"crypto/rand"
	"errors"
	"net"
	"onion/dh"
	"onion/encryption"
	"onion/logger"
	"strconv"
	"strings"
	"sync"
	"encoding/base64"
	"encoding/binary"
)

const PEMPubKeyLength = 178
const packetLength = 1280

// setup data structures for flow IDs, symmetric keys and sequence numbers
// flow looks like this: "ip:TPort" and maps to a flow ID which is used to
// identify all data connected to that flow
var flowMap = make(map[string]int)
var sequenceNumbersMap = make(map[int]int)

type symmetricKeys struct {
	data  map[string][]byte
	mutex sync.Mutex
}

var keyMap = symmetricKeys{data: make(map[string][]byte)}
var waitForDHChannel = make(chan bool, 1)

type keyPair struct {
	privateKey []byte
	publicKey  []byte
}

// stores uncompleted DH Handshake
type openDHHandshakes struct {
	data  map[string]keyPair
	mutex sync.Mutex
}

var openDHs = openDHHandshakes{data: make(map[string]keyPair)}

func getUDPAddrString(addr *net.UDPAddr) (string, error) {
	addrString := addr.String()
	if addrString == "<nil>" || (!strings.Contains(addrString, ".") && !strings.Contains(addrString, ":")) {
		logger.Error.Println("Could not convert UDP address to valid string")
		return "<nil>", errors.New("invalidArgumentError")
	}
	return addrString, nil
}

func padPacket(in []byte) ([packetLength]byte, error) {
	if len(in) > packetLength {
		logger.Error.Println("Cannot pad packet longer than packetLength (" + strconv.Itoa(packetLength) + ")")
		return [packetLength]byte{}, errors.New("invalidArgumentError")
	}
	out := [packetLength]byte{}
	bytesCopied := copy(out[:], in)
	paddingBytes := make([]byte, packetLength-bytesCopied)
	rand.Read(paddingBytes)
	copy(out[bytesCopied:], paddingBytes)
	return out, nil
}

// SubscribeTo subscribes a callback function to a specific UDP address
// the callback function should handle onion L3 packets
// listening address can just be a port (":1234") or also include an address
// ("5.6.7.8:1234")
func SubscribeTo(listeningAddress string, callback func(int, []byte)) (*net.UDPConn, error) {
	logger.Info.Println("Opening new listening connection: " + listeningAddress)
	udpaddr, err := net.ResolveUDPAddr("udp", listeningAddress)
	if err != nil {
		logger.Error.Println("Listening address invalid")
		return nil, errors.New("invalidArgumentError")
	}
	udpconn, err := net.ListenUDP("udp", udpaddr)
	if err != nil {
		defer udpconn.Close()
		logger.Error.Println("Cannot create listening port")
		return nil, errors.New("networkError")
	}
	go listen(udpconn, callback)
	return udpconn, nil
}

func listen(udpconn *net.UDPConn, callback func(int, []byte)) {
	for {
		buf := make([]byte, packetLength)
		curLength, addr, err := udpconn.ReadFromUDP(buf)
		if err != nil || curLength != packetLength {
			logger.Warning.Println("Skipping incoming packet")
			continue
		}
		go handleIncomingPacket(udpconn, addr, buf, callback)
	}
}

func handleDHExchange(udpconn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	// we are receiving a handshake response
	// extract public key from packet
	// first byte is reserved / DH flag
	peerPublicKey := data[1:PEMPubKeyLength + 1]
	// read from map synchronously
	openDHs.mutex.Lock()
	addrString, err := getUDPAddrString(addr)
	logger.Info.Println("Received public key from " + addrString + " (length " + strconv.Itoa(len(peerPublicKey)) + "): " + base64.StdEncoding.EncodeToString(peerPublicKey))
	if err != nil {
		return
	}
	value, exists := openDHs.data[addrString]
	openDHs.mutex.Unlock()
	if exists {
		sharedSecret, err := dh.DeriveSharedSecret(value.privateKey, peerPublicKey)
		if err != nil {
			logger.Error.Println("Could not derive shared secret")
			return
		}
		openDHs.mutex.Lock()
		delete(openDHs.data, addrString)
		openDHs.mutex.Unlock()
		keyMap.mutex.Lock()
		keyMap.data[addrString] = sharedSecret
		keyMap.mutex.Unlock()
		waitForDHChannel <- true
		return
	}
	// we have received the first handshake message and need to generate our keypair
	privateKey, publicKey, err := dh.GenKeyPair()
	if err != nil {
		logger.Error.Println("Could not generate keypair")
		return
	}
	sharedSecret, err := dh.DeriveSharedSecret(privateKey, peerPublicKey)
	if err != nil {
		logger.Error.Println("Could not derive shared secret")
		return
	}
	keyMap.mutex.Lock()
	keyMap.data[addrString] = sharedSecret
	keyMap.mutex.Unlock()
	waitForDHChannel <- true
	packet, err := padPacket(append([]byte{0}, publicKey...))
	if err != nil {
		logger.Error.Println("Could not pad packet")
		logger.Error.Println(err.Error())
		return
	}
	udpconn.WriteToUDP(packet[:], addr)
}

func handleIncomingPacket(udpconn *net.UDPConn, addr *net.UDPAddr, data []byte, callback func(int, []byte)) {
	// [0x01|0x00]((packetLength - 1)*[0xYY]) starting flag indicates whether packet is DH param (=0x0) or regular data message (0x1)
	// check if this is a Diffie-Hellman handshake
	// if it is: respond and save the key in the keystore in case we do not have a key with this address already
	// otherwise: decrypt packet
	// translate addr and TPort into flow id
	// call callback(flowID, data)
	// consideration: maybe ratelimit at some point per IP? premature optimization is the root of all evil
	addrStr, _ := getUDPAddrString(addr)
	if data[0]&1 == 0 {
		logger.Info.Println("Got DH keyexchange from " + addrStr)
		handleDHExchange(udpconn, addr, data)
		return
	}
	// this is not a Diffie-Hellman, we need to decrypt and handle data
	// there should already be a key here
	keyMap.mutex.Lock()
	key, exists := keyMap.data[addrStr]
	keyMap.mutex.Unlock()
	if !exists {
		logger.Warning.Println("Could not find symmetric key for peer: " + addrStr)
		return
	}
	plaintext, err := encryption.Decrypt(key, data[1:])
	if err != nil {
		logger.Error.Println("Could not decrypt data from peer: " + addrStr)
		return
	}
	size := binary.BigEndian.Uint16(plaintext[:2])
	logger.Info.Println("Got message (length " + strconv.Itoa(int(size)) + "): " + string(plaintext[2:size + 2]))
	return
}

// SendPacket sends a packet conforming to our onion hop layer protocol
// Blocks until data is sent or an error is generated
func SendPacket(sendingUDPConn *net.UDPConn, addr string, data []byte) error {
	if len(data) > packetLength {
		logger.Error.Println("Packet too long")
		return errors.New("invalidArgumentError")
	}
	receiverAddress, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	addrString, err := getUDPAddrString(receiverAddress)
	if err != nil {
		return err
	}
	keyMap.mutex.Lock()
	key, exists := keyMap.data[addrString]
	keyMap.mutex.Unlock()
	if !exists {
		// We haven't established a shared secret, so we must perform DH
		logger.Info.Println("Did not find existing key for " + addr + ". Attempting to create one via DH.")
		privateKey, publicKey, err := dh.GenKeyPair()
		if err != nil {
			logger.Error.Println("Could not generate keypair")
			return errors.New("internalError")
		}
		keyPair := keyPair{privateKey, publicKey}
		openDHs.mutex.Lock()
		openDHs.data[addrString] = keyPair
		openDHs.mutex.Unlock()
		packet, err := padPacket(append([]byte{0}, publicKey...))
		if err != nil {
			logger.Error.Println("Could not pad packet")
			return errors.New("internalError")
		}
		logger.Info.Println("Sending public key to " + addrString + " (length " + strconv.Itoa(len(publicKey)) + "): " + base64.StdEncoding.EncodeToString(publicKey))
		sendingUDPConn.WriteToUDP(packet[:], receiverAddress)
		// wait until DH is done
		for {
			keyMap.mutex.Lock()
			key, exists = keyMap.data[addrString]
			keyMap.mutex.Unlock()
			if exists {
				break
			}
			<-waitForDHChannel
		}
	}
	// TODO sequence numbers
	// encrypt
	sizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sizeBytes, uint16(len(data)))
	data = append(sizeBytes, data...)
	ciphertext, err := encryption.Encrypt(key, data)
	if err != nil {
		logger.Error.Println("Could not encrypt packet")
		return errors.New("internalError")
	}
	// add flags
	unpaddedPacket := append([]byte{0x1}, ciphertext...)
	// pad
	paddedPacket, err := padPacket(unpaddedPacket)
	if err != nil {
		logger.Error.Println("Could not pad packet")
		return errors.New("internalError")
	}
	// sanity check
	if len(paddedPacket) != packetLength {
		logger.Error.Println("Packet has wrong size")
		return errors.New("invalidArgumentError")
	}
	// send
	sendingUDPConn.WriteToUDP(paddedPacket[:], receiverAddress)
	return nil
}
