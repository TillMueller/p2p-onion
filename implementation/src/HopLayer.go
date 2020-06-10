package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
)

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

var sendingUDPConn *net.UDPConn

func getUDPAddrString(addr *net.UDPAddr) (string, error) {
	addrString := addr.String()
	if addrString == "<nil>" || (!strings.Contains(addrString, ".") && !strings.Contains(addrString, ":")) {
		return "<nil>", errors.New("Could not convert UDP address to valid string")
	}
	return addrString + ":" + strconv.Itoa(addr.Port), nil
}

func padPacket(in []byte) ([packetLength]byte, error) {
	if len(in) > packetLength {
		return [packetLength]byte{}, errors.New("Cannot cut packet longer than packetLength")
	}
	out := [packetLength]byte{}
	bytesCopied := copy(out[:], in)
	paddingBytes := make([]byte, packetLength-bytesCopied)
	rand.Read(paddingBytes)
	copy(out[:], paddingBytes)
	return out, nil
}

// SubscribeTo subscribes a callback function to a specific UDP address
// the callback function should handle onion L3 packets
// listening address can just be a port (":1234") or also include an address
// ("5.6.7.8:1234")
func SubscribeTo(listeningAddress string, callback func(int, []byte)) bool {
	udpaddr, err := net.ResolveUDPAddr("udp", listeningAddress)
	if err != nil {
		fmt.Printf("Listening address invalid")
		return false
	}
	udpconn, err := net.ListenUDP("udp", udpaddr)
	sendingUDPConn = udpconn
	if err != nil {
		fmt.Printf("Cannot create listening port")
		defer udpconn.Close()
		return false
	}
	go listen(udpconn, callback)
	return true
}

func listen(udpconn *net.UDPConn, callback func(int, []byte)) {
	for {
		buf := make([]byte, packetLength)
		curLength, addr, err := udpconn.ReadFromUDP(buf)
		if err != nil || curLength != packetLength {
			continue
		}
		go handleIncomingPacket(udpconn, addr, buf, callback)
	}
}

func handleDHExchange(udpconn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	// we are receiving a handshake response
	// extract public key from packet
	// first byte is reserved / DH flag
	peerPublicKey := data[1:33]
	// read from map synchronously
	openDHs.mutex.Lock()
	addrString, err := getUDPAddrString(addr)
	if err != nil {
		return
	}
	value, exists := openDHs.data[addrString]
	openDHs.mutex.Unlock()
	if exists {
		sharedSecret, err := deriveSharedSecret(value.privateKey, peerPublicKey)
		if err != nil {
			fmt.Printf("Could not derive shared secret")
			fmt.Printf(err.Error())
			return
		}
		openDHs.mutex.Lock()
		delete(openDHs.data, addrString)
		openDHs.mutex.Unlock()
		keyMap.mutex.Lock()
		keyMap.data[addrString] = sharedSecret
		keyMap.mutex.Unlock()
		return
	}
	// we have received the first handshake message and need to generate our key pair
	privateKey, publicKey, err := genKeyPair()
	if err != nil {
		fmt.Printf("Could not generate keypair")
		fmt.Printf(err.Error())
		return
	}
	sharedSecret, err := deriveSharedSecret(privateKey, peerPublicKey)
	if err != nil {
		fmt.Printf("Could not derive shared secret")
		fmt.Printf(err.Error())
		return
	}
	keyMap.mutex.Lock()
	keyMap.data[addrString] = sharedSecret
	keyMap.mutex.Unlock()
	packet, err := padPacket(append([]byte{0}, publicKey...))
	if err != nil {
		fmt.Printf("Could not pad packet")
		fmt.Printf(err.Error())
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
	if data[0]&1 == 0 {
		handleDHExchange(udpconn, addr, data)
		return
	}
	// this is not a Diffie-Hellman, we need to decrypt and handle data
}

// SendPacket sends a packet conforming to our onion hop layer protocol
func SendPacket(addr string, data []byte) error {
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
	if exists {
		// encrypt and send packet
	}
	return nil
}
