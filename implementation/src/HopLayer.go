package main

import (
	"fmt"
	"net"
	"sync"
)

const packetLength = 1280

// setup data structures for flow IDs, symmetric keys and sequence numbers
// flow looks like this: "ip:TPort" and maps to a flow ID which is used to
// identify all data connected to that flow
var flowMap = make(map[string]int)
var sequenceNumbersMap = make(map[int]int)

type symmetricKeys struct {
	data  map[net.Addr][]byte
	mutex sync.Mutex
}

var keyMap = symmetricKeys{data: make(map[net.Addr][]byte)}

type keyPair struct {
	privateKey []byte
	publicKey  []byte
}

// stores uncompleted DH Handshake
type openDHHandshakes struct {
	data  map[net.Addr]keyPair
	mutex sync.Mutex
}

var openDHs = openDHHandshakes{data: make(map[net.Addr]keyPair)}

// listening address can just be a port (":1234") or also include an address
// ("5.6.7.8:1234")
func subscribeTo(listeningAddress string, callback func(int, []byte)) bool {
	pc, err := net.ListenPacket("udp", listeningAddress)
	if err != nil {
		fmt.Printf("Cannot create listening port")
		defer pc.Close()
		return false
	}
	go listen(pc, callback)
	return true
}

func listen(pc net.PacketConn, callback func(int, []byte)) {
	for {
		buf := make([]byte, packetLength)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n != packetLength {
			continue
		}
		go handleIncomingPacket(addr, buf, callback)
	}
}

func handleIncomingPacket(addr net.Addr, data []byte, callback func(int, []byte)) {
	// [0x01|0x00]((packetLength - 1)*[0xYY]) starting flag indicates whether packet is DH param (=0x0) or regular data message (0x1)
	// check if this is a Diffie-Hellman handshake
	// if it is: respond and save the key in the keystore in case we do not have a key with this address already
	// otherwise: decrypt packet
	// translate addr and TPort into flow id
	// call callback(flowID, data)
	// consideration: maybe ratelimit at some point per IP? premature optimization is the root of all evil
	if data[0]&1 == 0 {
		peerPublicKey := data[1:33]
		// read from map synchronously
		openDHs.mutex.Lock()
		value, exists := openDHs.data[addr]
		openDHs.mutex.Unlock()
		if exists {
			// we are receiving a handshake response
			// extract public key from packet
			// first byte is reserved / DH flag
			sharedSecret, err := deriveSharedSecret(value.privateKey, peerPublicKey)
			if err != nil {
				return
			}
			openDHs.mutex.Lock()
			delete(openDHs.data, addr)
			openDHs.mutex.Unlock()
			keyMap.mutex.Lock()
			keyMap.data[addr] = sharedSecret
			keyMap.mutex.Unlock()
			return
		}
		// we have received the first handshake message and need to generate our key pair
		privateKey, publicKey, err := genKeyPair()
		if err != nil {
			return
		}
		sharedSecret, err := deriveSharedSecret(privateKey, peerPublicKey)
		if err != nil {
			return
		}
		keyMap.mutex.Lock()
		keyMap.data[addr] = sharedSecret
		keyMap.mutex.Unlock()
		// send local public key to peer
	}
	// this is not a Diffie-Hellman, we need to decrypt and handle data
}

func sendPacket(flowID int, data []byte) bool {
	return false
}
