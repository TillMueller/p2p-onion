package hoplayer

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"onion/dh"
	"onion/encryption"
	"onion/logger"
	"onion/storage"
	"strconv"
	"strings"
	"sync"
	"time"
)

const PEMPubKeyLength = 178
const packetLength = 1232 // == 1280 (v6 minimum MTU) - 40 (v6 header) - 8 (udp header)
const DH_MSGCODE = 0x0
const DATA_MSGCODE = 0x1 // set if contained payload is data. If not set, payload is part of a Diffie-Hellman Handshake
const RST_MSGCODE = 0x2
// TODO move timeout to config?
const timeout = 2 * time.Second

var receivingMutex sync.Mutex

// contains the next used sequence number
var sendingSeqNums = storage.InitSequenceNumbers()

// contains the next expected sequence number
var receivingSeqNums = storage.InitSequenceNumbers()

// stores derived symmetric keys
var keyMap = storage.InitSymmetricKeys()

// stores uncompleted DH Handshake
var openDHs = storage.InitKeyPairs()

// When we have a new shared secret, initialize all data structures we need for peer-to-peer communication
func newKey(sharedSecret []byte, addrString string) {
	storage.SetSymmetricKeysValue(keyMap, addrString, sharedSecret)
	// initially set sending sequence number
	storage.SetSequenceNumbersValue(sendingSeqNums, addrString, 0)
	// initially set receiving sequence number
	storage.SetSequenceNumbersValue(receivingSeqNums, addrString, 0)
	// notify waiting goroutines of new value
	storage.BroadcastSymmetricKeys(keyMap, addrString)
}

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
	_, err := rand.Read(paddingBytes)
	if err != nil {
		logger.Error.Println("Could not read bytes for packet padding")
		return [packetLength]byte{}, errors.New("CryptoError")
	}
	copy(out[bytesCopied:], paddingBytes)
	return out, nil
}

func clearPeerInformation(addrStr string) {
	storage.DeleteSymmetricKeysValue(keyMap, addrStr)
	storage.DeleteSequenceNumbersValue(sendingSeqNums, addrStr)
	storage.DeleteSequenceNumbersValue(receivingSeqNums, addrStr)
	logger.Info.Println("Removed all local information for peer: " + addrStr)
}

// SetPacketReceiver subscribes a callback function to a specific UDP address
// the callback function should handle onion L3 packets
// listening address can just be a port (":1234") or also include an address
// ("5.6.7.8:1234")
func SetPacketReceiver(listeningAddress string, callback func(*net.UDPAddr, []byte)) (*net.UDPConn, error) {
	logger.Info.Println("Opening new listening connection: " + listeningAddress)
	udpaddr, err := net.ResolveUDPAddr("udp", listeningAddress)
	if err != nil {
		logger.Error.Println("Listening address invalid")
		return nil, errors.New("invalidArgumentError")
	}
	udpconn, err := net.ListenUDP("udp", udpaddr)
	if err != nil {
		logger.Error.Println("Cannot create listening port")
		return nil, errors.New("networkError")
	}
	go listen(udpconn, callback)
	return udpconn, nil
}

func listen(udpconn *net.UDPConn, callback func(*net.UDPAddr, []byte)) {
	defer udpconn.Close()
	defer logger.Info.Println("Closing onion UDP connection")
	for {
		buf := make([]byte, packetLength)
		curLength, addr, err := udpconn.ReadFromUDP(buf)
		if err != nil || curLength != packetLength {
			addrString, err := getUDPAddrString(addr)
			if err != nil {
				logger.Warning.Println("Could not generate address string from UDP address")
				continue
			}
			logger.Warning.Println("Got packet with wrong size from peer: " + addrString)
			go clearPeerInformation(addrString)
			continue
		}
		go handleIncomingPacket(udpconn, addr, buf, callback)
	}
}

func handleDHExchange(udpconn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	// we are receiving a handshake response
	// extract public key from packet
	// first byte is reserved / DH flag
	peerPublicKey := data[1 : PEMPubKeyLength+1]
	// read from map synchronously
	addrString, err := getUDPAddrString(addr)
	if err != nil {
		logger.Warning.Println("Could not generate address string from UDP address")
		return
	}
	logger.Info.Println("Received public key from " + addrString + " (length " + strconv.Itoa(len(peerPublicKey)) + ")")
	value, exists := storage.GetKeyPairsValue(openDHs, addrString)
	if exists {
		sharedSecret, err := dh.DeriveSharedSecret(value.PrivateKey, peerPublicKey)
		if err != nil {
			logger.Error.Println("Could not derive shared secret")
			return
		}
		storage.DeleteKeyPairsValue(openDHs, addrString)
		newKey(sharedSecret, addrString)
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
	newKey(sharedSecret, addrString)
	packet, err := padPacket(append([]byte{DH_MSGCODE}, publicKey...))
	if err != nil {
		logger.Error.Println("Could not pad packet")
		return
	}
	_, err = udpconn.WriteToUDP(packet[:], addr)
	if err != nil {
		logger.Error.Println("Could not send DH response to peer " + addrString)
		return
	}
}

func handleIncomingPacket(udpconn *net.UDPConn, addr *net.UDPAddr, data []byte, callback func(*net.UDPAddr, []byte)) {
	// [0x01|0x00]((packetLength - 1)*[0xYY]) starting flag indicates whether packet is DH param (=0x0) or regular data message (0x1)
	// check if this is a Diffie-Hellman handshake
	// if it is: respond and save the key in the keystore in case we do not have a key with this address already
	// otherwise: decrypt packet
	// translate addr and TPort into flow id
	// call callback(flowID, data)
	// consideration: maybe ratelimit at some point per IP?
	addrStr, _ := getUDPAddrString(addr)

	//upon receiving a RST_MSGCODE, delete all local state of hoplayer connection.
	if data[0] == RST_MSGCODE {
		logger.Info.Println("Got reset message from peer: " + addrStr)
		clearPeerInformation(addrStr)
		return
	}
	if data[0] == DH_MSGCODE {
		logger.Info.Println("Got DH keyexchange from " + addrStr)
		handleDHExchange(udpconn, addr, data)
		return
	}
	receivingMutex.Lock()
	defer receivingMutex.Unlock()
	// this is not a Diffie-Hellman, we need to decrypt and handle data
	// there should already be a key here
	key, exists := storage.GetSymmetricKeysValue(keyMap, addrStr)
	if !exists {
		logger.Warning.Println("Could not find symmetric key for peer: " + addrStr)
		// send reset message to peer
		packet, err := padPacket([]byte{RST_MSGCODE})
		if err != nil {
			logger.Error.Println("Could not pad reset packet for peer: " + addrStr)
			return
		}
		_, err = udpconn.WriteToUDP(packet[:], addr)
		if err != nil {
			logger.Error.Println("Could not send reset message to peer: " + addrStr)
			return
		}
		logger.Warning.Println("Sent hoplayer reset message to peer: " + addrStr)
		return
	}
	plaintext, err := encryption.Decrypt(key, data[1:])
	if err != nil {
		logger.Error.Println("Could not decrypt data from peer: " + addrStr)
		return
	}
	size := binary.BigEndian.Uint16(plaintext[:2])
	receivedSeqNum := int(binary.BigEndian.Uint32(plaintext[2:6]))
	curSeqNum, exists := storage.GetSequenceNumbersValue(receivingSeqNums, addrStr)
	if !exists {
		logger.Error.Println("Could not find sequence number for peer: " + addrStr)
		return
	}
	if receivedSeqNum < curSeqNum {
		logger.Warning.Println("Received packet with repeated sequence number (got " + strconv.Itoa(receivedSeqNum) + ", expected " + strconv.Itoa(curSeqNum) +") from peer: " + addrStr)
		return
	}
	if receivedSeqNum > curSeqNum {
		logger.Warning.Println("Some sequence numbers were missed, possibly due to lost packets. Expected sequence number: " + strconv.Itoa(curSeqNum) + "; received sequence number: " + strconv.Itoa(receivedSeqNum) + " from peer " + addrStr)
	}
	storage.SetSequenceNumbersValue(receivingSeqNums, addrStr, receivedSeqNum+1)
	logger.Info.Println("Got message (length " + strconv.Itoa(int(size)) + ")")
	callback(addr, plaintext[6:size+6])
	return
}

// SendPacket sends a packet conforming to our onion hop layer protocol
// Blocks until data is sent or an error is generated
func SendPacket(sendingUDPConn *net.UDPConn, addr string, data []byte) error {
	if len(data) > (packetLength - 7) {
		logger.Error.Println("Packet too long")
		return errors.New("invalidArgumentError")
	}
	receiverAddress, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		logger.Error.Println("Could not resolve address " + addr)
		return errors.New("networkError")
	}
	addrString, err := getUDPAddrString(receiverAddress)
	if err != nil {
		logger.Error.Println("Could not create address string from receiver address " + receiverAddress.String())
		return errors.New("networkError")
	}
	key, exists := storage.GetSymmetricKeysValue(keyMap, addrString)
	if !exists {
		// We haven't established a shared secret, so we must perform DH
		logger.Info.Println("Did not find existing key for " + addr + ". Attempting to create one via DH.")
		privateKey, publicKey, err := dh.GenKeyPair()
		if err != nil {
			logger.Error.Println("Could not generate keypair")
			return errors.New("internalError")
		}
		storage.SetKeyPairsValue(openDHs, addrString, storage.KeyPair{PrivateKey: privateKey, PublicKey: publicKey})

		packet, err := padPacket(append([]byte{0}, publicKey...))
		if err != nil {
			logger.Error.Println("Could not pad packet")
			return errors.New("internalError")
		}
		logger.Info.Println("Sending public key to " + addrString + " (length " + strconv.Itoa(len(publicKey)) + ")")
		_, err = sendingUDPConn.WriteToUDP(packet[:], receiverAddress)
		if err != nil {
			logger.Error.Println("Could not send public key to " + addrString)
			return errors.New("networkError")
		}
		// wait until DH is done
		logger.Info.Println("Waiting for DH with peer: " + addrString)
		key, exists = storage.WaitForSymmetricKeysValue(keyMap, addrString, timeout)
		if !exists {
			logger.Warning.Println("HopLayer keyexchange timed out, aborting")
			clearPeerInformation(addrString)
			return errors.New("NetworkError")
		}
	}
	// encrypt
	sizeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sizeBytes, uint16(len(data)))
	seqBytes := make([]byte, 4)
	seqNum, exists := storage.GetAndIncrementSequenceNumbersValue(sendingSeqNums, addrString)
	if !exists {
		logger.Error.Println("Didn't find sequence number for given address: " + addrString)
		return errors.New("internalError")
	}
	logger.Info.Println("Sending out packet to " + addrString + " with sequence number " + strconv.Itoa(seqNum))
	binary.BigEndian.PutUint32(seqBytes, uint32(seqNum))
	headerBytes := append(sizeBytes, seqBytes...)
	data = append(headerBytes, data...)
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
	// send
	_, err = sendingUDPConn.WriteToUDP(paddedPacket[:], receiverAddress)
	if err != nil {
		logger.Error.Println("Could not send packet to peer " + addrString)
		return errors.New("networkError")
	}
	return nil
}
