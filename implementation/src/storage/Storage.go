package storage

import (
	"container/list"
	"crypto/rsa"
	"errors"
	"net"
	"onion/logger"
	"sync"
	"time"
)

type symmetricKeys struct {
	data  map[string][]byte
	mutex sync.Mutex
	cond  *sync.Cond
}

// InitSymmetricKeysMap creates a new map for storage of symmetric keys, used for storing the keypair generated for a
// Diffie-Hellman exchange. It also contains functionality to broadcast signals for routines waiting for new map values
func InitSymmetricKeys() *symmetricKeys {
	return &symmetricKeys{
		data:  make(map[string][]byte),
		mutex: sync.Mutex{},
		cond:  sync.NewCond(&sync.Mutex{}),
	}
}

func SetSymmetricKeysValue(symmetricKeysMap *symmetricKeys, key string, value []byte) {
	symmetricKeysMap.mutex.Lock()
	symmetricKeysMap.data[key] = value
	symmetricKeysMap.mutex.Unlock()
}

func BroadcastSymmetricKeys(symmetricKeysMap *symmetricKeys) {
	symmetricKeysMap.cond.L.Lock()
	symmetricKeysMap.cond.Broadcast()
	symmetricKeysMap.cond.L.Unlock()
}

func DeleteSymmetricKeysValue(ksymmetricKeysMap *symmetricKeys, key string) {
	ksymmetricKeysMap.mutex.Lock()
	_, exists := ksymmetricKeysMap.data[key]
	if exists {
		delete(ksymmetricKeysMap.data, key)
	}
	ksymmetricKeysMap.mutex.Unlock()
}

func GetSymmetricKeysValue(symmetricKeysMap *symmetricKeys, key string) (value []byte, exists bool) {
	symmetricKeysMap.mutex.Lock()
	value, exists = symmetricKeysMap.data[key]
	symmetricKeysMap.mutex.Unlock()
	return value, exists
}

func WaitForSymmetricKeysValue(symmetricKeysMap *symmetricKeys, key string) (value []byte) {
	// TODO if this works when multiple routines are waiting at the same time
	// 	In the worst case the second one cannot aquire the cond.L.Lock() and has to wait for the first to get its values
	// 	before being able to continue
	// TODO replace this with the notifyGroup implementation below
	symmetricKeysMap.cond.L.Lock()
	for {
		// this _should not_ be a deadlock
		var exists bool
		value, exists = GetSymmetricKeysValue(symmetricKeysMap, key)
		if exists {
			break
		}
		symmetricKeysMap.cond.Wait()
	}
	symmetricKeysMap.cond.L.Unlock()
	return value
}

type KeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

type keyPairs struct {
	data  map[string]KeyPair
	mutex sync.Mutex
}

func InitKeyPairs() *keyPairs {
	return &keyPairs{data: make(map[string]KeyPair)}
}

func GetKeyPairsValue(keyPairsMap *keyPairs, key string) (value KeyPair, exists bool) {
	keyPairsMap.mutex.Lock()
	value, exists = keyPairsMap.data[key]
	keyPairsMap.mutex.Unlock()
	return value, exists
}

func DeleteKeyPairsValue(keyPairsMap *keyPairs, key string) {
	keyPairsMap.mutex.Lock()
	_, exists := keyPairsMap.data[key]
	if exists {
		delete(keyPairsMap.data, key)
	}
	keyPairsMap.mutex.Unlock()
}

func SetKeyPairsValue(keyPairsMap *keyPairs, key string, value KeyPair) {
	keyPairsMap.mutex.Lock()
	keyPairsMap.data[key] = value
	keyPairsMap.mutex.Unlock()
}

type sequenceNumbers struct {
	data  map[string]int
	mutex sync.Mutex
}

func InitSequenceNumbers() *sequenceNumbers {
	return &sequenceNumbers{
		data: make(map[string]int),
	}
}

func SetSequenceNumbersValue(sequenceNumbersMap *sequenceNumbers, key string, value int) {
	sequenceNumbersMap.mutex.Lock()
	sequenceNumbersMap.data[key] = value
	sequenceNumbersMap.mutex.Unlock()
}

func DeleteSequenceNumbersValue(sequenceNumbersMap *sequenceNumbers, key string) {
	sequenceNumbersMap.mutex.Lock()
	_, exists := sequenceNumbersMap.data[key]
	if exists {
		delete(sequenceNumbersMap.data, key)
	}
	sequenceNumbersMap.mutex.Unlock()
}

func GetSequenceNumbersValue(sequenceNumbersMap *sequenceNumbers, key string) (value int, exists bool) {
	sequenceNumbersMap.mutex.Lock()
	value, exists = sequenceNumbersMap.data[key]
	sequenceNumbersMap.mutex.Unlock()
	return value, exists
}

func GetAndIncrementSequenceNumbersValue(sequenceNumbersMap *sequenceNumbers, key string) (value int, exists bool) {
	sequenceNumbersMap.mutex.Lock()
	value, exists = sequenceNumbersMap.data[key]
	if exists {
		sequenceNumbersMap.data[key]++
	}
	sequenceNumbersMap.mutex.Unlock()
	return value, exists
}

type peers struct {
	data  map[string]*Forwarder
	mutex sync.Mutex
}

func InitPeers() *peers {
	return &peers{
		data: make(map[string]*Forwarder),
	}
}

func SetPeer(peersMap *peers, key string, peer *Forwarder) {
	peersMap.mutex.Lock()
	peersMap.data[key] = peer
	peersMap.mutex.Unlock()
}

func GetPeer(peersMap *peers, key string) (value *Forwarder, exists bool) {
	peersMap.mutex.Lock()
	value, exists = peersMap.data[key]
	peersMap.mutex.Unlock()
	return value, exists
}

func DeletePeer(peersMap *peers, key string) {
	peersMap.mutex.Lock()
	_, exists := peersMap.data[key]
	if exists {
		delete(peersMap.data, key)
	}
	peersMap.mutex.Unlock()
}

type TunnelType int

const (
	TUNNEL_TYPE_INITIATOR          TunnelType = 0
	TUNNEL_TYPE_HOP                TunnelType = 1
	TUNNEL_TYPE_DESTINATION        TunnelType = 2
	TUNNEL_TYPE_HOP_OR_DESTINATION TunnelType = 3
)

type Forwarder struct {
	NextHop         *Hop
	PreviousHop     *Hop
	TType           TunnelType
	TunnelID        uint32
	ReceivingSeqNum uint32
	SendingSeqNum   uint32
	DHPublicKey     []byte
	DHPrivateKey    []byte
	SharedSecret    []byte
}

type forwarders struct {
	data  map[string]*Forwarder
	mutex sync.Mutex
}

func InitForwarders() *forwarders {
	return &forwarders{
		data: make(map[string]*Forwarder),
	}
}

func SetForwarder(forwarderMap *forwarders, key string, value *Forwarder) {
	forwarderMap.mutex.Lock()
	forwarderMap.data[key] = value
	forwarderMap.mutex.Unlock()
}

func GetForwarder(forwarderMap *forwarders, key string) (*Forwarder, bool) {
	forwarderMap.mutex.Lock()
	value, exists := forwarderMap.data[key]
	forwarderMap.mutex.Unlock()
	return value, exists
}

func DeleteForwarder(forwarderMap *forwarders, key string) {
	forwarderMap.mutex.Lock()
	_, exists := forwarderMap.data[key]
	if exists {
		delete(forwarderMap.data, key)
	}
	forwarderMap.mutex.Unlock()
}

type Hop struct {
	TPort   uint32
	Address string
}

type Tunnel struct {
	Peers               *list.List
	Destination         *OnionPeer
	Completed           bool
	Initiator           bool
	ForwarderIdentifier string
}

type OnionPeer struct {
	Address         string
	Hostkey         *rsa.PublicKey
	ReceivingSeqNum uint32
	SendingSeqNum   uint32
	DHPublicKey     []byte
	DHPrivateKey    []byte
	SharedSecret    []byte
}

type tunnels struct {
	data  map[uint32]*Tunnel
	mutex sync.Mutex
}

type peerTPorts struct {
	data  map[string]*list.List
	mutex sync.Mutex
}

func InitPeerTPorts() *peerTPorts {
	return &peerTPorts{
		data: make(map[string]*list.List),
	}
}

func AddPeerTPort(peerTPortsMap *peerTPorts, key string, value uint32) error {
	peerTPortsMap.mutex.Lock()
	lst, exists := peerTPortsMap.data[key]
	if !exists {
		lst = list.New()
		lst.PushBack(value)
		peerTPortsMap.data[key] = lst
	} else {
		valueAlreadyExists := false
		for cur := lst.Front(); cur != nil; cur = cur.Next() {
			if cur.Value == value {
				valueAlreadyExists = true
				break
			}
		}
		if !valueAlreadyExists {
			// TODO Test adding multiple values to one list using AddPeerTPort
			lst.PushBack(value)
		} else {
			return errors.New("ValueAlreadyExists")
		}
	}
	peerTPortsMap.mutex.Unlock()
	return nil
}

func DeletePeerTPort(peerTPortsMap *peerTPorts, key string, value uint32) {
	peerTPortsMap.mutex.Lock()
	lst, exists := peerTPortsMap.data[key]
	if exists {
		for cur := lst.Front(); cur != nil; cur = cur.Next() {
			if cur.Value == value {
				lst.Remove(cur)
				break
			}
		}
		if lst.Len() == 0 {
			delete(peerTPortsMap.data, key)
		}
	}
	peerTPortsMap.mutex.Unlock()
}

func GetPeerTPorts(peerTPortsMap *peerTPorts, key string) (*list.List, bool) {
	peerTPortsMap.mutex.Lock()
	lst, exists := peerTPortsMap.data[key]
	peerTPortsMap.mutex.Unlock()
	return lst, exists
}

func InitTunnels() *tunnels {
	return &tunnels{
		data: make(map[uint32]*Tunnel),
	}
}

func SetTunnel(tunnelMap *tunnels, key uint32, value *Tunnel) {
	tunnelMap.mutex.Lock()
	tunnelMap.data[key] = value
	tunnelMap.mutex.Unlock()
}

func GetTunnel(tunnelMap *tunnels, key uint32) (value *Tunnel, exists bool) {
	tunnelMap.mutex.Lock()
	value, exists = tunnelMap.data[key]
	tunnelMap.mutex.Unlock()
	return value, exists
}

func RemoveTunnel(tunnelMap *tunnels, key uint32) {
	tunnelMap.mutex.Lock()
	_, exists := tunnelMap.data[key]
	if exists {
		delete(tunnelMap.data, key)
	}
	tunnelMap.mutex.Unlock()
}

func ExistsTunnel(tunnelMap *tunnels, key uint32) bool {
	tunnelMap.mutex.Lock()
	_, exists := tunnelMap.data[key]
	tunnelMap.mutex.Unlock()
	return exists
}

type notifyGroup struct {
	lock            chan struct{}
	alreadyNotified bool
}

type NotifyGroups struct {
	data  map[string]notifyGroup
	mutex sync.Mutex
}

func InitNotifyGroups() *NotifyGroups {
	return &NotifyGroups{
		data: make(map[string]notifyGroup),
	}
}

func WaitForNotifyGroup(notifyGroupsMap *NotifyGroups, key string, timeout time.Duration) {
	notifyGroupsMap.mutex.Lock()
	value, exists := notifyGroupsMap.data[key]
	if !exists {
		value = notifyGroup{
			lock:            make(chan struct{}),
			alreadyNotified: false,
		}
		notifyGroupsMap.data[key] = value
	}
	notifyGroupsMap.mutex.Unlock()
	if !value.alreadyNotified {
		if timeout > 0 {
			select {
			case <-value.lock:
				break
			case <-time.After(timeout):
				break
			}
		} else {
			<-value.lock
		}
	}
}

func BroadcastNotifyGroup(notifyGroupsMap *NotifyGroups, key string) {
	notifyGroupsMap.mutex.Lock()
	value, exists := notifyGroupsMap.data[key]
	if exists {
		close(value.lock)
		value.alreadyNotified = true
	} else {
		value = notifyGroup{
			lock:            nil,
			alreadyNotified: true,
		}
	}
	notifyGroupsMap.data[key] = value
	notifyGroupsMap.mutex.Unlock()
}

func CleanupNotifyGroup(notifyGroupsMap *NotifyGroups, key string) {
	notifyGroupsMap.mutex.Lock()
	value, exists := notifyGroupsMap.data[key]
	if exists {
		if value.alreadyNotified {
			delete(notifyGroupsMap.data, key)
		} else {
			close(value.lock)
			delete(notifyGroupsMap.data, key)
		}
	}
	notifyGroupsMap.mutex.Unlock()
}

type ApiConnection struct {
	Connection net.Conn
}

type ApiConnections struct {
	data  *list.List
	mutex sync.Mutex
}

func InitApiConnections() *ApiConnections {
	return &ApiConnections{
		data:  list.New(),
	}
}

func AddApiConnection(apiConnectionMap *ApiConnections, value *ApiConnection) {
	apiConnectionMap.mutex.Lock()
	apiConnectionMap.data.PushBack(value)
	apiConnectionMap.mutex.Unlock()
}

func RemoveApiConnection(apiConnectionMap *ApiConnections, key uint32) {
	// TODO
}

func SendAllApiConnections(apiConnectionMap *ApiConnections, data []byte) {
	apiConnectionMap.mutex.Lock()
	for cur := apiConnectionMap.data.Front(); cur != nil; cur = cur.Next() {
		apiConn, typeCheck := cur.Value.(*ApiConnection)
		if !typeCheck {
			logger.Warning.Println("Got wrong type from API connections list")
			continue
		}
		n, err := apiConn.Connection.Write(data)
		if err != nil || n != len(data) {
			logger.Warning.Println("Could not send API message to connection " + apiConn.Connection.RemoteAddr().String())
			continue
		}
	}
	apiConnectionMap.mutex.Unlock()
}