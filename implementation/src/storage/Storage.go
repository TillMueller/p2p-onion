package storage

import (
	"container/list"
	"crypto/rsa"
	"sync"
	"time"
)

type SymmetricKeys struct {
	data  map[string][]byte
	mutex sync.Mutex
	cond  *sync.Cond
}

// InitSymmetricKeysMap creates a new map for storage of symmetric keys, used for storing the keypair generated for a
// Diffie-Hellman exchange. It also contains functionality to broadcast signals for routines waiting for new map values
func InitSymmetricKeys() *SymmetricKeys {
	return &SymmetricKeys{
		data:  make(map[string][]byte),
		mutex: sync.Mutex{},
		cond:  sync.NewCond(&sync.Mutex{}),
	}
}

func SetSymmetricKeysValue(symmetricKeysMap *SymmetricKeys, key string, value []byte) {
	symmetricKeysMap.mutex.Lock()
	symmetricKeysMap.data[key] = value
	symmetricKeysMap.mutex.Unlock()
}

func BroadcastSymmetricKeys(symmetricKeysMap *SymmetricKeys) {
	symmetricKeysMap.cond.L.Lock()
	symmetricKeysMap.cond.Broadcast()
	symmetricKeysMap.cond.L.Unlock()
}

func DeleteSymmetricKeysValue(ksymmetricKeysMap *SymmetricKeys, key string) {
	ksymmetricKeysMap.mutex.Lock()
	_, exists := ksymmetricKeysMap.data[key]
	if exists {
		delete(ksymmetricKeysMap.data, key)
	}
	ksymmetricKeysMap.mutex.Unlock()
}

func GetSymmetricKeysValue(symmetricKeysMap *SymmetricKeys, key string) (value []byte, exists bool) {
	symmetricKeysMap.mutex.Lock()
	value, exists = symmetricKeysMap.data[key]
	symmetricKeysMap.mutex.Unlock()
	return value, exists
}

func WaitForSymmetricKeysValue(symmetricKeysMap *SymmetricKeys, key string) (value []byte) {
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

type KeyPairs struct {
	data  map[string]KeyPair
	mutex sync.Mutex
}

func InitKeyPairs() *KeyPairs {
	return &KeyPairs{data: make(map[string]KeyPair)}
}

func GetKeyPairsValue(keyPairsMap *KeyPairs, key string) (value KeyPair, exists bool) {
	keyPairsMap.mutex.Lock()
	value, exists = keyPairsMap.data[key]
	keyPairsMap.mutex.Unlock()
	return value, exists
}

func DeleteKeyPairsValue(keyPairsMap *KeyPairs, key string) {
	keyPairsMap.mutex.Lock()
	_, exists := keyPairsMap.data[key]
	if exists {
		delete(keyPairsMap.data, key)
	}
	keyPairsMap.mutex.Unlock()
}

func SetKeyPairsValue(keyPairsMap *KeyPairs, key string, value KeyPair) {
	keyPairsMap.mutex.Lock()
	keyPairsMap.data[key] = value
	keyPairsMap.mutex.Unlock()
}

type SequenceNumbers struct {
	data  map[string]int
	mutex sync.Mutex
}

func InitSequenceNumbers() *SequenceNumbers {
	return &SequenceNumbers{
		data: make(map[string]int),
	}
}

func SetSequenceNumbersValue(sequenceNumbersMap *SequenceNumbers, key string, value int) {
	sequenceNumbersMap.mutex.Lock()
	sequenceNumbersMap.data[key] = value
	sequenceNumbersMap.mutex.Unlock()
}

func DeleteSequenceNumbersValue(sequenceNumbersMap *SequenceNumbers, key string) {
	sequenceNumbersMap.mutex.Lock()
	_, exists := sequenceNumbersMap.data[key]
	if exists {
		delete(sequenceNumbersMap.data, key)
	}
	sequenceNumbersMap.mutex.Unlock()
}

func GetSequenceNumbersValue(sequenceNumbersMap *SequenceNumbers, key string) (value int, exists bool) {
	sequenceNumbersMap.mutex.Lock()
	value, exists = sequenceNumbersMap.data[key]
	sequenceNumbersMap.mutex.Unlock()
	return value, exists
}

func GetAndIncrementSequenceNumbersValue(sequenceNumbersMap *SequenceNumbers, key string) (value int, exists bool) {
	sequenceNumbersMap.mutex.Lock()
	value, exists = sequenceNumbersMap.data[key]
	if exists {
		sequenceNumbersMap.data[key]++
	}
	sequenceNumbersMap.mutex.Unlock()
	return value, exists
}

type Peers struct {
	data  map[string]*OnionPeer
	mutex sync.Mutex
}

func InitPeers() *Peers {
	return &Peers{
		data: make(map[string]*OnionPeer),
	}
}

func SetPeer(peersMap *Peers, key string, peer *OnionPeer) {
	peersMap.mutex.Lock()
	peersMap.data[key] = peer
	peersMap.mutex.Unlock()
}

func GetPeer(peersMap *Peers, key string) (value *OnionPeer, exists bool) {
	peersMap.mutex.Lock()
	value, exists = peersMap.data[key]
	peersMap.mutex.Unlock()
	return value, exists
}

func DeletePeer(peersMap *Peers, key string) {
	peersMap.mutex.Lock()
	_, exists := peersMap.data[key]
	if exists {
		delete(peersMap.data, key)
	}
	peersMap.mutex.Unlock()
}

type Tunnel struct {
	Hops        *list.List
	Destination *OnionPeer
}

type OnionPeer struct {
	TPort           uint32
	Address         string
	Hostkey         *rsa.PublicKey
	ReceivingSeqNum uint32
	SendingSeqNum   uint32
}

type Tunnels struct {
	data  map[uint32]*Tunnel
	mutex sync.Mutex
}

func InitTunnels() *Tunnels {
	return &Tunnels{
		data: make(map[uint32]*Tunnel),
	}
}

func SetTunnel(tunnelMap *Tunnels, key uint32, value *Tunnel) {
	tunnelMap.mutex.Lock()
	tunnelMap.data[key] = value
	tunnelMap.mutex.Unlock()
}

func GetTunnel(tunnelMap *Tunnels, key uint32) (value *Tunnel, exists bool) {
	tunnelMap.mutex.Lock()
	value, exists = tunnelMap.data[key]
	tunnelMap.mutex.Unlock()
	return value, exists
}

func RemoveTunnel(tunnelMap *Tunnels, key uint32) {
	tunnelMap.mutex.Lock()
	_, exists := tunnelMap.data[key]
	if exists {
		delete(tunnelMap.data, key)
	}
	tunnelMap.mutex.Unlock()
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
			case <-time.After(timeout * time.Second):
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
