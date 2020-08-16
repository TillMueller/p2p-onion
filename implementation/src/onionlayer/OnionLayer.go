package onionlayer

import (
	"crypto/rsa"
	"net"
)

func buildTunnel(finalHopAddress net.IP, finalHopAddressIsIPv6 bool, finalHopPort int, finalHopHostKey *rsa.PublicKey) {
	// DONE
	// - get the public key of the final hop -> We get this as part of the "ONION TUNNEL BUILD" message
	// TODO
	// - get two peers to use as hops including their respective public keys and onion addresses / ports -> RPS gives us all this information
	// - generate diffie hellman nonce and encrypt it with the first hop's public key
	// - generate a tunnel ID to use towards the first hop and a tunnel ID to use towards the API
	// - send to first hop: tunnel ID, IP version / IP of next hop, encrypted DH nonce
	// - wait for response; if response does not happen within a certain timeframe (e.g. one second) we can either resend or choose a new hop
	// - derive ephemeral symmetric key for this hop
	// - do the same for the second and third hop
	// - enable keepalive messages (or is this already required before?)
	// - make API send message that tunnel creation was successful (what can we do in case of failure?)
}

// func destroyTunnel()
