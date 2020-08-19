#!/usr/bin/bash
for f in *_peer{1,2}_*; do
	mv $f $(echo $f | sed -e 's/skiptest/test/')
done
rm onion.log
touch onion.log
go test network_peer2_test.go HopLayer.go -run TestDiffieHellmanExchangePeer2 &
go test network_peer1_test.go HopLayer.go -run TestDiffieHellmanExchangePeer1 &
#go test -v network_peer2_test.go HopLayer.go -run TestResetPeer2 &
#go test -v network_peer1_test.go HopLayer.go -run TestResetPeer1 &
timeout 10s tail -f onion.log
for f in *_peer{1,2}_*; do
	mv $f $(echo $f | sed -e 's/test/skiptest/')
done
