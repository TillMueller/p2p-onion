#!/usr/bin/bash
for f in *_peer{1,2,3}_*; do
	mv $f $(echo $f | sed -e 's/skiptest/test/')
done
rm onion.log
touch onion.log
go test -v OnionLayer_peer1_test.go OnionLayer.go -run TestBuildTunnelSingleHopPeer1 &
go test -v OnionLayer_peer2_test.go OnionLayer.go -run TestBuildTunnelSingleHopPeer2 &
go test -v OnionLayer_peer3_test.go OnionLayer.go -run TestBuildTunnelSingleHopPeer3 &
timeout 10s tail -f onion.log
for f in *_peer{1,2,3}_*; do
	mv $f $(echo $f | sed -e 's/test/skiptest/')
done
