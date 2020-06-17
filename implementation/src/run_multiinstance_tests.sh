#!/usr/bin/env bash
rm onion.log
touch onion.log
go test network_peer2_test.go HopLayer.go &
go test network_peer1_test.go HopLayer.go &
tail -f onion.log