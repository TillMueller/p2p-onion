package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"time"
)

const (
	_LengthOfSize          = 2
	_EnrollInit     uint16 = 680
	_EnrollRegister uint16 = 681
	_EnrollSuccess  uint16 = 682
	_EnrollFailure  uint16 = 683

	_Email      = "ga27set@mytum.de\r\n"
	_FirstName  = "Valentin\r\n"
	_LastName   = "Langer\r\n"
	_TeamNumber = 8
	_Project    = 39943
)

func run() int {
	fmt.Println("Trying to connect")
	conn, err := net.Dial("tcp", "p2psec.net.in.tum.de:13337")
	if err != nil {
		fmt.Println("Could not connect")
		return 1
	}
	defer conn.Close()
	fmt.Println("Connection established")
	for {
		lengthBuf := make([]byte, _LengthOfSize)
		n, err := io.ReadFull(conn, lengthBuf)
		if err != nil || n != _LengthOfSize {
			fmt.Println("Could not read from socket or wrong length read")
			return 1
		}
		msgLength := binary.BigEndian.Uint16(lengthBuf)
		msgBuf := make([]byte, msgLength-_LengthOfSize)
		_, err = io.ReadFull(conn, msgBuf)
		if err != nil {
			fmt.Println("Could not read from message buffer")
			return 1
		}
		msgCode := binary.BigEndian.Uint16(msgBuf[:2])
		switch msgCode {
		case _EnrollInit:
			fmt.Println("Message: Enroll Init")
			challenge := msgBuf[2:]
			rand.Seed(time.Now().UnixNano())
			shaBufLength := 20 + len(_Email) + len(_FirstName) + len(_LastName)
			shaMsgBuf := make([]byte, shaBufLength)
			copy(shaMsgBuf[:8], challenge)
			binary.BigEndian.PutUint16(shaMsgBuf[8:10], _TeamNumber)
			binary.BigEndian.PutUint16(shaMsgBuf[10:12], _Project)
			pointer := 20
			copy(shaMsgBuf[pointer:], _Email)
			pointer += len(_Email)
			copy(shaMsgBuf[pointer:], _FirstName)
			pointer += len(_FirstName)
			copy(shaMsgBuf[pointer:], _LastName)
			pointer += len(_LastName)
			for msgSha := [32]byte{1}; !bytes.Equal(msgSha[:3], []byte{0, 0, 0}); {
				nonce := rand.Uint64()
				binary.BigEndian.PutUint64(shaMsgBuf[12:20], nonce)
				msgSha = sha256.Sum256(shaMsgBuf)
			}
			pointer += 4
			outMsgBuf := make([]byte, pointer)
			binary.BigEndian.PutUint16(outMsgBuf[:2], uint16(pointer))
			binary.BigEndian.PutUint16(outMsgBuf[2:4], _EnrollRegister)
			copy(outMsgBuf[4:], shaMsgBuf)
			fmt.Println(sha256.Sum256(shaMsgBuf))
			fmt.Println(outMsgBuf)
			conn.Write(outMsgBuf)
		case _EnrollSuccess:
			fmt.Println("Message: Enroll Success")
			fmt.Println(msgBuf)
			fmt.Println("Team number is:", binary.BigEndian.Uint16(msgBuf[4:6]))
			return 0
		case _EnrollFailure:
			fmt.Println("Message: Enroll Failure")
			fmt.Println(msgBuf)
			return 1
		default:
			fmt.Println("Unknown message received:", msgCode)
			fmt.Println(msgBuf)
			return 1
		}
	}
}

func main() {
	os.Exit(run())
}
