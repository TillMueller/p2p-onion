package logger

import (
	"crypto/rand"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"onion/config"
	"os"
	"strconv"
)

var (
	// Generate Random ID for differentiating different hosts in log file
	logFile *os.File
	// Info is the logger for informational messages
	Info *log.Logger
	// Warning is the logger for Warning messages
	Warning *log.Logger
	// Error is the logger for errors
	Error *log.Logger
)

func Initialize() {
	logFile = initializeLogFile(config.LogfileLocation)
	initializeLogger(strconv.Itoa(getRandomNumber(1000)))
}

func initializeLogFile(name string) *os.File {
	file, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	return file
}

func getRandomNumber(max int) int {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}
	return int(nBig.Int64())
}

func initializeLogger(name string) {
	warningMultiWriter := io.MultiWriter(os.Stdout, logFile)
	errorMultiWriter := io.MultiWriter(os.Stderr, logFile)
	var infoLogDest io.Writer
	if config.LogInfo {
		infoLogDest = logFile
	} else {
		infoLogDest = ioutil.Discard
	}
	Info = log.New(infoLogDest, "["+name+"] INFO: ", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
	Warning = log.New(warningMultiWriter, "["+name+"] WARNING: ", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
	Error = log.New(errorMultiWriter, "["+name+"] ERROR: ", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile)
}
