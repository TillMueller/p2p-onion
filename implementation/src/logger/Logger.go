package logger

import (
	"crypto/rand"
	"log"
	"math/big"
	"os"
	"strconv"
)

var (
	// Generate Random ID for differentiating different hosts in log file
	logFile = initializeLogFile("onion.log")
	// Info is the logger for informational messages
	Info *log.Logger
	// Warning is the logger for Warning messages
	Warning *log.Logger
	// Error is the logger for errors
	Error *log.Logger
)

func init() {
	InitializeLogger(strconv.Itoa(getRandomNumber(1000)))
}

func initializeLogFile(name string) *os.File {
	file, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		// do something
		return nil
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

func InitializeLogger(name string) {
	Info = log.New(logFile, "[" + name + "] INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	Warning = log.New(logFile, "[" + name +  "] WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	Error = log.New(logFile, "[" + name +  "] ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}