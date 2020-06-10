package logger

import (
	"log"
	"os"
)

var (
	// Info is the logger for informational messages
	Info *log.Logger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	// Warning is the logger for Warning messages
	Warning *log.Logger = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	// Error is the logger for errors
	Error *log.Logger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
)
