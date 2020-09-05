package main

import (
	"fmt"
	"onion/api"
	"onion/config"
	"onion/logger"
	"onion/onionlayer"
	"os"
	"os/signal"
	"syscall"
)

func writeError(msg string) {
	_, err := fmt.Fprintln(os.Stderr, msg)
	if err != nil {
		panic(err)
	}
}

func main() {
	// default config location is config.ini in the programs folder
	configLocation := "config.ini"
	// get config location via command line parameter#
	for i:= 1; i < len(os.Args); i++ {
		cur := os.Args[i]
		switch cur {
		case "-c":
			configLocation = os.Args[i + 1]
			i++
		default:
			writeError("Unknown command line option: " + cur)
		}
	}
	err := config.LoadConfig(configLocation)
	if err != nil {
		writeError("Could not load configuration file " + configLocation + ". You can specify a configuration file using the -c parameter. Exiting.")
		return
	}
	// initialize logger
	logger.Initialize()
	// initialize onion layer
	err = onionlayer.Initialize()
	if err != nil {
		logger.Error.Println("Could not initialize onion module. Exiting.")
		return
	}
	// initialize API
	err = api.Initialize()
	if err != nil {
		logger.Error.Println("Could not initialize API. Exiting.")
		return
	}
	logger.Info.Println("Initialization successful")
	fmt.Println("Onion module has been started with configuration file " + configLocation + ". Press Ctrl+C to exit")
	// wait until the program is terminated by SIGTERM
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	fmt.Println("Received SIGTERM, exiting")
	// cleanup and exit
	return
}