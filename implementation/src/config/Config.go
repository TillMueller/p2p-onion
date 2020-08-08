package config

import (
	"bufio"
	"encoding/pem"
	"errors"
	"onion/logger"
	"os"
	"strconv"

	"github.com/go-ini/ini"
)

var (
	// default values
	default_p2p_port          = 42424
	default_p2p_hostname      = "127.0.0.1"
	default_intermediate_hops = 2
	minimum_intermediate_hops = 2
	default_hostkey_location  = "hostkey.pem"

	P2p_port          int
	P2p_hostname      string
	Intermediate_hops int
	Hostkey           []byte
	PrivateKey        []byte
	PublicKey         []byte
	RpsAddress        string
)

func loadConfig(path string) error {
	// TODO maybe we need to check where the path is relative to
	config, err := ini.Load(path)
	if err != nil {
		logger.Error.Println("Could not load configuration file " + path)
		return errors.New("InputOutputError")
	}

	P2p_port = config.Section("onion").Key("p2p_port").MustInt(default_p2p_port)
	P2p_hostname = config.Section("onion").Key("p2p_hostname").MustString(default_p2p_hostname)
	Intermediate_hops = config.Section("onion").Key("minimum_intermediate_hops").MustInt(default_intermediate_hops)
	if Intermediate_hops < minimum_intermediate_hops {
		logger.Error.Println("Config defines insecure value for minimum intermediate hops, has to be at least " + strconv.Itoa(minimum_intermediate_hops))
		return errors.New("ConfigurationError")
	}
	hostkey_location := config.Section("onion").Key("hostkey").MustString(default_hostkey_location)
	fi, err := os.Stat(hostkey_location)
	if err != nil {
		logger.Error.Println("Could not probe length of either given hostkey file or hostkey file in default location")
		return errors.New("ConfigurationError")
	}

	// Adapted from https://medium.com/@Raulgzm/export-import-pem-files-in-go-67614624adc7
	// TODO test this
	file, err := os.Open(hostkey_location)
	if err != nil {
		logger.Error.Println("Neither hostkey specified in config nor hostkey in default location found")
		return errors.New("ConfigurationError")
	}
	hostkeyBuf := make([]byte, fi.Size())
	tempBuf := bufio.NewReader(file)

	readSize, err := tempBuf.Read(hostkeyBuf)
	if err != nil || int64(readSize) != fi.Size() {
		logger.Error.Println("Error while reading hostkey file")
		return errors.New("InputOutputError")
	}
	PrivateKey, _ := pem.Decode([]byte(hostkeyBuf))
	if PrivateKey == nil {
		logger.Error.Println("Could not decode hostkey from PEM file")
		return errors.New("InputOutputError")
	}
	//todo fix issue here
	PublicKey = &PrivateKey.PublicKey
	if !config.Section("rps").HasKey("api_address") {
		logger.Error.Println("RPS API address could not be found in config")
		return errors.New("ConfigurationError")
	}
	RpsAddress = config.Section("rps").Key("api_address").MustString("")
	return nil
}
