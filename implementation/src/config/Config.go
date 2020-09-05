package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"onion/logger"
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
	PrivateKey        *rsa.PrivateKey
	RpsAddress        string
	ApiAddress        string
)

// TODO add logfile location to config

func loadPrivateKeyFile(hostkeyLocation string) error {
	keyFileContent, err := ioutil.ReadFile(hostkeyLocation)
	if err != nil {
		logger.Error.Println("Could not read hostkey from pem file, is the path correct?")
		return errors.New("InputOutputError")
	}
	privateKeyPem, _ := pem.Decode(keyFileContent)
	if privateKeyPem.Type != "RSA PRIVATE KEY" {
		logger.Error.Println("Host key is in wrong format")
		return errors.New("CryptoError")
	}
	PrivateKey, err = x509.ParsePKCS1PrivateKey(privateKeyPem.Bytes)
	if err != nil {
		logger.Error.Println("Could not parse private host key")
		return errors.New("CryptoError")
	}
	logger.Info.Println("Loaded private key")
	return nil
}

func LoadConfig(path string) error {
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
	hostkeyLocation := config.Section("onion").Key("hostkey").MustString(default_hostkey_location)
	if loadPrivateKeyFile(hostkeyLocation) != nil {
		logger.Error.Println("Private key file load failed: " + hostkeyLocation)
		return errors.New("ConfigurationError")
	}
	if !config.Section("rps").HasKey("api_address") {
		logger.Error.Println("RPS API address could not be found in config")
		return errors.New("ConfigurationError")
	}
	RpsAddress = config.Section("rps").Key("api_address").MustString("")
	ApiAddress = config.Section("onion").Key("api_address").MustString("")
	return nil
}
