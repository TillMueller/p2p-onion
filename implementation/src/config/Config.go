package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
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
	default_rps_address       = "127.0.0.1:42426"
	default_api_address       = "127.0.0.1:42425"
	default_hostkey_location  = "hostkey.pem"
	default_logfile_location  = "onion.log"
	default_log_info          = true

	P2p_port          int
	P2p_hostname      string
	Intermediate_hops int
	PrivateKey        *rsa.PrivateKey
	RpsAddress        string
	ApiAddress        string
	LogfileLocation   = default_logfile_location
	LogInfo           bool
	LogDebug          bool
)

func readBoolFromConfig(section *ini.Section, key string, defaultValue bool) bool {
	if section.HasKey(key) {
		switch section.Key(key).String() {
		case "yes":
			return true
		case "no":
			return false
		default:
			writeError("Configuration parameter " + key + " is malformed, using default: " + strconv.FormatBool(defaultValue))
			return defaultValue
		}
	} else {
		writeError("Configuration section onion does not contain parameter " + key + ", using default: " + strconv.FormatBool(defaultValue))
		return defaultValue
	}
}

func readStringFromConfig(section *ini.Section, key string, defaultValue string) string {
	if section.HasKey(key) {
		return section.Key(key).String()
	} else {
		writeError("Configuration section onion does not contain parameter " + key + ", using default: " + defaultValue)
		return defaultValue
	}
}

func readIntFromConfig(section *ini.Section, key string, defaultValue int) int {
	if section.HasKey(key) {
		tmpValue, err := strconv.Atoi(section.Key(key).String())
		if err != nil {
			writeError("Configuration parameter " + key + " is malformed, using default: " + strconv.Itoa(defaultValue))
			return defaultValue
		} else {
			return tmpValue
		}
	} else {
		writeError("Configuration section onion does not contain parameter " + key + ", using default: " + strconv.Itoa(defaultValue))
		return defaultValue
	}
}

func loadPrivateKeyFile(hostkeyLocation string) error {
	keyFileContent, err := ioutil.ReadFile(hostkeyLocation)
	if err != nil {
		writeError("Could not read hostkey from pem file, is the path correct?")
		return errors.New("InputOutputError")
	}
	privateKeyPem, _ := pem.Decode(keyFileContent)
	if privateKeyPem.Type != "RSA PRIVATE KEY" {
		writeError("Host key is in wrong format")
		return errors.New("CryptoError")
	}
	PrivateKey, err = x509.ParsePKCS1PrivateKey(privateKeyPem.Bytes)
	if err != nil {
		writeError("Could not parse private host key")
		return errors.New("CryptoError")
	}
	return nil
}

func writeError(msg string) {
	_, err := fmt.Fprintln(os.Stderr, msg)
	if err != nil {
		panic(err)
	}
}

func LoadConfig(path string) error {
	config, err := ini.Load(path)
	if err != nil {
		writeError("Could not load configuration file "+path)
		return errors.New("InputOutputError")
	}
	section, err := config.GetSection("onion")
	if err != nil {
		writeError("Configuration file does not contain an onion section")
		return errors.New("ConfigurationError")
	}
	P2p_port = readIntFromConfig(section, "p2p_port", default_p2p_port)
	P2p_hostname = readStringFromConfig(section, "p2p_hostname", default_p2p_hostname)
	Intermediate_hops = readIntFromConfig(section, "intermediate_hops", default_intermediate_hops)
	if Intermediate_hops < minimum_intermediate_hops {
		writeError("Configuration defines insecure value for minimum intermediate hops, has to be at least " + strconv.Itoa(minimum_intermediate_hops) + ". Using default: " + strconv.Itoa(default_intermediate_hops))
		Intermediate_hops = default_intermediate_hops
	}

	hostkeyLocation := readStringFromConfig(section, "hostkey_location", default_hostkey_location)
	if loadPrivateKeyFile(hostkeyLocation) != nil {
		writeError("Could not load private key file: " + hostkeyLocation)
		return errors.New("ConfigurationError")
	}

	ApiAddress = readStringFromConfig(section, "api_address", default_api_address)
	LogfileLocation = readStringFromConfig(section, "logfile_location", default_logfile_location)
	LogInfo = readBoolFromConfig(section, "log_info", true)
	LogDebug = readBoolFromConfig(section, "log_debug", true)

	rpsSection, err := config.GetSection("rps")
	if err != nil {
		writeError("Configuration does not contain RPS section, using default RPS api_address: " + default_rps_address)
		RpsAddress = default_rps_address
	} else {
		RpsAddress = readStringFromConfig(rpsSection, "api_address", default_rps_address)
	}
	return nil
}
