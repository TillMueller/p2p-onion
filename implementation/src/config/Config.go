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

	P2p_port          int
	P2p_hostname      string
	Intermediate_hops int
	PrivateKey        *rsa.PrivateKey
	RpsAddress        string
	ApiAddress        string
	LogfileLocation   = default_logfile_location
)

// TODO add logfile location to config

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
	// TODO maybe we need to check where the path is relative to
	config, err := ini.Load(path)
	if err != nil {
		_, err = fmt.Fprintln(os.Stderr, "Could not load configuration file " + path)
		if err != nil {
			panic(err)
		}
		return errors.New("InputOutputError")
	}
	section, err := config.GetSection("onion")
	if err != nil {
		writeError("Configuration file does not contain an onion section")
		return errors.New("ConfigurationError")
	}
	if section.HasKey("p2p_port") {
		tmpP2Pport, err := strconv.Atoi(section.Key("p2p_port").String())
		if err != nil {
			writeError("Configuration parameter p2p_port is malformed, using default: " + strconv.Itoa(default_p2p_port))
			P2p_port = default_p2p_port
		} else {
			P2p_port = tmpP2Pport
		}
	} else {
		writeError("Configuration section onion does not contain parameter p2p_port, using default: " + strconv.Itoa(default_p2p_port))
		P2p_port = default_p2p_port
	}

	if section.HasKey("p2p_hostname") {
		P2p_hostname = section.Key("p2p_hostname").String()
	} else {
		writeError("Configuration section onion does not contain parameter p2p_hostname, using default: " + default_p2p_hostname)
		P2p_hostname = default_p2p_hostname
	}

	if section.HasKey("intermediate_hops") {
		tmpIntermediateHops, err := strconv.Atoi(section.Key("intermediate_hops").String())
		if err != nil {
			writeError("Configuration parameter intermediate_hops is malformed, using default: " + strconv.Itoa(default_intermediate_hops))
			Intermediate_hops = default_intermediate_hops
		} else {
			Intermediate_hops = tmpIntermediateHops
		}
	} else {
		writeError("Configuration section onion does not contain parameter intermediate_hops, using default: " + strconv.Itoa(default_intermediate_hops))
		Intermediate_hops = default_intermediate_hops
	}
	if Intermediate_hops < minimum_intermediate_hops {
		writeError("Configuration defines insecure value for minimum intermediate hops, has to be at least " + strconv.Itoa(minimum_intermediate_hops) + ". Using default: " + strconv.Itoa(default_intermediate_hops))
		Intermediate_hops = default_intermediate_hops
	}

	hostkeyLocation := default_hostkey_location
	if section.HasKey("hostkey_location") {
		hostkeyLocation = section.Key("hostkey_location").String()
	} else {
		writeError("Configuration section onion does not contain parameter hostkey_location, using default: " + default_hostkey_location)
	}
	if loadPrivateKeyFile(hostkeyLocation) != nil {
		writeError("Could not load private key file: " + hostkeyLocation)
		return errors.New("ConfigurationError")
	}

	if section.HasKey("api_address") {
		ApiAddress = section.Key("api_address").String()
	} else {
		writeError("Configuration section onion does not contain parameter api_address, using default: " + default_api_address)
		ApiAddress = default_api_address
	}

	if section.HasKey("logfile_location") {
		LogfileLocation = section.Key("logfile_location").String()
	} else {
		writeError("Configuration section onion does not contain parameter logfile_location, using default: " + default_logfile_location)
		LogfileLocation = default_logfile_location
	}

	rpsSection, err := config.GetSection("rps")
	if err != nil {
		writeError("Configuration does not contain RPS section, using default RPS api_address: " + default_rps_address)
		RpsAddress = default_rps_address
	} else {
		if rpsSection.HasKey("api_address") {
			RpsAddress = rpsSection.Key("api_address").String()
		} else {
			writeError("Configuration does not contain api_address in RPS section, using default value: " + default_rps_address)
			RpsAddress = default_rps_address
		}
	}
	return nil
}
