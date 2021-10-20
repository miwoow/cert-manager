package common

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

func LoadPriKeyFromPEM(priKeyPath string) (*rsa.PrivateKey, error) {
	var pri *rsa.PrivateKey

	_, err := os.Stat(priKeyPath)
	if err != nil {
		return nil, err
	}

	var keybytes []byte
	keybytes, err = ioutil.ReadFile(priKeyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keybytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("faile to decode PEM code containing private key")
	}

	pri, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pri, nil
}

func LoadCertsFromPEM(certsPath string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	keybytes, err := ioutil.ReadFile(certsPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keybytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("faile to decode PEM code containing Certificat")
	}

	certs, err = x509.ParseCertificates(block.Bytes)
	if err != nil {
		return nil, err
	}
	return certs, nil
}
