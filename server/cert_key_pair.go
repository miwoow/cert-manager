package main

import (
	"cert-manager/common"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"path/filepath"
	"strings"
)

type CertKeyPair struct {
	Certs  []*x509.Certificate
	Prikey *rsa.PrivateKey
}

func (c *CertKeyPair) LoadCertsKeyFromFile(rootPath string, certsName string) error {
	certsPath := filepath.Join(rootPath, "pub")
	prikeyPath := filepath.Join(rootPath, "pri")

	certPath := filepath.Join(certsPath, certsName)
	certsInFile, err := common.LoadCertsFromPEM(certPath)
	if err != nil {
		return err
	}
	pos := strings.LastIndex(certsName, ".")
	if pos == -1 {
		return errors.New("file name is error. Don't contain '.'")
	}
	prikey, err := common.LoadPriKeyFromPEM(filepath.Join(prikeyPath, certsName[:pos]+".key"))
	if err != nil {
		return err
	}

	c.Certs = certsInFile
	c.Prikey = prikey

	return nil
}
