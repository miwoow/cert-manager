package main

import (
	"fmt"
	"os"
	"io/ioutil"
	"strings"
	"errors"
	"path/filepath"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
)

type CertStorage struct {
	CertPath string
}

func (s *CertStorage) CheckPubPriPair(cert string, pri string) (int, error) {
	var err error
	_, err = os.Stat(cert)
	if err != nil {
		return 1, err
	}
	_, err = os.Stat(pri)
	if err != nil {
		return 1, err
	}

	var keybytes []byte
	keybytes, err = ioutil.ReadFile(pri)
	if err != nil {
		return 1, err
	}

	block, _ := pem.Decode(keybytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return 1, errors.New("Faile to decode PEM code containing Private key.")
	}

	var prikey *rsa.PrivateKey
	prikey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return 1, err
	}

	keybytes, err = ioutil.ReadFile(cert)
	if err != nil {
		return 1, err
	}

	block, _ = pem.Decode(keybytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return 1, errors.New("faile to decode PEM code containing Certificat.")
	}

	var certs []*x509.Certificate
	certs, err = x509.ParseCertificates(block.Bytes)
	if err != nil {
		return 1, err
	}


	if prikey.PublicKey.Equal(certs[0].PublicKey) {
		return 0, nil
	} else {
		return 1, errors.New("Pub and pri key is not a pair.")
	}
}

func (s *CertStorage) Init(path string) (int, error) {
	s.CertPath = path
	var pubkeypath string
	var prikeypath string
	pubkeypath = filepath.Join(s.CertPath, "pub")
	prikeypath = filepath.Join(s.CertPath, "pri")
	_, err := os.Stat(pubkeypath)
	if err != nil {
		err = os.Mkdir(pubkeypath, os.ModePerm)
		if err != nil {
			return 1, errors.New("mk pubkeypath error: " + pubkeypath)
		}
	}

	_, err = os.Stat(prikeypath)
	if err != nil {
		err = os.Mkdir(prikeypath, os.ModePerm)
		if err != nil {
			return 1, errors.New("mk prikeypath error: " + prikeypath)
		}
	}
	return 0, nil
}

func (s *CertStorage) CertList() {
	fmt.Println("[TODO] list certs.")
}

func (s *CertStorage) CertNewName(cert string) (string, error) {
	keybytes, err := ioutil.ReadFile(cert)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(keybytes)
	if block == nil {
		return "", errors.New("Failed to decode PEM data containg cert info.")
	}

	var certs []*x509.Certificate
	certs, err = x509.ParseCertificates(block.Bytes)
	if err != nil {
		return "", err
	}

	if len(certs) == 0 {
		return "", errors.New("Certificate file contains 0 certificat.")
	}
	//fmt.Println(certs[0].NotBefore)
	//fmt.Println(certs[0].NotAfter)
	y := certs[0].NotAfter
	newFileName := fmt.Sprintf("%s_%d_%02d_%02d", strings.Replace(certs[0].Subject.CommonName, "*", "star", -1), y.Year(), y.Month(), y.Day())
	return newFileName, nil
}

func (s *CertStorage) ImportCert(pub string, pri string) (int, error) {
	// check pub or pri key is dumplicated.
	// check pub and pri key is right.
	var err error
	var name string
	_, err = s.CheckPubPriPair(pub, pri)
	if err != nil {
		return 1, err
	}

	name, err = s.CertNewName(pub)
	if err != nil {
		return 1, err
	}
	fmt.Println("cert new name: ", name)
	// import it.
	fmt.Println("[TODO] import certs.")
	return 0, nil
}
