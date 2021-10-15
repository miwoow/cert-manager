package main

import (
	"fmt"
	"os"
	"io/ioutil"
	"errors"
	"bytes"
	"path/filepath"
	"github.com/spacemonkeygo/openssl"
)

type CertStorage struct {
	CertPath string
}

func (s *CertStorage) CheckPubPriPair(pub string, pri string) (int, error) {
	var err error
	pubkeyfile := filepath.Join(s.CertPath, "pub", pub)
	prikeyfile := filepath.Join(s.CertPath, "pri", pri)
	_, err = os.Stat(pubkeyfile)
	if err != nil {
		return 1, errors.New("pub key file not exists: " + pub)
	}
	_, err = os.Stat(prikeyfile)
	if err != nil {
		return 1, errors.New("pri key file not exists: " + pri)
	}

	var prikey openssl.PrivateKey
	var pubkey openssl.PublicKey
	var keybytes []byte
	var keybytes2 []byte
	keybytes, err = ioutil.ReadFile(prikeyfile)
	if err != nil {
		return 1, err
	}
	prikey, err = openssl.LoadPrivateKeyFromPEM(keybytes)
	if err != nil {
		return 1, err
	}

	keybytes, err = ioutil.ReadFile(pubkeyfile)
	if err != nil {
		return 1, err
	}

	pubkey, err = openssl.LoadPublicKeyFromPEM(keybytes)
	if err != nil {
		return 1, err
	}

	keybytes, err = prikey.MarshalPKIXPublicKeyPEM()
	if err != nil {
		return 1, err
	}

	keybytes2, err = pubkey.MarshalPKIXPublicKeyPEM()
	if err != nil {
		return 1, err
	}

	if bytes.Equal(keybytes, keybytes2) {
		return 1, errors.New("Pub and Pri key is not a pair.")
	}

	return 0, nil
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

func (s *CertStorage) ImportCert(pub string, pri string) (int, error) {
	// check pub or pri key is dumplicated.
	// check pub and pri key is right.
	var err error
	_, err = s.CheckPubPriPair(pub, pri)
	if err != nil {
		return 1, err
	}
	// import it.
	fmt.Println("[TODO] import certs.")
	return 0, nil
}
