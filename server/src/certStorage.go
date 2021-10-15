package main

import (
	"fmt"
	"os"
	"errors"
	"path/filepath"
//	"github.com/spacemonkeygo/openssl"
)

type CertStorage struct {
	CertPath string
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

func (s *CertStorage) CheckPubPriPair(pub string, pri string) (int, error) {

	return 0, nil
}

func (s *CertStorage) ImportCert(pub string, pri string) int {
	// check pub and pri key is right.
	// check pub or pri key is dumplicated.
	// import it.
	fmt.Println("[TODO] import certs.")
	return 0
}
