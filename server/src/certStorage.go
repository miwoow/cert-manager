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
	_, err = os.Stat(pub)
	if err != nil {
		return 1, err
	}
	_, err = os.Stat(pri)
	if err != nil {
		return 1, err
	}

	var prikey openssl.PrivateKey
	var pubkey openssl.PublicKey
	var cert *openssl.Certificate
	var keybytes []byte
	var keybytes2 []byte
	keybytes, err = ioutil.ReadFile(pri)
	if err != nil {
		return 1, err
	}
	prikey, err = openssl.LoadPrivateKeyFromPEM(keybytes)
	if err != nil {
		return 1, err
	}

	keybytes, err = ioutil.ReadFile(pub)
	if err != nil {
		return 1, err
	}

	certs := openssl.SplitPEM(keybytes)
	if len(certs) == 0 {
		return 1, errors.New("Split PEM Failed.")
	}

	cert, err = openssl.LoadCertificateFromPEM(certs[0])
	if err != nil {
		return 1, err
	}

	pubkey, err = cert.PublicKey()
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

	if !bytes.Equal(keybytes, keybytes2) {
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

func (s *CertStorage) CertNewName(cert string) (string, error) {
	var certObj *openssl.Certificate
	var err error
	var keybytes []byte
	keybytes, err = ioutil.ReadFile(cert)
	if err != nil {
		return "", err
	}
	certObj, err = openssl.LoadCertificateFromPEM(keybytes)
	if err != nil {
		return "", err
	}

	var name *openssl.Name
	name, err = certObj.GetSubjectName()
	if (err != nil) {
		return "", err
	}

	entry, ok := name.GetEntry(openssl.NID_commonName)
	if !ok {
		return "", errors.New("Get Entry failed.")
	}

	return entry, nil
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
