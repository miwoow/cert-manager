package main

import (
	"bytes"
	"cert-manager/common"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type CertStorage struct {
	CertPath string
}

var instance *CertStorage
var once sync.Once

func CertServerInstance() *CertStorage {
	once.Do(func() {
		instance = &CertStorage{}
		instance.Init("./certs")
	})
	return instance
}

func (s *CertStorage) CheckPubPriPair(certPath string, priPath string) (int, error) {
	prikey, err := common.LoadPriKeyFromPEM(priPath)
	if err != nil {
		return 1, err
	}
	certs, err := common.LoadCertsFromPEM(certPath)
	if err != nil {
		return 1, err
	}

	if prikey.PublicKey.Equal(certs[0].PublicKey) {
		return 0, nil
	} else {
		return 1, errors.New("pub and pri key is not a pair")
	}
}

func (s *CertStorage) Init(path string) (int, error) {
	s.CertPath = path
	pubkeypath := filepath.Join(s.CertPath, "pub")
	prikeypath := filepath.Join(s.CertPath, "pri")
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

func (s *CertStorage) CertNewName(certPath string) (string, error) {
	certs, err := common.LoadCertsFromPEM(certPath)
	if err != nil {
		return "", err
	}

	if len(certs) == 0 {
		return "", errors.New("certificate file contains 0 certificat")
	}
	//fmt.Println(certs[0].NotBefore)
	//fmt.Println(certs[0].NotAfter)
	y := certs[0].NotAfter
	newFileName := fmt.Sprintf("%s_%d_%02d_%02d", strings.Replace(certs[0].Subject.CommonName, "*", "STAR", -1), y.Year(), y.Month(), y.Day())
	return newFileName, nil
}

func (s *CertStorage) GetCertsKeyByCertsPem(certsPem []byte) (*CertKeyPair, error) {
	var certKeyPair *CertKeyPair = nil

	certsPath := filepath.Join(s.CertPath, "pub")

	files, err := ioutil.ReadDir(certsPath)
	if err != nil {
		return nil, err
	}

	for _, onefile := range files {
		if onefile.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(certsPath, onefile.Name()))
		if err != nil {
			return nil, err
		}
		if bytes.Equal(content, certsPem) {
			certKeyPair = &CertKeyPair{}
			certKeyPair.LoadCertsKeyFromFile(s.CertPath, onefile.Name())
			break
		}
	}

	return certKeyPair, nil
}

func (s *CertStorage) SearchCertsForDomain(domain string) ([]*CertKeyPair, error) {
	//TODO: return slice may be inefficent.
	var certs []*CertKeyPair

	certsPath := filepath.Join(s.CertPath, "pub")
	files, err := ioutil.ReadDir(certsPath)
	if err != nil {
		return nil, err
	}
	for _, onefile := range files {
		if onefile.IsDir() {
			continue
		}
		certPath := filepath.Join(certsPath, onefile.Name())
		certsInFile, err := common.LoadCertsFromPEM(certPath)
		if err != nil {
			continue
		}
		if certsInFile[0].VerifyHostname(domain) != nil {
			continue
		} else {
			certKeyPair := &CertKeyPair{}
			certKeyPair.LoadCertsKeyFromFile(s.CertPath, onefile.Name())
			certs = append(certs, certKeyPair)
		}
	}

	return certs, nil
}

func (s *CertStorage) ImportCert(certPath string, priPath string) (int, error) {
	// check pub or pri key is dumplicated.
	// check pub and pri key is right.
	var err error
	var name string
	_, err = s.CheckPubPriPair(certPath, priPath)
	if err != nil {
		return 1, err
	}

	name, err = s.CertNewName(certPath)
	if err != nil {
		return 1, err
	}
	fmt.Println("cert new name: ", name)

	// check dumplicate.
	newCertPath := filepath.Join(s.CertPath, "pub", name+".pem")
	_, err = os.Stat(newCertPath)
	if err != nil {
		if os.IsNotExist(err) {
			// import it
			err = os.Rename(certPath, newCertPath)
			if err != nil {
				return 1, err
			}
			newPriPath := filepath.Join(s.CertPath, "pri", name+".key")
			err = os.Rename(priPath, newPriPath)
			if err != nil {
				return 1, err
			}
		} else if os.IsExist(err) {
			// dumplicate. ignore.
			return 0, nil
		} else {
			return 1, err
		}
	}

	return 0, nil
}
