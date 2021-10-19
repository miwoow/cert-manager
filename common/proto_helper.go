package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"google.golang.org/protobuf/proto"
)

type StreamParseStateMachine struct {
	RemainCache    [1024]byte
	RemainCacheLen int
	RemainStatus   int
	ParseStatus    int
	TmpPkg         CMPkg
	PkgDataPos     int
	Conn           net.Conn
	PrivateKey     *rsa.PrivateKey
	Certs          []*x509.Certificate
}

func (s *StreamParseStateMachine) ParseData(data []byte) error {
	var longCache []byte
	var tmp [2]byte
	var pos int

	if s.RemainCacheLen > 0 {
		longCache = append(longCache, s.RemainCache[:s.RemainCacheLen]...)
		longCache = append(longCache, data...)
		s.ParseStatus = s.RemainStatus
		s.RemainCacheLen = 0
		s.RemainStatus = PUNKNOWN
	} else {
		longCache = append(longCache, data...)
		s.ParseStatus = PSTART
	}

	if len(longCache) > MAX_PKG_LEN {
		return errors.New("pkg too long")
	}

	pos = 0
	for {
		if pos > len(longCache) {
			break
		}
		switch s.ParseStatus {
		case PSTART:
			if len(longCache)-pos < 2 {
				goto PARSEEND
			}
			tmp[0] = longCache[pos]
			pos++
			s.ParseStatus = PPKGLEN
		case PPKGLEN:
			tmp[1] = longCache[pos]
			pos++
			s.TmpPkg.PkgLen = Byte2Int(tmp[:])
			s.ParseStatus = PPKGLENEND
		case PPKGLENEND:
			if len(longCache)-pos < 2 {
				goto PARSEEND
			}
			tmp[0] = longCache[pos]
			pos++
			s.ParseStatus = PMSGID
		case PMSGID:
			tmp[1] = longCache[pos]
			pos++
			s.TmpPkg.PkgId = Byte2Int(tmp[:])
			s.ParseStatus = PMSGIDEND
		case PMSGIDEND:
			s.PkgDataPos = 0
			s.TmpPkg.PkgData = append(s.TmpPkg.PkgData, longCache[pos])
			pos++
			s.PkgDataPos++
			s.ParseStatus = PCOPYDATA
		case PCOPYDATA:
			s.TmpPkg.PkgData = append(s.TmpPkg.PkgData, longCache[pos])
			pos++
			s.PkgDataPos++
			if s.PkgDataPos == int(s.TmpPkg.PkgLen)-2 {
				err := s.ParsePkgAndResponse()
				s.ParseStatus = PSTART
				if err != nil {
					return err
				}
			}
		default:
			return errors.New("unknow status")
		}
	}
PARSEEND:
	if pos < len(longCache) {
		copy(s.RemainCache[:], longCache[pos:])
		s.RemainCacheLen = len(longCache) - pos
		s.RemainStatus = s.ParseStatus
	}
	return nil
}

func (s *StreamParseStateMachine) ParsePkgAndResponse() error {
	fmt.Println("Start parse pkg and send response.")
	switch s.TmpPkg.PkgId {
	case CLIENTAUTH_PKGID:
		fmt.Println("Recv client auth pkg.")
		pkg := &ClientAuth{}
		if err := proto.Unmarshal(s.TmpPkg.PkgData, pkg); err != nil {
			return err
		}
		// init machine certs and pri key
		_, err := os.Stat("6270132__wxianlai.com.key")
		if err != nil {
			fmt.Println("Pri key is not exists: ")
			return err
		}

		keybytes, err := ioutil.ReadFile("6270132__wxianlai.com.key")
		if err != nil {
			fmt.Println("Read pri key file error", err)
			return err
		}

		block, _ := pem.Decode(keybytes)
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			fmt.Println("Faile to decode PEM code containing Private key.")
			return errors.New("faile to decode PEM code containing Private key")
		}

		s.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			fmt.Println("parse pri key from pem block error")
			return errors.New("parse pri key from pem block error")
		}

		keybytes, err = ioutil.ReadFile("6270132__wxianlai.com.pem")
		if err != nil {
			fmt.Println("Read Cert file failed.", err)
			return err
		}

		block, _ = pem.Decode(keybytes)
		if block == nil || block.Type != "CERTIFICATE" {
			fmt.Println("faile to decode PEM code containing Certificat.")
			return errors.New("faile to decode PEM code containing Certificat")
		}

		s.Certs, err = x509.ParseCertificates(block.Bytes)
		if err != nil {
			fmt.Print("failed parse certificates:", err)
			return err
		}
		// test code end
		sendPkg := ServerAuthToken{}

		cryptoToken, err := rsa.EncryptPKCS1v15(rand.Reader, &s.PrivateKey.PublicKey, []byte("crypto token"))
		if err != nil {
			return err
		}
		sendPkg.Cryptotoken = append(sendPkg.Cryptotoken, cryptoToken...)
		out, err := proto.Marshal(&sendPkg)
		if err != nil {
			return err
		}
		pkgData := PackPkg(SERVERAUTHTOKEN_PKGID, out)
		_, err = s.Conn.Write(pkgData)
		if err != nil {
			return err
		}
		fmt.Println("send server auth token pkg.")
	case SERVERAUTHTOKEN_PKGID:
		fmt.Println("Recv server auth token pkg.")
		pkg := &ServerAuthToken{}
		if err := proto.Unmarshal(s.TmpPkg.PkgData, pkg); err != nil {
			return err
		}
		plainToken, err := s.PrivateKey.Decrypt(rand.Reader, []byte(pkg.GetCryptotoken()), nil)
		if err != nil {
			return err
		}
		fmt.Println("plain token is :", string(plainToken))
		clientTokenAckPkg := ClientAuthTokenACK{}
		ack := [3]byte{'A', 'C', 'K'}
		cryptoTokenAck, err := rsa.EncryptPKCS1v15(rand.Reader, &s.PrivateKey.PublicKey, append(plainToken, ack[:]...))
		if err != nil {
			return err
		}

		clientTokenAckPkg.CryptotokenACK = append(clientTokenAckPkg.CryptotokenACK, cryptoTokenAck...)
		out, err := proto.Marshal(&clientTokenAckPkg)
		if err != nil {
			return err
		}
		pkgData := PackPkg(CLIENTAUTHTOKENACK_PKGID, out)
		_, err = s.Conn.Write(pkgData)
		if err != nil {
			return err
		}
		fmt.Println("Send cleint auth token ack pkg.")
	case CLIENTAUTHTOKENACK_PKGID:
		fmt.Println("Recv client auth token ack pkg.")
		pkg := &ClientAuthTokenACK{}
		if err := proto.Unmarshal(s.TmpPkg.PkgData, pkg); err != nil {
			return err
		}
		plainTokenACK, err := s.PrivateKey.Decrypt(rand.Reader, []byte(pkg.GetCryptotokenACK()), nil)
		if err != nil {
			return err
		}
		fmt.Println("Plain token ack is :", string(plainTokenACK))
	default:
		return errors.New("pkg id is unknown")
	}
	return nil
}
