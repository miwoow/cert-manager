package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	"google.golang.org/protobuf/proto"
)

type StreamParseStateMachine struct {
	RemainCache    [1024]byte
	RemainCacheLen int
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

	if s.RemainCacheLen > 0 {
		longCache = append(longCache, s.RemainCache[:s.RemainCacheLen]...)
		longCache = append(longCache, data...)
		s.RemainCacheLen = 0
	}

	if len(longCache) > MAX_PKG_LEN {
		return errors.New("pkg too long")
	}

	pos := 0
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
		}
	}
PARSEEND:
	if pos < len(longCache) {
		copy(s.RemainCache[:], longCache[pos:])
		s.RemainCacheLen = len(longCache) - pos
	}
	return nil
}

func (s *StreamParseStateMachine) ParsePkgAndResponse() error {
	switch s.TmpPkg.PkgId {
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
		fmt.Println("plain token is :", plainToken)
		clientTokenAckPkg := ClientAuthTokenACK{}
		ack := [3]byte{'A', 'C', 'K'}
		cryptoTokenAck, err := rsa.EncryptPKCS1v15(rand.Reader, &s.PrivateKey.PublicKey, append(plainToken, ack[:]...))
		if err != nil {
			return err
		}
		clientTokenAckPkg.CryptotokenACK = string(cryptoTokenAck)
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
	default:
		return errors.New("pkg id is unknown")
	}
	return nil
}
