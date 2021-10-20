package common

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
)

type StreamParseStateMachine struct {
	RemainCache    []byte
	RemainCacheLen int
	RemainStatus   int
	ParseStatus    int
	TmpPkg         CMPkg
	PkgDataPos     int
	Conn           net.Conn
	PrivateKey     *rsa.PrivateKey
	Certs          []*x509.Certificate
}

type PackageProcessFunc func(s *StreamParseStateMachine) error

func (s *StreamParseStateMachine) ParseData(data []byte, pkgHandler PackageProcessFunc) error {
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
	}

	pos = 0
	for {
		if pos >= len(longCache) {
			break
		}
		switch s.ParseStatus {
		case PSTART:
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
			fmt.Println("pkg id: ", s.TmpPkg.PkgId)
			s.ParseStatus = PMSGIDEND
		case PMSGIDEND:
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
			fmt.Println("pkg len: ", s.TmpPkg.PkgLen)
			s.ParseStatus = PPKGLENEND
		case PPKGLENEND:
			s.PkgDataPos = 0
			s.TmpPkg.PkgData = append(s.TmpPkg.PkgData, longCache[pos])
			pos++
			s.PkgDataPos++
			s.ParseStatus = PCOPYDATA
		case PCOPYDATA:
			s.TmpPkg.PkgData = append(s.TmpPkg.PkgData, longCache[pos])
			pos++
			s.PkgDataPos++
			if s.PkgDataPos == int(s.TmpPkg.PkgLen) {
				err := pkgHandler(s)
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

	s.RemainCacheLen = len(longCache) - pos
	s.RemainStatus = s.ParseStatus
	if s.RemainCacheLen > 0 {
		s.RemainCache = make([]byte, s.RemainCacheLen)
		copy(s.RemainCache, longCache[pos:])
	}
	return nil
}
