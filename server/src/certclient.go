package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"google.golang.org/protobuf/proto"
)

//WARNING: on package can't longer than 1024 byte.

type CertClient struct {
	Ip             string
	Connp          *net.Conn
	ParseStatus    int
	RemainData     []byte
	RemainLen      int
	PackageLen     uint16
	PackageId      uint16
	PackageData    []byte
	PackageDataPos int
}

func NewCertClient(ip string, conn *net.Conn, status int) (*CertClient, error) {
	c := &CertClient{Ip: ip, Connp: conn, ParseStatus: status}
	c.PackageData = make([]byte, 0)
	return c, nil
}

func (c *CertClient) ParsePackage(buf []byte, buflen int) error {
	var longbuf []byte
	longbuf = make([]byte, 0)
	longbuf = append(longbuf, c.RemainData[:c.RemainLen]...)
	longbuf = append(longbuf, buf[:buflen]...)
	var tmp []byte
	var pos int

	tmp = make([]byte, 2)

	if len(longbuf) > 1024 {
		return errors.New("[ERROR] Package length > 1024 byte")
	}

	pos = 0
	for {
		if pos >= len(longbuf) {
			break
		}
		switch c.ParseStatus {
		case PSTART:
			if len(longbuf)-pos < 2 {
				goto PARSEEND
			}
			tmp[0] = longbuf[pos]
			pos++
			c.ParseStatus = PPKGLEN
		case PPKGLEN:
			tmp[1] = longbuf[pos]
			pos++
			bytebuf := bytes.NewBuffer(tmp)
			binary.Read(bytebuf, binary.BigEndian, &(c.PackageLen))
			c.ParseStatus = PPKGLENEND
		case PPKGLENEND:
			if len(longbuf)-pos < 2 {
				goto PARSEEND
			}
			tmp[0] = longbuf[pos]
			pos++
			c.ParseStatus = PMSGID
		case PMSGID:
			tmp[1] = longbuf[pos]
			pos++
			bytebuf := bytes.NewBuffer(tmp)
			binary.Read(bytebuf, binary.BigEndian, &(c.PackageId))
			c.ParseStatus = PMSGIDEND
		case PMSGIDEND:
			c.PackageDataPos = 0
			c.PackageData = append(c.PackageData, longbuf[pos])
			pos++
			c.PackageDataPos++
			c.ParseStatus = PCOPYDATA
		case PCOPYDATA:
			c.PackageData = append(c.PackageData, longbuf[pos])
			pos++
			c.PackageDataPos++
			if c.PackageDataPos == int(c.PackageLen)-2 {
				// parse data.
				c.ParsePkgAndResponse()
				c.ParseStatus = PSTART
			}
		}
	}
PARSEEND:
	if pos < len(longbuf) {
		copy(c.RemainData, longbuf[pos:])
		c.RemainLen = len(longbuf) - pos
	}

	return nil
}

func (c *CertClient) ParsePkgAndResponse() error {
	switch c.PackageId {
	case CLIENTAUTH_PKGID:
		pkg := &ClientAuth{}
		if err := proto.Unmarshal(c.PackageData, pkg); err != nil {
			return err
		}
		fmt.Println(string(pkg.Domain))
		fmt.Println(string(pkg.Certificates))

	}
	return nil
}
