package main

import (
	"cert-manager/common"
	"net"
)

//WARNING: on package can't longer than 1024 byte.

type CertClient struct {
	Ip      string
	Machine common.StreamParseStateMachine
}

func NewCertClient(ip string, conn *net.Conn) (*CertClient, error) {
	c := &CertClient{Ip: ip}
	c.Machine.Conn = *conn
	// c.Machine.ParseStatus = common.PSTART
	return c, nil
}
