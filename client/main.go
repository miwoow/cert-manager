package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"net"

	"cert-manager/common"

	"google.golang.org/protobuf/proto"
)

var cert = flag.String("cert", "", "Cert files in pem format.")
var prikey = flag.String("pri", "", "Private key file.")

func main() {
	var stateMachine common.StreamParseStateMachine
	var err error

	flag.Parse()

	stateMachine.PrivateKey, err = common.LoadPriKeyFromPEM(*prikey)
	if err != nil {
		fmt.Println("parse pri key from pem block err.r")
		return
	}

	stateMachine.Certs, err = common.LoadCertsFromPEM(*cert)
	if err != nil {
		fmt.Print("failed parse certificates:", err)
		return
	}

	conn, err := net.Dial("tcp", "127.0.0.1:6666")
	if err != nil {
		fmt.Println("err ", err)
		return
	}
	defer conn.Close()

	stateMachine.Conn = conn
	// stateMachine.ParseStatus = common.PSTART

	clientAuthPkg := &common.ClientAuth{}
	clientAuthPkg.Domain = "www.wxianlai.com"
	clientAuthPkg.Certificates = "abc"
	out, err := proto.Marshal(clientAuthPkg)
	if err != nil {
		return
	}
	data := common.PackPkg(common.CLIENTAUTH_PKGID, out)
	conn.Write(data)
	fmt.Println("Send Auth pkg.")
	for {
		var buf [1024]byte
		reader := bufio.NewReader(conn)
		n, err := reader.Read(buf[:])
		if err != nil {
			fmt.Println("[ERROR] Read from server error", err)
			break
		}
		err = stateMachine.ParseData(buf[:n], PkgHandler)
		if err != nil {
			fmt.Println("[ERROR] Error accured: ", err)
			break
		}
	}
}

func PkgHandler(s *common.StreamParseStateMachine) error {
	fmt.Println("Start parse pkg and send response.")
	switch s.TmpPkg.PkgId {
	case common.SERVERAUTHTOKEN_PKGID:
		fmt.Println("Recv server auth token pkg.")
		pkg := &common.ServerAuthToken{}
		if err := proto.Unmarshal(s.TmpPkg.PkgData, pkg); err != nil {
			return err
		}
		plainToken, err := s.PrivateKey.Decrypt(rand.Reader, []byte(pkg.GetCryptotoken()), nil)
		if err != nil {
			return err
		}
		fmt.Println("plain token is :", string(plainToken))
		clientTokenAckPkg := common.ClientAuthTokenACK{}
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
		pkgData := common.PackPkg(common.CLIENTAUTHTOKENACK_PKGID, out)
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
