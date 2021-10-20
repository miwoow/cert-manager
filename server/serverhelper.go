package main

import (
	"bufio"
	"cert-manager/common"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"sync"

	"google.golang.org/protobuf/proto"
)

var clients map[string]*CertClient
var clientsLock sync.Mutex

func PkgHandler(s *common.StreamParseStateMachine) error {
	fmt.Println("Start parse pkg and send response.")
	var err error
	switch s.TmpPkg.PkgId {
	case common.CLIENTAUTH_PKGID:
		fmt.Println("Recv client auth pkg.")
		pkg := &common.ClientAuth{}
		if err := proto.Unmarshal(s.TmpPkg.PkgData, pkg); err != nil {
			return err
		}

		s.PrivateKey, err = common.LoadPriKeyFromPEM("6270132__wxianlai.com.key")
		if err != nil {
			fmt.Println("parse pri key from pem block error")
			return errors.New("parse pri key from pem block error")
		}

		s.Certs, err = common.LoadCertsFromPEM("6270132__wxianlai.com.pem")
		if err != nil {
			fmt.Print("failed parse certificates:", err)
			return err
		}
		// test code end
		sendPkg := common.ServerAuthToken{}

		cryptoToken, err := rsa.EncryptPKCS1v15(rand.Reader, &s.PrivateKey.PublicKey, []byte("crypto token"))
		if err != nil {
			return err
		}
		sendPkg.Code = 0
		sendPkg.Msg = ""
		sendPkg.Cryptotoken = append(sendPkg.Cryptotoken, cryptoToken...)
		out, err := proto.Marshal(&sendPkg)
		if err != nil {
			return err
		}
		pkgData := common.PackPkg(common.SERVERAUTHTOKEN_PKGID, out)
		_, err = s.Conn.Write(pkgData)
		if err != nil {
			return err
		}
		fmt.Println("send server auth token pkg.")
	case common.CLIENTAUTHTOKENACK_PKGID:
		fmt.Println("Recv client auth token ack pkg.")
		pkg := &common.ClientAuthTokenACK{}
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

func ClientHandlerProcess(c *CertClient) {
	conn := c.Machine.Conn

	defer conn.Close()
	ip := conn.RemoteAddr().String()
	for {
		reader := bufio.NewReader(conn)
		var buf [1024]byte
		n, err := reader.Read(buf[:])
		if err != nil {
			fmt.Println("read from client failed, err: ", err)
			clientsLock.Lock()
			delete(clients, ip)
			clientsLock.Unlock()
			break
		}
		fmt.Println("Recv data: ", n)
		err = c.Machine.ParseData(buf[:n], PkgHandler)
		if err != nil {
			fmt.Println("[ERROR] parse pkg error: ", err)
			clientsLock.Lock()
			delete(clients, ip)
			clientsLock.Unlock()
			break
		}
	}
}

func TcpServerStart(ip string, port int) (int, error) {
	clients = make(map[string]*CertClient)
	listen, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return 1, err
	}
	for {
		conn, err := listen.Accept()
		if err != nil {
			continue
		}

		c, _ := NewCertClient(conn.RemoteAddr().String(), &conn)
		clientsLock.Lock()
		clients[conn.RemoteAddr().String()] = c
		clientsLock.Unlock()
		go ClientHandlerProcess(c)
	}
}
