package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"cert-manager/common"

	"google.golang.org/protobuf/proto"
)

var cert = flag.String("cert", "", "Cert files in pem format.")
var prikey = flag.String("pri", "", "Private key file.")

func main() {
	var stateMachine common.StreamParseStateMachine

	flag.Parse()

	_, err := os.Stat(*prikey)
	if err != nil {
		fmt.Println("Pri key is not exists: ", *prikey)
		return
	}

	keybytes, err := ioutil.ReadFile(*prikey)
	if err != nil {
		fmt.Println("Read pri key file error", err)
		return
	}

	block, _ := pem.Decode(keybytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		fmt.Println("Faile to decode PEM code containing Private key.")
		return
	}

	stateMachine.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("parse pri key from pem block err.r")
		return
	}

	keybytes, err = ioutil.ReadFile(*cert)
	if err != nil {
		fmt.Println("Read Cert file failed.", err)
		return
	}

	block, _ = pem.Decode(keybytes)
	if block == nil || block.Type != "CERTIFICATE" {
		fmt.Println("faile to decode PEM code containing Certificat.")
		return
	}

	stateMachine.Certs, err = x509.ParseCertificates(block.Bytes)
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

	clientAuthPkg := &common.ClientAuth{}
	clientAuthPkg.Domain = "www.wxianlai.com"
	clientAuthPkg.Certificates = "abc"
	out, err := proto.Marshal(clientAuthPkg)
	if err != nil {
		return
	}
	data := common.PackPkg(1, out)
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
		err = stateMachine.ParseData(buf[:n])
		if err != nil {
			fmt.Println("[ERROR] Error accured: ", err)
			break
		}
	}
}
