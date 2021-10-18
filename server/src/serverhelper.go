package main

import (
	"bufio"
	"fmt"
	"net"
	"sync"
)

var clients map[string]*CertClient
var clientsLock sync.Mutex

func ClientHandlerProcess(c *CertClient) {
	conn := *(c.Connp)
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
		err = c.ParsePackage(buf[:n], n)
		if err != nil {
			fmt.Println("[ERROR] parse pkg error: ", err)
			clientsLock.Lock()
			delete(clients, ip)
			clientsLock.Unlock()
			break
		}
		// recvStr := string(buf[:n])
		// fmt.Println("Recv Client data: ", recvStr)
		// conn.Write([]byte(recvStr + " ACK."))
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

		c, _ := NewCertClient(conn.RemoteAddr().String(), &conn, 0)
		clientsLock.Lock()
		clients[conn.RemoteAddr().String()] = c
		clientsLock.Unlock()
		go ClientHandlerProcess(c)
	}
	return 0, nil
}
