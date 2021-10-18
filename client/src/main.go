package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"

	"google.golang.org/protobuf/proto"
)

var cache [1024]byte
var cachelen int = 0
var parseStatus int

func ParseData(data []byte) error {
	var longCache []byte
	var pos int
	longCache = make([]byte, 0)
	if cachelen > 0 {
		longCache = append(longCache, cache[:cachelen]...)
		longCache = append(longCache, data...)
	}
	if len(longCache) > 1024 {
		return errors.New("pkg too long")
	}
	pos = 0
	for {
		if pos > len(longCache) {
			break
		}

	}
	return nil
}

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:6666")
	if err != nil {
		fmt.Println("err ", err)
		return
	}

	defer conn.Close()
	clientAuthPkg := &ClientAuth{}
	clientAuthPkg.Domain = "www.wxianlai.com"
	clientAuthPkg.Certificates = "abc"
	out, err := proto.Marshal(clientAuthPkg)
	if err != nil {
		return
	}
	var data []byte
	var pkglen int
	var pkgid int = 1
	pkglen = len(out) + 2
	data = make([]byte, 0)
	data = append(data, Int2Byte(pkglen)...)
	data = append(data, Int2Byte(pkgid)...)
	data = append(data, out...)
	conn.Write(data)
	for {
		var buf [1024]byte
		reader := bufio.NewReader(conn)
		n, err := reader.Read(buf[:])
		if err != nil {
			fmt.Println("[ERROR] Read from server error", err)
			break
		}
		err = ParseData(buf[:n])
		if err != nil {
			fmt.Println("[ERROR] Error accured: ", err)
			break
		}
	}
	// inputReader := bufio.NewReader(os.Stdin)
	// for {
	// 	input, _ := inputReader.ReadString('\n')
	// 	inputInfo := strings.Trim(input, "\r\n")
	// 	if strings.ToUpper(inputInfo) == "Q" {
	// 		return
	// 	}

	// 	_, err := conn.Write([]byte(inputInfo))
	// 	if err != nil {
	// 		fmt.Println("send failed, err:", err)
	// 		return
	// 	}

	// 	buf := [512]byte{}
	// 	n, err := conn.Read(buf[:])
	// 	if err != nil {
	// 		fmt.Println("recv failed, err:", err)
	// 		return
	// 	}
	// 	fmt.Println(string(buf[:n]))
	// }
}
