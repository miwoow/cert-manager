package main

import (
	"fmt"
	"net"

	"google.golang.org/protobuf/proto"
)

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
