package main

import (
	"bufio"
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

	var stateMachine StreamParseStateMachine

	defer conn.Close()
	clientAuthPkg := &ClientAuth{}
	clientAuthPkg.Domain = "www.wxianlai.com"
	clientAuthPkg.Certificates = "abc"
	out, err := proto.Marshal(clientAuthPkg)
	if err != nil {
		return
	}
	data := PackPkg(1, out)
	conn.Write(data)
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
