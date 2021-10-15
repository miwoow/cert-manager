package main

import (
	"fmt"
	"flag"
)

var configFile = flag.String("config", "./config.yaml", "Use this config file.")
var runMode = flag.String("runMode", "d", "Run as daemon.")
var action = flag.String("action", "", `Action to do. Valiable actions:
import: Import cert to server.`)
var pubkey = flag.String("pub", "", "Public key to use in action.")
var prikey = flag.String("pri", "", "Private key to use in action.")

func main() {
	var err error
	var conf *FDConf
	flag.Parse()

	var c FDConf
	conf, err = c.GetConf(*configFile)
	if conf == nil {
		fmt.Println(err)
		return
	}

	fmt.Println("action :", *action)

	switch *action {
	case "import":
		var cs CertStorage
		var code int
		_, err := cs.Init(conf.CertPath)
		if err != nil {
			fmt.Println(err)
			return
		}
		code = cs.ImportCert(*pubkey, *prikey)
		if code != 0 {
			return
		}
		fmt.Println("action import.\n")
	default:
		fmt.Println("[ERROR] Action not support.\n")
	}
	fmt.Println(conf.CertPath)

	fmt.Println("hello world\n")
}
