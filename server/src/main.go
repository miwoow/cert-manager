package main

import (
	"fmt"
	"flag"
	"log"
	"os"
)

var configFile = flag.String("config", "./config.yaml", "Use this config file.")
var runMode = flag.String("runMode", "d", "Run as daemon.")
var action = flag.String("action", "", `Action to do. Valiable actions:
import: Import cert to server.`)
var pubkey = flag.String("pub", "", "Public key to use in action.")
var prikey = flag.String("pri", "", "Private key to use in action.")

func init() {
	logFile, err := os.OpenFile("./cmserver.log", os.O_CREATE | os. O_WRONLY | os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("[ERROR] OPen log file failed, err: ", err)
		return
	}
	log.SetOutput(logFile)
	log.SetFlags(log.Flags() | log.Llongfile)
}

func main() {
	var err error
	var conf *FDConf
	var c FDConf

	flag.Parse()
	conf, err = c.GetConf(*configFile)
	if conf == nil {
		fmt.Println(err)
		return
	}

	log.Println("action :", *action)

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
	default:
		log.Println("[ERROR] Action not support.")
	}
	log.Println(conf.CertPath)

	fmt.Println("hello world")
}
