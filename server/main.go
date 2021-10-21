package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"unicode/utf8"
)

var configFile = flag.String("config", "./config.yaml", "Use this config file.")
var action = flag.String("action", "", `Action to do. Valiable actions:
import: Import cert to server.
daemon: Run as Daemon.
search: Search certs for this domain.`)
var pubkey = flag.String("pub", "", "Public key to use in action.")
var prikey = flag.String("pri", "", "Private key to use in action.")

var domain = flag.String("domain", "", "Domain names for search action.")

func init() {
	logFile, err := os.OpenFile("./cmserver.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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

	var certServer CertServer

	flag.Parse()
	conf, err = c.GetConf(*configFile)
	if conf == nil {
		fmt.Println(err)
		return
	}

	log.Println("action :", *action)

	cs := CertServerInstance()

	certServer.Conf = conf

	switch *action {
	case "import":
		_, err = cs.ImportCert(*pubkey, *prikey)
		if err != nil {
			fmt.Println(err)
			return
		}
	case "search":
		if utf8.RuneCountInString(*domain) == 0 {
			fmt.Println("Domain is empty.")
			return
		}
		certsForDomain, err := cs.SearchCertsForDomain(*domain)
		if err != nil {
			fmt.Println("Search certs for domain faild: ", err)
			return
		}
		if len(certsForDomain) == 0 {
			fmt.Println("Can't find any certs for domain:", *domain)
			return
		} else {
			for _, certKeyPair := range certsForDomain {
				fmt.Println("Cert for Domain: ", *domain, ", Subject name: ", certKeyPair.Certs[0].Subject.CommonName)
			}
		}

	case "daemon":
		TcpServerStart(&certServer)
	default:
		log.Println("[ERROR] Action not support.")
	}
	log.Println(conf.CertPath)
}
