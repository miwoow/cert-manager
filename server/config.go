package main

import (
	"errors"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

type FDConf struct {
	CertPath   string `yaml:"certPath"`
	ListenIp   string `yaml:"listenIp"`
	ListenPort int    `yaml:"listenPort"`
}

func (c *FDConf) GetConf(configPath string) (*FDConf, error) {

	_, err := os.Stat(configPath)

	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("[ERROR] Config file not exists: " + configPath)
		} else {
			return nil, errors.New("[ERROR] State config path error: " + configPath)
		}
	}
	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, errors.New("[ERROR] Read config file error.")
	}

	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		return nil, errors.New("[ERROR] Parse config file error.")
	}
	return c, nil
}
