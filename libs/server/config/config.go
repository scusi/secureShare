// config - secureShareServer config module
package config

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
)

type Config struct {
	ListenAddr string // host:port listen address
	CertFile   string // TLS certificate to use
	KeyFile    string // TLS key to use
	DataDir    string // directory where userdata is written to
	UsersFile  string // yaml file which holds the user database
	Email      string // Email to be used for the server minilock identity
	Password   string // Password to be used for the server minilock identity
}

func New() (cfg *Config) {
	cfg = &Config{
		ListenAddr: "127.0.0.1:9999",
		CertFile:   "",
		KeyFile:    "",
		DataDir:    "data",
		UsersFile:  "users.yml",
		Email:      "",
		Password:   "",
	}
	return
}

func ReadFromFile(filename string) (cfg *Config, err error) {
	// read and parse config
	cdata, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	cfg = new(Config)
	err = yaml.Unmarshal(cdata, cfg)
	if err != nil {
		return
	}
	return
}

func WriteToFile(filename string, cfg *Config) (err error) {
	y, err := yaml.Marshal(cfg)
	if err != nil {
		return
	}
	err = ioutil.WriteFile(filename, y, 0700)
	if err != nil {
		return
	}
	return
}
