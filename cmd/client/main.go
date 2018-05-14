// secureShare client
package main

import (
	"flag"
	"fmt"
	"github.com/cathalgarvey/go-minilock"
	"github.com/scusi/secureShare/libs/askpass"
	"github.com/scusi/secureShare/libs/client"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

var defClientConfigFile string
var clientConfigFile string

var Debug bool
var list bool
var register bool
var file string
var fileID string
var recipient string

func init() {
	flag.BoolVar(&Debug, "debug", false, "enables debug output when 'true'")
	// get user home dir
	usr, err := user.Current()
	checkFatal(err)
	defClientConfigFile = filepath.Join(usr.HomeDir, "secureshare", "client.yml")
	// configure flags
	flag.BoolVar(&list, "list", false, "list files waiting in your secureShare box")
	flag.BoolVar(&register, "register", false, "register at secureShare")
	flag.StringVar(&clientConfigFile, "conf", defClientConfigFile, "client configfile to location")
	flag.StringVar(&file, "send", "", "file to send")
	flag.StringVar(&fileID, "receive", "", "fileID to retrieve")
	flag.StringVar(&recipient, "recipient", "", "recipient to send file to, comma separated")
}

func checkFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	flag.Parse()

	if Debug {
		client.Debug = true
	}
	// register
	if register {
		// TODO: fully implement register
		email, password := askpass.Credentials()
		keys, err := minilock.GenerateKey(email, password)
		checkFatal(err)
		pubID, err := keys.EncodeID()
		checkFatal(err)
		c, err := client.New(
			client.SetUsername(email),
			client.SetPassword(password),
			//client.SetAPIToken(token),
		)
		checkFatal(err)
		token, err := c.Register(email, password, pubID)
		checkFatal(err)
		c.APIToken = token
		cy, err := yaml.Marshal(c)
		checkFatal(err)
		clientConfigPath := filepath.Dir(clientConfigFile)
		err = os.MkdirAll(clientConfigPath, 0700)
		checkFatal(err)
		err = ioutil.WriteFile(clientConfigFile, cy, 0700)
		checkFatal(err)
		log.Printf("your configuration has been saved under: '%s'\n", clientConfigFile)
		return
	}

	// load client from config
	var c client.Client
	data, err := ioutil.ReadFile(clientConfigFile)
	checkFatal(err)
	err = yaml.Unmarshal(data, &c)
	checkFatal(err)
	c.SetHttpClient(new(http.Client))
	if Debug {
		fmt.Printf("client: %+v\n", c)
	}
	// list files
	if list {
		fileList, err := c.List()
		checkFatal(err)
		fmt.Printf("%s\n", fileList)
		return
	}

	recipientList := strings.Split(recipient, ",")
	// read file
	if file != "" {
		// encrypt file
		data, err := ioutil.ReadFile(file)
		encryptedContent, err := minilock.EncryptFileContentsWithStrings(file, data, c.Username, c.Password, true, recipientList...)

		checkFatal(err)
		log.Printf("read %d byte from file '%s'\n", len(data), file)
		// upload a file
		fileID, err = c.UploadFile(recipient, encryptedContent)
		checkFatal(err)
		log.Printf("file was uploaded for '%s' with fileID is: '%s'\n", recipient, fileID)

		return
	}

	if fileID != "" {
		filename, data, err := c.DownloadFile(fileID)
		if err != nil {
			checkFatal(err)
		}
		err = ioutil.WriteFile(filename, data, 0700)
		checkFatal(err)
		log.Printf("fileID '%s' written to '%s'\n", fileID, filename)
	}
}
