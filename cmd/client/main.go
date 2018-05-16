// secureShare client
package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/cathalgarvey/go-minilock"
	"github.com/cathalgarvey/go-minilock/taber"
	"github.com/scusi/secureShare/libs/askpass"
	"github.com/scusi/secureShare/libs/client"
	"github.com/scusi/secureShare/libs/client/addressBook"
	//"github.com/scusi/secureShare/libs/client/identity"
	"golang.org/x/crypto/scrypt"
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
var usr *user.User
var err error

func init() {
	flag.BoolVar(&Debug, "debug", false, "enables debug output when 'true'")
	// get user home dir
	usr, err = user.Current()
	checkFatal(err)
	defClientConfigFile = filepath.Join(
		usr.HomeDir, ".config",
		"secureshare", "client", "config.yml")
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
		// ask user for minilock credentials
		email, password := askpass.Credentials()
		keys, err := minilock.GenerateKey(email, password)
		checkFatal(err)
		pubID, err := keys.EncodeID()
		checkFatal(err)
		// scrypt pubID to get username for server
		salt := make([]byte, 16)
		rand.Read(salt)
		dk, err := scrypt.Key([]byte(pubID), salt, 1<<15, 8, 1, 32)
		if err != nil {
			log.Fatal(err)
		}
		username := base64.URLEncoding.EncodeToString(dk)
		c, err := client.New(
			client.SetUsername(username),
			client.SetKeys(keys),
			//client.SetAPIToken(token),
		)
		checkFatal(err)
		// WIP - change register function
		// TODO: what do we do against exhausting attacks and similar
		//       somehow we need to make it ...
		token, err := c.Register(username, pubID)
		checkFatal(err)
		c.APIToken = token

		c.PublicKey = pubID
		cy, err := yaml.Marshal(c)
		checkFatal(err)
		// make sure that the path exists
		clientConfigFile = filepath.Join(
			usr.HomeDir, ".config",
			"secureshare", "client", username, "config.yml")
		clientConfigPath := filepath.Dir(clientConfigFile)
		err = os.MkdirAll(clientConfigPath, 0700)
		checkFatal(err)
		// write actual config file to disk
		err = ioutil.WriteFile(clientConfigFile, cy, 0700)
		checkFatal(err)
		log.Printf("your configuration has been saved under: '%s'\n", clientConfigFile)
		a := addressbook.New(username)
		ay, err := yaml.Marshal(a)
		checkFatal(err)
		addressbookPath := filepath.Join(usr.HomeDir, ".config", "secureshare", "client", username)
		err = os.MkdirAll(addressbookPath, 0700)
		checkFatal(err)
		addressbookPath = filepath.Join(addressbookPath, "addressbook.yml")
		err = ioutil.WriteFile(addressbookPath, ay, 0700)
		checkFatal(err)
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

	// read file
	if file != "" {
		// prepare recipient keys
		var recipientKeys []*taber.Keys
		recipientList := strings.Split(recipient, ",")
		for _, recipient := range recipientList {
			keys, err := taber.FromID(recipient)
			if err != nil {
				log.Printf("Error generating recipient key for '%s'\n", recipient)
				continue
			}
			recipientKeys = append(recipientKeys, keys)
		}
		// encrypt file
		data, err := ioutil.ReadFile(file)
		encryptedContent, err := minilock.EncryptFileContents(file, data, c.Keys, recipientKeys...)

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
