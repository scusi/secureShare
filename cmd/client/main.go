// secureShare client
package main

import (
	"crypto/rand"
<<<<<<< HEAD
=======
	"crypto/tls"
>>>>>>> public
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/cathalgarvey/go-minilock"
	"github.com/cathalgarvey/go-minilock/taber"
	"github.com/scusi/secureShare/libs/askpass"
	"github.com/scusi/secureShare/libs/client"
	"github.com/scusi/secureShare/libs/client/addressBook"
<<<<<<< HEAD
	//"github.com/scusi/secureShare/libs/client/identity"
=======
>>>>>>> public
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

<<<<<<< HEAD
=======
var skipVerify bool
>>>>>>> public
var Debug bool
var list bool
var register bool
var file string
var fileID string
var recipient string
var usr *user.User
var err error
<<<<<<< HEAD

func init() {
	flag.BoolVar(&Debug, "debug", false, "enables debug output when 'true'")
=======
var URL string
var addContact string
var alias string

func init() {
	flag.BoolVar(&Debug, "debug", false, "enables debug output when 'true'")
	flag.BoolVar(&skipVerify, "InsecureSkipVerify", false, "turn off TLS certificate checks - INSECURE")
>>>>>>> public
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
<<<<<<< HEAD
=======
	flag.StringVar(&URL, "url", "http://127.0.0.1:9999/", "url of the secureShare server to use")
	flag.StringVar(&addContact, "addContact", "", "add a secureShare user to your contacts")
	flag.StringVar(&alias, "alias", "", "alias to use for addContact")
>>>>>>> public
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
<<<<<<< HEAD
			//client.SetAPIToken(token),
		)
		checkFatal(err)
		// WIP - change register function
=======
			client.SetURL(URL),
			//client.SetAPIToken(token),
		)
		checkFatal(err)
		if skipVerify {
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			insecureSkipVerify := &http.Client{Transport: tr}
			c.SetHttpClient(insecureSkipVerify)
		}
>>>>>>> public
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
<<<<<<< HEAD
		a := addressbook.New(username)
		ay, err := yaml.Marshal(a)
		checkFatal(err)
=======

		// create a new addressbook for the user
		a := addressbook.New(username, c.URL)
		// set owner Information
		a.Owner.PublicKey = c.PublicKey
		a.Owner.Alias = email
		a.URL = c.URL
		// marshal addressbook
		ay, err := yaml.Marshal(a)
		checkFatal(err)
		// prepare to write to file
>>>>>>> public
		addressbookPath := filepath.Join(usr.HomeDir, ".config", "secureshare", "client", username)
		err = os.MkdirAll(addressbookPath, 0700)
		checkFatal(err)
		addressbookPath = filepath.Join(addressbookPath, "addressbook.yml")
<<<<<<< HEAD
=======
		// write to file on disk
>>>>>>> public
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
<<<<<<< HEAD
	c.SetHttpClient(new(http.Client))
	if Debug {
		fmt.Printf("client: %+v\n", c)
	}
=======
	// skip certificate checks is skipVerify is set true
	if skipVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		insecureSkipVerify := &http.Client{Transport: tr}
		c.SetHttpClient(insecureSkipVerify)
	} else {
		c.SetHttpClient(new(http.Client))
	}

	if Debug {
		log.Printf("client: %+v\n", c)
	}

	// load addressbook
	var a *addressbook.Addressbook
	addressbookPath := filepath.Join(usr.HomeDir, ".config", "secureshare", "client", c.Username)
	addressbookPath = filepath.Join(addressbookPath, "addressbook.yml")
	adata, err := ioutil.ReadFile(addressbookPath)
	checkFatal(err)
	err = yaml.Unmarshal(adata, &a)
	checkFatal(err)

	// add contact
	if addContact != "" {
		// add contact
		a.AddEntry(addContact, alias)
		pubKey, err := c.UpdateKey(addContact)
		checkFatal(err)
		log.Printf("updatedPubKey: %s\n", pubKey)
		a.AddKey(addContact, pubKey)
		// save addressbook
		adata, err = yaml.Marshal(&a)
		checkFatal(err)
		log.Printf("addrbook to save: %s\n", adata)
		err = ioutil.WriteFile(addressbookPath, adata, 0700)
		checkFatal(err)
		log.Printf("contact '%s' added\n", addContact)
		return
	}

>>>>>>> public
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
<<<<<<< HEAD
		var recipientKeys []*taber.Keys
		recipientList := strings.Split(recipient, ",")
		for _, recipient := range recipientList {
			keys, err := taber.FromID(recipient)
=======
		// TODO: this part needs to change when the addressbook is used
		// recipients are then aliases from the addressbook.
		// for each alias the publicKey needs to be looked up
		var recipientKeys []*taber.Keys // holds the keys of the recipients
		var recipientIDs []string       // holds the recipient alias list
		var recipientNames []string
		recipientList := strings.Split(recipient, ",")
		for _, recipient := range recipientList {
			// add recipient name to recipientNames
			name := a.NameByAlias(recipient)
			log.Printf("alias '%s' resolved to name: '%s'\n", recipient, name)
			recipientNames = append(recipientNames, name)
			// add recipient encodeID to recipientIDs
			pubKey := a.PubkeyByAlias(recipient)
			if pubKey == "" {
				pubKey, err = c.UpdateKey(name)
				log.Println(err)
			}
			if pubKey == "" {
				err = fmt.Errorf("ERROR: public key for alias '%s' could not be found!\n", recipient)
				log.Println(err)
				continue

			}
			log.Printf("alias '%s' resolved to pubKey: '%s'\n", recipient, pubKey)
			recipientIDs = append(recipientIDs, pubKey)

			// add recipient key to recipientKeys
			keys, err := taber.FromID(pubKey)
>>>>>>> public
			if err != nil {
				log.Printf("Error generating recipient key for '%s'\n", recipient)
				continue
			}
			recipientKeys = append(recipientKeys, keys)
<<<<<<< HEAD
=======

		}
		// check if recipientKeys at least contain one value
		if len(recipientKeys) <= 0 {
			err = fmt.Errorf("ERORR: no recipient keys could be found, aborting\n")
			checkFatal(err)
>>>>>>> public
		}
		// encrypt file
		data, err := ioutil.ReadFile(file)
		encryptedContent, err := minilock.EncryptFileContents(file, data, c.Keys, recipientKeys...)

		checkFatal(err)
		log.Printf("read %d byte from file '%s'\n", len(data), file)
		// upload a file
<<<<<<< HEAD
		fileID, err = c.UploadFile(recipient, encryptedContent)
		checkFatal(err)
		log.Printf("file was uploaded for '%s' with fileID is: '%s'\n", recipient, fileID)

=======
		recipientNamesString := strings.Join(recipientNames, ",")
		recipientNamesString = strings.TrimSuffix(recipientNamesString, ",")
		if Debug {
			client.Debug = true
		}
		fileID, err = c.UploadFile(recipientNamesString, encryptedContent)
		checkFatal(err)
		log.Printf("file was uploaded for user '%s' with fileID: '%s'\n", recipient, fileID)
>>>>>>> public
		return
	}

	if fileID != "" {
		filename, data, err := c.DownloadFile(fileID)
		if err != nil {
			checkFatal(err)
		}
<<<<<<< HEAD
=======
		// make sure filename contains no path
		filename = filepath.Base(filename)
>>>>>>> public
		err = ioutil.WriteFile(filename, data, 0700)
		checkFatal(err)
		log.Printf("fileID '%s' written to '%s'\n", fileID, filename)
	}
}
