// secureShare client
package main

import (
	"flag"
	"fmt"
	"github.com/cathalgarvey/go-minilock"
	"github.com/scusi/secureShare/libs/client"
	"io/ioutil"
	"log"
	"strings"
)

var list bool
var register bool
var file string
var fileID string
var recipient string

func init() {
	flag.BoolVar(&list, "list", false, "list files waiting in your secureShare box")
	flag.BoolVar(&register, "register", false, "register at secureShare")
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
	// read and parse config
	// TODO
	// generate a new Client
	c, err := client.New(
		client.SetUsername("flw@posteo.de"),
		client.SetPassword("1q2w3e4r5t"),
		client.SetAPIToken("3f262751d8ebf09fc9a4a2facbb401c80a9589cecb3a231521b3e7ffea402343"),
	)
	checkFatal(err)
	//fmt.Printf("client: %+v\n", c)

	// register
	if register {
		// TODO: fully implement register
		//token := c.Register(username, password, pubID)
		return
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
