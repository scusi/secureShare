// this program shows how one can create a scrypt salted hash
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"log"
)

var Debug bool
var saltA string
var salt []byte
var encodeIDA string
var encodeID []byte
var err error

func init() {
	flag.BoolVar(&Debug, "debug", false, "enables debug output when set to 'true'")
	flag.StringVar(&saltA, "salt", "", "salt to be used")
	flag.StringVar(&encodeIDA, "encodeID", "", "encodeID to be used")
}

func main() {
	flag.Parse()
	if saltA == "" {
		salt = make([]byte, 16)
		rand.Read(salt)
	} else {
		salt, err = hex.DecodeString(saltA)
		if err != nil {
			panic(err)
		}
	}
	if Debug {
		fmt.Printf("salt: %x\n", salt)
	}

	if encodeIDA == "" {
		encodeID = []byte("HZfb8HL4tL7bGJBZq2ha1oyQkf3ePTsLCBBqKog8ESz4y")
	}

	dk, err := scrypt.Key(encodeID, salt, 1<<15, 8, 1, 32)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(base64.URLEncoding.EncodeToString(dk))
}
