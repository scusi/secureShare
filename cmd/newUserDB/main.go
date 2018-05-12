package main

import (
	"flag"
	"github.com/cathalgarvey/go-minilock"
	"github.com/scusi/secureShare/libs/user"
	"log"
)

var userDB *user.UserDB
var err error
var userName string
var userPasswd string

func init() {
	flag.StringVar(&userName, "u", "", "username to be used")
	flag.StringVar(&userPasswd, "p", "", "user password")
	//userDB = new(user.UserDB)
	/*
	 */
	userDB, err = user.LoadFromFile("users.yml")
	if err != nil {
		log.Println(err)
		userDB = new(user.UserDB)
	}
	userDB.Path = "users.yml"
}

func main() {
	flag.Parse()
	// generate key
	keys, err := minilock.GenerateKey(userName, userPasswd)
	if err != nil {
		panic(err)
	}
	// log EncodeID
	encodeID, err := keys.EncodeID()
	if err != nil {
		panic(err)
	}
	log.Printf("EncodeID: %s\n", encodeID)
	err = userDB.Add(userName, userPasswd, encodeID)
	if err != nil {
		log.Println(err.Error())
	}
	/*
		log.Printf("userDB (%v):\n%#v\n", &userDB, userDB)
		err = user.SaveToFile(*userDB, "users.yml")
		if err != nil {
			panic(err)
		}
		err = userDB.Save("users.yml")
		if err != nil {
			panic(err)
		}
	*/

	if userDB.Authenticate(userName, userPasswd) {
		log.Printf("AUTHENTICATED!")
		log.Printf("APIToken for %s: %s\n", userName, userDB.APIToken(userName))
	}

}
