package main

import (
	"fmt"
	"github.com/scusi/secureShare/libs/server/common"
	"log"
)

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	userID, err := common.NewUserID()
	check(err)
	log.Printf("userID: %#v\n", userID)
	fmt.Printf("generated UserID: '%s'\n", userID)
	/*
	 */
	ok, err := common.VerifyUserID(userID)
	check(err)
	fmt.Printf("UserID verification: %t\n", ok)
}
