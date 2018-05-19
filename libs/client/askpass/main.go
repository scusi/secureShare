// Following is one of best way to get it done. First get terminal package by go get golang.org/x/crypto/ssh
//
//package main
package askpass

import (
	"bufio"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"regexp"
	"strings"
	"syscall"
)

// in your Programm use it like this:
/*

import("github.com/scusi/minilockShare/libs/askpass")

func main() {
    username, password := askpass.Credentials()
    fmt.Printf("Username: %s, Password: %s\n", username, password)
}

*/

// Crendetials will ask the user for Email and password and returning it.
// NOTE: Credentials trims spaces from username (Email) and password
func Credentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Emailaddress: ")
	username, _ := reader.ReadString('\n')

	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err == nil {
		//fmt.Println("\nPassword typed: " + string(bytePassword))
	}
	fmt.Println("")
	password := string(bytePassword)
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	return username, password
}

// ValidateEmail will validate an email address for syntactical correctness,
// returns a boolen indicator if the given email is correct (true) or not (false).
func ValidateEmail(email string) bool {
	// BUG: In times of generic top level domains gTLD the follwoing regex does not work.
	//      A regex based approach is difficult to maintain while more and more generic TLDs will come.
	Re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return Re.MatchString(email)
}
