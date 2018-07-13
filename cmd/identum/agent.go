package main

import (
	"fmt"
	"github.com/cathalgarvey/go-minilock/taber"
	"github.com/scusi/secureShare/libs/identum"
	"github.com/scusi/secureShare/libs/identum/agent"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var signals = make(chan os.Signal, 1)
var done = make(chan bool, 1)
var identities = make(map[string]identum.Identum)

func init() {
	// Setup Teardown
	// signal notification (teardown)
	// notify on SIGTERM and SIGINT
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	// setup go routine to recieve signals, log them and set done channel
	go func() {
		sig := <-signals
		log.Printf("recieved signal '%s'\n", sig)
		done <- true
	}()
	// go routine to check done channel
	// when done channel is set to true we call Teardown() and Exit()
	go func() {
		<-done
		log.Printf("we are done!\n")
		Teardown()
		Exit()
	}()
	// So, servers should unlink the socket pathname prior to binding it.
	// https://troydhanson.github.io/network/Unix_domain_sockets.html
	syscall.Unlink("/tmp/identum.sock")
}

func Teardown() {
	syscall.Unlink("/tmp/identum.sock")
	return
}

func Exit() {
	os.Exit(0)
	return
}

func checkFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	// generate a new minilock keypair
	keys, err := taber.FromEmailAndPassphrase("flw@posteo.de", "1q2w3e4r5t")
	checkFatal(err)
	encodeID, _ := keys.EncodeID()
	// create an identum Key based on the minilock keypair
	myKey := &agent.Key{encodeID, "flw@posteo.de", *keys, "test key for development"}
	fmt.Printf("%s\n", string(myKey.MarshalPublic()))
	fmt.Printf("%s\n", string(myKey.MarshalPrivate()))
	// create a new Keyring to hold keys in memory
	a := agent.NewKeyring()
	// add the identum key to the keyring
	err = a.Add(*myKey)
	checkFatal(err)
	// list the keys from the keyring
	keyList := a.List()
	for i, k := range keyList {
		fmt.Printf("[%02d] %+v\n", i, k)
	}

	// start listen on a unix domain socket
	l, err := net.Listen("unix", "/tmp/identum.sock")
	if err != nil {
		log.Fatal("listen error:", err)
	}

	// run infinite
	for {
		fd, err := l.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
		}

		go echoServer(fd)
	}

}

func echoServer(c net.Conn) {
	for {
		buf := make([]byte, 512)
		nr, err := c.Read(buf)
		if err != nil {
			return
		}

		data := buf[0:nr]
		println("Server got:", string(data))
		_, err = c.Write(data)
		if err != nil {
			log.Fatal("Write: ", err)
		}
	}
}
