package main

import (
	"io"
	"log"
	"net"
	"time"

	"github.com/scusi/secureShare/libs/identum/message"
)

func reader(r io.Reader) {
	buf := make([]byte, 1024)
	for {
		n, err := r.Read(buf[:])
		if err != nil {
			return
		}
		println("Client got:", string(buf[0:n]))
	}
}

func main() {
	m := message.New(message.Lock, "foobar")
	mBytes, err := message.Marshal(m)

	c, err := net.Dial("unix", "/tmp/identum.sock")
	if err != nil {
		panic(err)
	}
	defer c.Close()

	go reader(c)
	for {
		_, err := c.Write(mBytes)
		if err != nil {
			log.Fatal("write error:", err)
			break
		}
		time.Sleep(1e9)
	}
}
