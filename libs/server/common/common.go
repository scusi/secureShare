package common

import (
	"fmt"
	"github.com/dchest/blake2b"
	"github.com/dchest/blake2s"
)

// LongID - genertes a blake2b 32 byte checksum over given data.
func LongID(data []byte) (id string) {
	b := blake2b.New256()
	b.Write(data)
	bsum := b.Sum(nil)
	return fmt.Sprintf("%x", bsum)
}

// generate a short file ID based on blake2s
func ShortID(data []byte) (c string, err error) {
	hash, err := blake2s.New(&blake2s.Config{Size: 4, Person: []byte("scusi.v1")})
	if err != nil {
		return
	}
	_, err = hash.Write(data)
	if err != nil {
		return
	}
	c = fmt.Sprintf("%x", hash.Sum(nil))
	return
}
