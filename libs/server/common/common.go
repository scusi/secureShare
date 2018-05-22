package common

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/dchest/blake2b"
	"github.com/dchest/blake2s"
	"github.com/decred/base58"
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

// NewUserID - generates a new (random) userID, which is integrity protected
// by a 1 byte blake2s checksum
func NewUserID() (encodedUID string, err error) {
	// generate 128 byte of random data
	uidData := make([]byte, 128)
	rand.Read(uidData)
	uid, err := shortChecksum(uidData, 6)
	if err != nil {
		return
	}
	cs, err := shortChecksum(uid, 1)
	if err != nil {
		return
	}
	uid = append(uid, cs[0])
	encodedUID = base58.Encode(uid)
	return
}

// VerifyUserID - checks if a userID is syntactical valid
func VerifyUserID(encodedUID string) (ok bool, err error) {
	// extract the userID checksum from the UID string
	decodedUID := base58.Decode(encodedUID)
	uid := decodedUID[:6]
	cs := decodedUID[6:]
	myCs, err := shortChecksum(uid, 1)
	if bytes.Equal(myCs, cs) {
		return true, nil
	} else {
		err = fmt.Errorf("Checksum check failed")
		return
	}
}

// shortChecksum - generates a short blake2s checksum
func shortChecksum(data []byte, size uint8) (cs []byte, err error) {
	checksum, err := blake2s.New(&blake2s.Config{Size: size, Person: []byte("ssUCheck")})
	if err != nil {
		return
	}
	_, err = checksum.Write(data)
	if err != nil {
		return
	}
	cs = checksum.Sum(nil)
	return

}
