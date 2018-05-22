package common

import (
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

func NewUserID() (encodedUID string, err error) {
	uidData := make([]byte, 128)
	rand.Read(uidData)
	hash, err := blake2s.New(&blake2s.Config{Size: 6, Person: []byte("ssUser.v1")})
	if err != nil {
		return
	}
	_, err = hash.Write(uidData)
	if err != nil {
		return
	}
	//uid := fmt.Sprintf("%x", hash.Sum(nil))
	uid := hash.Sum(nil)
	encodedUID = base58.Encode(uid)
	uidChecksum, err := blake2s.New(&blake2s.Config{Size: 1, Person: []byte("ssUCheck")})
	encodedUID = encodedUID + fmt.Sprintf("%x", uidChecksum)
	return
}

func VerifyUserID(encodedUID string) (ok bool, err error) {
	extractedChecksum := encodedUID[len(encodedUID)-1:]
	checksum, err := blake2s.New(&blake2s.Config{Size: 1, Person: []byte("ssUCheck")})
	checksumA := fmt.Sprintf("%x", checksum)
	if checksumA != extractedChecksum {
		err = fmt.Errorf("Checksum is not correct. '%s' vs. '%s'\n", extractedChecksum, checksumA)
		return false, err
	}
	return true, nil
}
