package agent

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"fmt"
	"github.com/cathalgarvey/go-minilock/taber"
)

type Agent interface {
	List() []*Key
	Add(key Key) error
	Remove(key Key) error
	RemoveAll()
	Lock(passphrase string) error
	Unlock(passphrase string) error
}

type Key struct {
	ID    string
	Email string
	taber.Keys
	Comment string
}

func (key Key) MarshalPrivate() []byte {
	var outBuf bytes.Buffer
	w := bufio.NewWriter(&outBuf)
	encodeID, _ := key.Keys.EncodeID()
	block := &pem.Block{
		Type: "MINILOCK PRIVATE KEY",
		Headers: map[string]string{
			"ID":      encodeID,
			"Comment": key.Comment,
			"Email":   key.Email,
		},
		Bytes: key.Private,
	}
	pem.Encode(w, block)
	w.Flush()
	return outBuf.Bytes()
}

func (key Key) MarshalPublic() []byte {
	var outBuf bytes.Buffer
	w := bufio.NewWriter(&outBuf)
	encodeID, _ := key.Keys.EncodeID()
	block := &pem.Block{
		Type: "MINILOCK PUBLIC KEY",
		Headers: map[string]string{
			"ID":      encodeID,
			"Comment": key.Comment,
			"Email":   key.Email,
		},
		Bytes: key.Public,
	}
	pem.Encode(w, block)
	w.Flush()
	return outBuf.Bytes()
}

//type keyring map[string]Key
type keyring struct {
	keys       map[string]Key
	locked     bool
	passphrase string
}

func (k *keyring) List() (keys []*Key) {
	keyringKeys := k.keys
	for _, key := range keyringKeys {
		keys = append(keys, &key)
	}
	return
}

func (k *keyring) Add(key Key) (err error) {
	tk := k.keys
	if _, ok := tk[key.Email]; ok {
		err = fmt.Errorf("key already exists")
		return
	}
	tk[key.Email] = key
	k.keys = tk
	return
}

func (k *keyring) Remove(key Key) (err error) {
	tk := k.keys
	delete(tk, key.Email)
	k.keys = tk
	return
}

func (k *keyring) RemoveAll() {
	k.keys = make(map[string]Key)
	return
}

func (k *keyring) Lock(passphrase string) (err error) {
	k.passphrase = passphrase
	k.locked = true
	return
}

func (k *keyring) Unlock(passphrase string) (err error) {
	if passphrase != k.passphrase {
		err = fmt.Errorf("unlocking failed")
		return
	}
	k.locked = false
	return
}

func NewKeyring() Agent {
	k := new(keyring)
	k.keys = make(map[string]Key)
	return k
}
