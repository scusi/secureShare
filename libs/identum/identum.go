// key - identum key
package key

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"github.com/cathalgarvey/go-minilock"
	"github.com/cathalgarvey/go-minilock/taber"
)

// Key
type Key struct {
	Email   string
	keys    taber.Keys
	Comment string
}

// NewPrivate creates a new private key
func NewPrivate(email, password string) (i *Key, err error) {
	i = new(Key)
	i.Email = email
	keys, err := taber.FromEmailAndPassphrase(email, password)
	if err != nil {
		return
	}
	i.keys = *keys
	return
}

// NewPublic creates a new public key
func NewPublic(email, encodeID string) (i *Key, err error) {
	i = new(Key)
	i.Email = email
	keypair, err := minilock.ImportID(encodeID)
	if err != nil {
		return
	}
	i.keys = *keypair
	return
}

func (i *Key) EncodeID() (encodeID string, err error) {
	encodeID, err = i.keys.EncodeID()
	if err != nil {
		return
	}
	return
}

func (i *Key) HasPrivate() bool {
	return i.keys.HasPrivate()
}

func (i *Key) Wipe() (err error) {
	err = i.keys.Wipe()
	return
}

// PublicOnly() returns a key that only contains the public part
func (i *Key) PublicOnly() (k *Key) {
	pubKey := i.keys.PublicOnly()
	k.keys = *pubKey
	k.Email = i.Email
	return
}

func (i *Key) SetComment(comment string) {
	i.Comment = comment
}

func (i *Key) ExportPublic() (publicBytes []byte, err error) {
	// TODO: export as PEM encoded key
	var outBuf bytes.Buffer
	w := bufio.NewWriter(&outBuf)
	encodeID, _ := i.keys.EncodeID()
	headers := make(map[string]string)
	headers["Email"] = i.Email
	headers["ID"] = encodeID
	if i.Comment != "" {
		headers["Comment"] = i.Comment
	}
	block := &pem.Block{
		Type:    "MINILOCK PUBLIC KEY",
		Headers: headers,
		Bytes:   i.keys.Public,
	}
	err = pem.Encode(w, block)
	if err != nil {
		return
	}
	err = w.Flush()
	if err != nil {
		return
	}
	return outBuf.Bytes(), nil
}
