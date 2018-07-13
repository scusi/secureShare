// identum - an secureShare Key and Identity Agent
package identum

import (
	//"github.com/cathalgarvey/go-minilock"
	"github.com/cathalgarvey/go-minilock/taber"
)

type Identum struct {
	Email string
	keys  taber.Keys
}

func New(email, password string) (i *Identum, err error) {
	i = new(Identum)
	i.Email = email
	keys, err := taber.FromEmailAndPassphrase(email, password)
	if err != nil {
		return
	}
	i.keys = *keys
	return
}

func (i *Identum) PublicKey() (encodeID string, err error) {
	encodeID, err = i.keys.EncodeID()
	if err != nil {
		return
	}
	return
}
