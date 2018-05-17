package addressbook

import (
	"fmt"
	"github.com/scusi/secureShare/libs/client/identity"
	"log"
)

type Addressbook struct {
	Owner   identity.Identity // secureShare identity name of the addressbook owner
	URL     string            // secureShareServer url
	Entries []identity.Identity
}

// New returns a new empty addressbook
func New(owner, url string) (a *Addressbook) {
	a = new(Addressbook)
	a.Owner = *identity.New(owner)
	a.URL = url
	return
}

func (a *Addressbook) AddEntry(name, alias string) (err error) {
	if name == "" {
		err = fmt.Errorf("name is empty but required")
		return
	}
	id := identity.New(name)
	if alias != "" {
		id.Alias = alias
	} else {
		id.Alias = name
	}
	a.Entries = append(a.Entries, *id)
	return
}

func (a *Addressbook) DeleteEntry(name string) {
	for i, entry := range a.Entries {
		if entry.Name == name {
			a.Entries = append(a.Entries[:i], a.Entries[i+1:]...)
		}
	}
	return
}

func (a *Addressbook) PubkeyByAlias(alias string) (pubKey string) {
	for _, entry := range a.Entries {
		if entry.Alias == alias {
			return entry.PublicKey
		}
	}
	return
}

func (a *Addressbook) PubkeyByName(name string) (pubKey string) {
	for _, entry := range a.Entries {
		if entry.Name == name {
			return entry.PublicKey
		}
	}
	return
}

func (a *Addressbook) NameByAlias(alias string) (name string) {
	for _, entry := range a.Entries {
		if entry.Alias == alias {
			return entry.Name
		}
	}
	return
}

func (a *Addressbook) AddKey(username, pubKey string) (err error) {
	if username == "" || pubKey == "" {
		return fmt.Errorf("'username' and 'pubKey' are required\n")
	}
	for i, entry := range a.Entries {
		if entry.Name == username {
			a.Entries[i].PublicKey = pubKey
			log.Printf("set pubKey for '%s' to '%s'\n", username, pubKey)
		}
	}
	return
}
