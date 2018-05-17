package addressbook

import (
	"fmt"
	"github.com/scusi/secureShare/libs/client/identity"
)

type Addressbook struct {
	Owner   identity.Identity // secureShare identity name of the addressbook owner
	Entries []identity.Identity
}

// New returns a new empty addressbook
func New(owner string) (a *Addressbook) {
	a = new(Addressbook)
	a.Owner = *identity.New(owner)
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
