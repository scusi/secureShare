package identity

import ()

var Debug bool
var URL string

type Identity struct {
	Alias     string // lokal alias for this identity
	Name      string // identity Name on the secureShare server
	PublicKey string // minilock encodeID
	Avatar    []byte // avatar picture of the user
}

func New(name string) (id *Identity) {
	id = new(Identity)
	id.Name = name
	return
}
