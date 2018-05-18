package identity

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
<<<<<<< HEAD
)

=======
	"strings"
)

var Debug bool
var URL string

>>>>>>> public
type Identity struct {
	Alias     string // lokal alias for this identity
	Name      string // identity Name on the secureShare server
	PublicKey string // minilock encodeID
	Avatar    []byte // avatar picture of the user
}

func New(name string) (id *Identity) {
	id = new(Identity)
	id.Name = name
<<<<<<< HEAD
	id.UpdateKey()
	return
}

func (id *Identity) UpdateKey() (err error) {
	v := url.Values{}
	v.Set("username", id.Name)
	resp, err := http.Get("http://127.0.0.1:9999/lookupKey?" + v.Encode())
=======
	return
}

func (id *Identity) UpdateKey(baseURL string) (err error) {
	if strings.HasSuffix(baseURL, "/") == false {
		baseURL = baseURL + "/"
	}
	v := url.Values{}
	v.Set("username", id.Name)
	url := baseURL + "lookupKey?" + v.Encode()
	resp, err := http.Get(url)
>>>>>>> public
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("StatusCode is '%d', something went wrong\n", resp.StatusCode)
		return
	}
	publicKey, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if publicKey == nil {
		err = fmt.Errorf("no public available")
		return
	}
	id.PublicKey = string(publicKey)
	return
}
