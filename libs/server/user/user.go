package user

import (
	"crypto/rand"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
)

var Debug bool

type User struct {
	Name      string // username choosen by the user
	APIToken  string // server issued token to authenticate to the secureShare API
	PublicKey string // minilock EncodeID of the user
}

type UserDB struct {
	Path  string
	Users []User
}

/* From within your program you do this:

```
import "github.com/scusi/secureShare/libs/server/user"

var userDB []user.User

func init() {
	userDB = user.LoadFromFile("/path/to/user.yml")
}

func main() {
	if userDB.Lookup("DummyUser") {
		log.Printf("user '%s' does exist.\n", "DummyUser")
	}
	...

	if userDB.Authenticate("DummyUser", "SecretPassword") {
		log.Printf("user '%s' authenticated correctly.\n", "DummyUser")
	}
}
```
*/

/* LoadFromFile - loads a user database from a yaml file */
func LoadFromFile(path string) (udb *UserDB, err error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	var ul = &UserDB{}
	ul.Path = path
	// decode yml
	err = yaml.Unmarshal(data, &ul)
	if err != nil {
		return
	}

	// return
	return ul, nil
}

/* SaveToFile - saves a given user database to a given file */
func SaveToFile(udb UserDB, path string) (err error) {
	ydata, err := yaml.Marshal(udb.Users)
	if err != nil {
		return
	}
	udb.Path = path
	err = ioutil.WriteFile(path, ydata, 0700)
	if err != nil {
		return
	}
	log.Printf("SaveToFile: saved to: %s\n", path)
	return
}

func (udb *UserDB) Save(path string) (err error) {
	if path != "" {
		udb.Path = path
	}
	ydata, err := yaml.Marshal(udb)
	if err != nil {
		return
	}
	if path != "" {
		err = ioutil.WriteFile(path, ydata, 0700)
		log.Printf("saved to: %s\n", path)
	} else {
		err = ioutil.WriteFile(udb.Path, ydata, 0700)
		log.Printf("saved to: %s\n", udb.Path)
	}
	return
}

func (udb *UserDB) Add(username, publicKey string) (err error) {
	if Debug {
		log.Printf("userDB.Add: username: '%s'", username)
	}
	doesExist := udb.Lookup(username)
	if doesExist {
		err = fmt.Errorf("invalid username, please choose another one.")
		return
	}
	u := new(User)
	u.Name = username
	// TODO: check if the publicKey is syntactitcal correct
	u.PublicKey = publicKey
	u.APIToken = newAPIToken()
	udb.Users = append(udb.Users, *u)
	udb.Save("")
	if Debug {
		log.Printf("udb: %#v\n", udb)
	}
	return
}

func (udb *UserDB) Delete(username string) (err error) {
	var found bool
	nudb := UserDB{}
	nudb = *udb
	for i, u := range nudb.Users {
		if u.Name == username {
			found = true
			udb.Users = append(nudb.Users[:i], nudb.Users[i+1:]...)
			//udb = &nudb
			return
		}
	}
	if found != true {
		err = fmt.Errorf("user was not found")
	}
	udb.Save("")
	return
}

func (udb *UserDB) Lookup(username string) (ok bool) {
	for _, u := range udb.Users {
		if u.Name == username {
			return true
		}
	}
	return false
}

func (udb *UserDB) LookupNameByPubkey(pubkey string) (name string) {
	for _, u := range udb.Users {
		if u.PublicKey == pubkey {
			return u.Name
		}
	}
	return ""
}

func (udb *UserDB) PublicKey(username string) (publicKey string) {
	for _, u := range udb.Users {
		if u.Name == username {
			return u.PublicKey
		}
	}
	return
}

func (udb *UserDB) APIAuthenticate(username, APIToken string) (ok bool) {
	for _, u := range udb.Users {
		if u.Name == username {
			APIToken = u.APIToken
			return true
		}
	}
	return false
}

// newAPIToken - generates a new random token for API usage
func newAPIToken() (token string) {
	t := make([]byte, 32)
	rand.Read(t)
	return fmt.Sprintf("%x", t)
}

// NewAPIToken will set a a new random API token for a given username
func (udb *UserDB) NewAPIToken(username string) (APIToken string) {
	APIToken = newAPIToken()
	for _, u := range udb.Users {
		if u.Name == username {
			u.APIToken = APIToken
		}
	}
	udb.Save("")
	return
}

// APIToken shows the APIToken for the given user
func (udb *UserDB) APIToken(username string) (APIToken string) {
	for _, u := range udb.Users {
		if u.Name == username {
			return u.APIToken
		}
	}
	return ""
}
