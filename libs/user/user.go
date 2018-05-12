package user

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
)

type UserDB struct {
	Path  string
	Users []User
}

/* From within your program you do this:

```
import "github.com/scusi/secureShare/libs/user"

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

type User struct {
	Name     string
	Password string
	APIToken string
	PubID    string
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

func (udb *UserDB) Add(username, password, PubID string) (err error) {
	doesExist := udb.Lookup(username)
	if doesExist {
		err = fmt.Errorf("invalid username, please choose another one.")
		return
	}
	u := new(User)
	u.Name = username
	passwdbyt, err := bcrypt.GenerateFromPassword([]byte(password), 0)
	if err != nil {
		return
	}
	u.Password = string(passwdbyt)
	u.PubID = PubID
	u.APIToken = newAPIToken()
	udb.Users = append(udb.Users, *u)
	//nudb.Path = udb.Path
	udb.Save("")
	log.Printf("nudb: %#v\n", udb)
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

// Authenticate will autenticate a given user with a given password.
// returns true if the password was correct, otherwise false
func (udb *UserDB) Authenticate(username, password string) (ok bool) {
	var storedHash string
	for _, u := range udb.Users {
		if u.Name == username {
			storedHash = u.Password
		}
	}
	if storedHash == "" {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	if err == nil {
		return true
	}
	return false
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

// SetPassword - will set a given password for a given user
func (udb *UserDB) SetPassword(username, password string) (err error) {
	udb.Save("")
	return
}

// ChangePassword - will set a new given password for a given username if the current password given was correct
func (udb *UserDB) ChangePassword(username, oldPasswd, newPasswd string) (ok bool, err error) {
	udb.Save("")
	return
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
