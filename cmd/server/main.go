package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"github.com/dchest/blake2b"
	"github.com/dchest/blake2s"
	"github.com/gorilla/mux"
	"github.com/peterbourgon/diskv"
	"github.com/scusi/secureShare/libs/server/user"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"strings"
)

var userDB *user.UserDB

var Debug bool
var configFile string
var listenAddr string
var store *diskv.Diskv

type Config struct {
	ListenAddr string
	CertFile   string
	KeyFile    string
	DataDir    string
	UsersFile  string
}

func init() {
	flag.BoolVar(&Debug, "debug", true, "enables debug output, when 'true'")
	flag.StringVar(&configFile, "conf", "", "config file to use (yaml)")
	flag.StringVar(&listenAddr, "l", "127.0.0.1:9999", "address to listen on, default is: 127.0.0.1:9999")
}

func AdvancedTransformExample(key string) *diskv.PathKey {
	//log.Printf("Atransform: key: %s\n", key)
	path := strings.Split(key, "/")
	last := len(path) - 1
	//log.Printf("path: '%s', last: '%d\n", path, last)
	return &diskv.PathKey{
		Path:     path[:last],
		FileName: path[last],
	}

}

// If you provide an AdvancedTransform, you must also provide its
// inverse:

func InverseTransformExample(pathKey *diskv.PathKey) (key string) {
	//log.Printf("revTransform: pathKey: %+v\n", pathKey)
	key = strings.Join(pathKey.Path, "/") + "/" + pathKey.FileName
	//log.Printf("revTransform: key: %s\n", key)
	return key

}

func main() {
	flag.Parse()
	// read config
	cdata, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}
	cfg := new(Config)
	yaml.Unmarshal(cdata, cfg)
	userDB, err = user.LoadFromFile(cfg.UsersFile)
	if err != nil {
		log.Fatal(err)
	}
	// init file storage
	store = diskv.New(diskv.Options{
		BasePath:          cfg.DataDir,
		AdvancedTransform: AdvancedTransformExample,
		InverseTransform:  InverseTransformExample,
	})

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/{UserID}/{FileID}", Download)
	router.HandleFunc("/upload/", Upload)
	router.HandleFunc("/list/", List)
	router.HandleFunc("/register/", Register)
	router.HandleFunc("/lookupKey", LookupKey)

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		log.Printf("listenAddr: %s (TLS)\n", cfg.ListenAddr)
		log.Fatal(http.ListenAndServeTLS(cfg.ListenAddr, cfg.CertFile, cfg.KeyFile, router))
	} else {
		log.Printf("listenAddr: %s\n", cfg.ListenAddr)
		log.Fatal(http.ListenAndServe(cfg.ListenAddr, router))
	}
}

func Register(w http.ResponseWriter, r *http.Request) {
	log.Printf("Register -->")
	username := r.FormValue("username")
	pubID := r.FormValue("pubID")
	if Debug {
		log.Printf("username: '%s', pubID: '%s'", username, pubID)
	}
	// TODO: check if pubID is a syntactical valid minilock ID

	if userDB.Lookup(username) {
		http.Error(w, "User already existing", 500)
		return
	}
	log.Printf("going to add new user '%s' with pubID '%s'\n", username, pubID)
	err := userDB.Add(username, pubID)
	if err != nil {
		http.Error(w, "adding user failed", 500)
		return
	}
	token := userDB.APIToken(username)
	fmt.Fprintf(w, "%s", token)
	return
}

func LookupKey(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "'username' not supplied", 400)
	}
	publicKey := userDB.PublicKey(username)
	fmt.Fprintf(w, "%s", publicKey)
}

// GenBlake2b32 - genertes a blake2b 32 byte checksum over given data.
// aka long ID
func GenBlake2b32(data []byte) (c string) {
	b := blake2b.New256()
	b.Write(data)
	bsum := b.Sum(nil)
	return fmt.Sprintf("%x", bsum)
}

// generate a short file ID based on blake2s
func GenBlake2s(data []byte) (c string, err error) {
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

func List(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("Apiusername")
	token := r.Header.Get("Apikey")
	if userDB.APIAuthenticate(username, token) != true {
		http.Error(w, "Unauthorized", 401)
		return
	}
	keyChan := store.KeysPrefix(username, nil)
	for k := range keyChan {
		//TODO: get the file time and display it
		k = strings.TrimPrefix(k, username+"/")
		fmt.Fprintf(w, "'%s'\n", k)
	}
}

func Upload(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		log.Printf("Method: POST\n")
		if Debug {
			dump, errDump := httputil.DumpRequest(r, true)
			if errDump != nil {
				log.Printf("ERROR: COULD NOT DUMP REQUEST!")
			} else {
				log.Printf("Request:\n%s\n", dump)
			}
		}
		// TODO: authenticate user

		var inBuf bytes.Buffer
		inWrt := bufio.NewWriter(&inBuf)
		//var o object.Object
		// extract file from request
		//get the multipart reader for the request.
		reader, err := r.MultipartReader()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		//copy each part to destination.
		var recList bytes.Buffer
		recListWriter := bufio.NewWriter(&recList)
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if part.FormName() == "recipientList" {
				log.Printf("recipientList from part: %+v", part)
				n, err := io.Copy(recListWriter, part)
				if err != nil {
					log.Printf("io.Copy error recipientList: %s\n", err.Error())
					return
				}
				log.Printf("Copied %d byte from recList\n", n)
			}
			//if part.FileName() is empty, skip this iteration.
			if part.FileName() == "" {
				continue
			}
			log.Printf("part.FileName = '%s'\n", part.FileName())
			n := int64(0)
			if n, err = io.Copy(inWrt, part); err != nil {
				log.Printf("Error copy file part: %s\n", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			log.Printf("copied %d byte to mime part\n", n)
			// genFileID
			//fileID := GenBlake2b32(inBuf.Bytes())
			fileID, err := GenBlake2s(inBuf.Bytes())
			if err != nil {
				log.Printf("error generating checksum blake2s: %s\n", err.Error())
				//http.Error(w, err.Error(), 500)
				fileID = GenBlake2b32(inBuf.Bytes())
			}

			// store file
			log.Printf("recList: %s\n", string(recList.Bytes()))
			recipientList := strings.Split(string(recList.Bytes()), "\n")
			for i, r := range recipientList {
				if r == "" {
					recipientList = append(recipientList[:i], recipientList[i+1:]...)
				}
			}
			log.Printf("recipientList: %q\n", recipientList)
			for _, userName := range recipientList {
				//name := userDB.LookupNameByPubkey(userID)
				isExistent := userDB.Lookup(userName)
				if isExistent == false {
					log.Printf("No user found with username: '%s'\n", userName)
					continue
				}
				filePath := filepath.Join(userName, fileID)
				log.Printf("filePath: %s\n", filePath)
				err = store.Write(filePath, inBuf.Bytes())
				if err != nil {
					log.Println(err)
				}
				log.Printf("file '%s' saved under: '%s'", fileID, filePath)
			}
			fmt.Fprintf(w, fileID)
		}
	default:
		http.Error(w, "Method not allowed", 405)
		return
	}
}

func Download(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("Apiusername")
	token := r.Header.Get("Apikey")
	if userDB.APIAuthenticate(username, token) != true {
		http.Error(w, "Unauthorized", 401)
		return
	}
	vars := mux.Vars(r)
	userID := vars["UserID"]
	fileID := vars["FileID"]
	filePath := strings.Join([]string{userID, fileID}, "/")
	data, err := store.Read(filePath)
	if err != nil {
		log.Printf("download error: %s\n", err.Error())
		http.Error(w, "file not found", 404)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\""+fileID+"\"")
	n, err := w.Write(data)
	if err != nil {
		log.Printf("error writing data to client")
		http.Error(w, err.Error(), 500)
		return
	}
	log.Printf("written %d byte to client\n", n)
	err = store.Erase(filePath)
	if err != nil {
		log.Printf("error erase file after download")
		http.Error(w, err.Error(), 500)
		return
	}
}
