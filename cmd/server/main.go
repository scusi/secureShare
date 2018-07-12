package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"github.com/cathalgarvey/go-minilock"
	"github.com/cathalgarvey/go-minilock/taber"
	"github.com/decred/base58"
	"github.com/gorilla/mux"
	"github.com/peterbourgon/diskv"
	"github.com/scusi/bytesize"
	"github.com/scusi/secureShare/libs/message"
	"github.com/scusi/secureShare/libs/server/common"
	"github.com/scusi/secureShare/libs/server/config"
	"github.com/scusi/secureShare/libs/server/user"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
)

var userDB *user.UserDB

var Debug bool
var configFile string
var listenAddr string
var fileStore *diskv.Diskv
var clientStore *diskv.Diskv
var cfg *config.Config
var err error
var keys *taber.Keys

func init() {
	flag.BoolVar(&Debug, "debug", false, "enables debug output, when 'true'")
	flag.StringVar(&configFile, "conf", "", "config file to use (yaml)")
	flag.StringVar(&listenAddr, "l", "", "address to listen on, overwrites config value if set")
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

func checkFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	flag.Parse()
	// read and parse config
	cfg, err = config.ReadFromFile(configFile)
	checkFatal(err)
	// overwrite the config listenAddr if flag is set
	if listenAddr != "" {
		cfg.ListenAddr = listenAddr
	}
	// generate server keypair
	if cfg.Email == "" {
		err := fmt.Errorf("Email field from config are empty.")
		checkFatal(err)
	}
	if cfg.Password == "" {
		// if password is empty create one and save it to config
		pwdSeed := make([]byte, 96)
		_, err = rand.Read(pwdSeed)
		checkFatal(err)
		// generate some password with a hash function from seed
		cfg.Password = base58.Encode(pwdSeed)
		log.Printf("generated Password for you: '%s'\n", cfg.Password)
		err = config.WriteToFile(configFile, cfg)
		checkFatal(err)
		log.Printf("config saved to '%s'\n", configFile)
	}
	keys, err = minilock.GenerateKey(cfg.Email, cfg.Password)
	checkFatal(err)
	encodeID, err := keys.EncodeID()
	checkFatal(err)
	log.Printf("server public key is: '%s'\n", encodeID)

	userDB, err = user.LoadFromFile(cfg.UsersFile)
	checkFatal(err)
	// init file storage
	fileStore = diskv.New(diskv.Options{
		BasePath:          cfg.DataDir,
		AdvancedTransform: AdvancedTransformExample,
		InverseTransform:  InverseTransformExample,
	})
	clientStore = diskv.New(diskv.Options{
		BasePath:          "clientData",
		AdvancedTransform: AdvancedTransformExample,
		InverseTransform:  InverseTransformExample,
	})
	// initialize http router
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/config/{UserID}", ConfigHandler).Name("ConfigHandler")
	router.HandleFunc("/{UserID}/{FileID}", Download)
	router.HandleFunc("/upload/", Upload)
	router.HandleFunc("/list/", List)
	router.HandleFunc("/register/", Register)
	router.HandleFunc("/lookupKey", LookupKey)
	router.HandleFunc("/usernameFromPubID", UsernameFromPubID)
	router.HandleFunc("/ping", Pong)
	router.HandleFunc("/", Index)
	// start server
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		log.Printf("listenAddr: %s (TLS)\n", cfg.ListenAddr)
		log.Fatal(http.ListenAndServeTLS(cfg.ListenAddr, cfg.CertFile, cfg.KeyFile, router))
	} else {
		log.Printf("listenAddr: %s\n", cfg.ListenAddr)
		log.Fatal(http.ListenAndServe(cfg.ListenAddr, router))
	}
}

func Pong(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "pong")
	return
}

func Index(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://github.com/scusi/secureShare", 301)
}

// RegisterHost
/*
should make it possible to use an existing account from a machine where no local config is available
*/
func RegisterHost() {
	//
}

// Register - registers a new key, creates a user and returns the new userID and the APIToken
// to the registering client
func Register(w http.ResponseWriter, r *http.Request) {
	log.Printf("Register -->")
	pubID := r.FormValue("pubID")
	machineID := r.FormValue("MachineID")
	// TODO: validate machineID
	if Debug {
		log.Printf("got register request from '%s' for pubID: '%s'", machineID, pubID)
	}
	// TODO: check if pubID is a syntactical valid minilock ID
	username, err := common.NewUserID()
	if err != nil {
		log.Printf("ERROR: creating userID failed: '%s'\n", err)
		http.Error(w, "creating user ID failed", 500)
		return
	}
	// check if userID already exists
	if userDB.Lookup(username) {
		log.Printf("ERROR: User '%s' already exists.\n", username)
		http.Error(w, "User already existing", 500)
		return
	}
	// check if there are other accounts with the same public key
	if userDB.LookupNameByPubkey(pubID) != "" {
		log.Printf("ERROR: another user with the same key (%s) already exists.\n", pubID)
		http.Error(w, "Another user with the same key already exists", 500)
		return
	}

	log.Printf("going to add new user '%s' with pubID '%s'\n", username, pubID)
	err = userDB.Add(username, pubID)
	if err != nil {
		http.Error(w, "adding user failed", 500)
		return
	}
	machineToken, err := userDB.AddMachine(username, machineID)
	if err != nil {
		http.Error(w, "adding machine failed", 500)
		return
	}

	token := userDB.APIToken(username)
	//fmt.Fprintf(w, "%s", token)
	registerResp := &message.RegisterResponse{
		Username:     username,
		APIToken:     token,
		MachineID:    machineID,
		MachineToken: machineToken,
	}
	y, err := yaml.Marshal(registerResp)
	if err != nil {
		http.Error(w, "marshaling response failed", 500)
		return
	}
	// encrypt register response with client public key
	rkeys, err := taber.FromID(pubID)
	if err != nil {
		http.Error(w, "generate recipient keys from encodeID failed", 500)
		return
	}
	cy, err := minilock.EncryptFileContents("RegisterResponse", y, keys, rkeys)
	if err != nil {
		http.Error(w, "encrypting RegisterResponse failed", 500)
		return
	}
	// write response to the client
	n, err := w.Write(cy)
	if err != nil {
		http.Error(w, "writing response failed", 500)
		return
	}
	log.Printf("Register: wrote %d byte to %s\n", n, r.RemoteAddr)
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

func UsernameFromPubID(w http.ResponseWriter, r *http.Request) {
	pubID := r.FormValue("pubID")
	username := userDB.LookupNameByPubkey(pubID)
	if username != "" {
		fmt.Fprintf(w, username)
		return
	}
	http.Error(w, "not found", 404)
	return
}

func List(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("Apiusername")
	token := r.Header.Get("Apikey")
	if userDB.APIAuthenticate(username, token) != true {
		http.Error(w, "Unauthorized", 401)
		return
	}
	keyChan := fileStore.KeysPrefix(username, nil)
	for k := range keyChan {
		//TODO: get the file time and display it
		fi, err := getFileInfo(k)
		if err != nil {
			http.Error(w, "could not list files", 500)
			log.Printf("ERROR: Could not list files for '%s': %s\n", username, err.Error())
		}
		k = strings.TrimPrefix(k, username+"/")
		fmt.Fprintf(w, "'%s'  %s\n", k, fi)
	}
}

func getFileInfo(filename string) (fileInfo string, err error) {
	// build filepath
	filePath := filepath.Join(cfg.DataDir, filename)
	// get size and creation date
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	fi, err := f.Stat()
	if err != nil {
		return
	}
	// return size and creation date as string
	size := fi.Size()
	if err != nil {
		return
	}
	modTime := fi.ModTime()
	if err != nil {
		return
	}
	// TODO: make size human readable with bytesize
	// TODO: format time as a shorter string
	//return fmt.Sprintf("%d, %s", size, modTime), nil
	return fmt.Sprintf("%s, %s", bytesize.ByteSize(int64(size)), modTime.Format("02.01.2006 15:04:05 MST")), nil
}

func Upload(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		//log.Printf("Method: POST\n")
		if Debug {
			dump, errDump := httputil.DumpRequest(r, false)
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
				//log.Printf("recipientList from part: %+v", part)
				_, err := io.Copy(recListWriter, part)
				if err != nil {
					log.Printf("ERROR: io.Copy recipientList: %s\n", err.Error())
					return
				}
				//log.Printf("Copied %d byte from recList\n", n)
			}
			//if part.FileName() is empty, skip this iteration.
			if part.FileName() == "" {
				continue
			}
			//log.Printf("part.FileName = '%s'\n", part.FileName())
			//n := int64(0)
			if _, err = io.Copy(inWrt, part); err != nil {
				log.Printf("Error copy file part: %s\n", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			//log.Printf("copied %d byte to mime part\n", n)
			// genFileID
			fileID, err := common.ShortID(inBuf.Bytes())
			if err != nil {
				log.Printf("ERROR generating checksum blake2s: %s\n", err.Error())
				//http.Error(w, err.Error(), 500)
				fileID = common.LongID(inBuf.Bytes())
			}

			// fileStore file
			//log.Printf("recList: %s\n", string(recList.Bytes()))
			recipientList := strings.Split(string(recList.Bytes()), "\n")
			for i, r := range recipientList {
				if r == "" {
					recipientList = append(recipientList[:i], recipientList[i+1:]...)
				}
			}
			//log.Printf("recipientList: %q\n", recipientList)
			for _, userName := range recipientList {
				//name := userDB.LookupNameByPubkey(userID)
				isExistent := userDB.Lookup(userName)
				if isExistent == false {
					log.Printf("ERROR: No user found with username: '%s'\n", userName)
					continue
				}
				filePath := filepath.Join(userName, fileID)
				//log.Printf("filePath: %s\n", filePath)
				err = fileStore.Write(filePath, inBuf.Bytes())
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
	// make sure a user can only download his/her own files
	if userID != username {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	filePath := strings.Join([]string{userID, fileID}, "/")
	data, err := fileStore.Read(filePath)
	if err != nil {
		log.Printf("ERROR downloading '%s': %s\n", fileID, err.Error())
		http.Error(w, "file not found", 404)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\""+fileID+"\"")
	n, err := w.Write(data)
	if err != nil {
		log.Printf("ERROR writing data to client '%s'\n", r.RemoteAddr)
		http.Error(w, err.Error(), 500)
		return
	}
	log.Printf("written %d byte to client\n", n)
	err = fileStore.Erase(filePath)
	if err != nil {
		log.Printf("ERROR erase file after download")
		http.Error(w, err.Error(), 500)
		return
	}
}

func ConfigHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("entering ConfigHandler...\n")
	/* We can not authenticate because we have no ApiKey on the client yet.
	username := r.Header.Get("Apiusername")
	token := r.Header.Get("Apikey")
	if userDB.APIAuthenticate(username, token) != true {
		http.Error(w, "Unauthorized", 401)
		return
	}
	*/
	vars := mux.Vars(r)
	userID := vars["UserID"]

	switch r.Method {
	case "GET":
		log.Printf("ConfigHandler GET\n")
		// send config to client aka download
		//filePath := strings.Join([]string{userID, "config"}, "/")
		filePath := filepath.Join(userID, "config")
		data, err := clientStore.Read(filePath)
		if err != nil {
			log.Printf("ERROR downloading '%s': %s\n", filePath, err.Error())
			http.Error(w, "file not found", 404)
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename=\"config\"")
		n, err := w.Write(data)
		if err != nil {
			log.Printf("ERROR writing data to client '%s'\n", r.RemoteAddr)
			http.Error(w, err.Error(), 500)
			return
		}
		log.Printf("written %d byte to client\n", n)
		return
	case "POST":
		log.Printf("ConfigHandler POST\n")
		// retrieve config from client and store aka upload
		bodyBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		filePath := filepath.Join(userID, "config")
		err = clientStore.Write(filePath, bodyBytes)
		if err != nil {
			log.Println(err)
		}
	}
	return
}
