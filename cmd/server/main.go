package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"github.com/dchest/blake2b"
	"github.com/gorilla/mux"
	"github.com/peterbourgon/diskv"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strings"
)

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
	flag.StringVar(&configFile, "conf", "", "config file to use (yaml)")
	flag.StringVar(&listenAddr, "l", "127.0.0.1:9999", "address to listen on, default is: 127.0.0.1:9999")
}

func AdvancedTransformExample(key string) *diskv.PathKey {
	log.Printf("Atransform: key: %s\n", key)
	path := strings.Split(key, "/")
	last := len(path) - 1
	log.Printf("path: '%s', last: '%d\n", path, last)
	return &diskv.PathKey{
		Path:     path[:last],
		FileName: path[last],
	}

}

// If you provide an AdvancedTransform, you must also provide its
// inverse:

func InverseTransformExample(pathKey *diskv.PathKey) (key string) {
	log.Printf("revTransform: pathKey: %+v\n", pathKey)
	key = strings.Join(pathKey.Path, "/") + "/" + pathKey.FileName
	log.Printf("revTransform: key: %s\n", key)
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
	// init file storage
	store = diskv.New(diskv.Options{
		BasePath:          cfg.DataDir,
		AdvancedTransform: AdvancedTransformExample,
		InverseTransform:  InverseTransformExample,
	})

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/{UserID}/{FileID}", Download)
	router.HandleFunc("/{UserID}/", Upload)
	log.Printf("listenAddr: %s\n", cfg.ListenAddr)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, router))
}

// GenBlake2b32 - genertes a blake2b 32 byte checksum over given data.
// aka long ID
func GenBlake2b32(data []byte) (c string) {
	b := blake2b.New256()
	b.Write(data)
	bsum := b.Sum(nil)
	return fmt.Sprintf("%x", bsum)
}

func Upload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["UserID"]
	switch r.Method {
	case "GET":
		keyChan := store.KeysPrefix(userID, nil)
		for k := range keyChan {
			fmt.Fprintf(w, "%s\n", k)
		}
	case "POST":
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
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}

			//if part.FileName() is empty, skip this iteration.
			if part.FileName() == "" {
				continue
			}
			if _, err := io.Copy(inWrt, part); err != nil {
				log.Printf("Error copy file part: %s\n", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// TODO: genFileID

			// TODO: store file
			fileID := GenBlake2b32(inBuf.Bytes())
			filePath := filepath.Join(userID, fileID)
			log.Printf("filePath: %s\n", filePath)
			err = store.Write(filePath, inBuf.Bytes())
			if err != nil {
				log.Println(err)
			}
			fmt.Fprintf(w, "files has been saved\n")
		}
	}
}

func Download(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["UserID"]
	fileID := vars["FileID"]
	filePath := strings.Join([]string{userID, fileID}, "/")
	data, err := store.Read(filePath)
	if err != nil {
		http.Error(w, err.Error(), 500)
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\""+fileID+"\"")
	w.Write(data)
}
