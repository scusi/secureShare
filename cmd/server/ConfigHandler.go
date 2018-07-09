package main

import (
	"github.com/gorilla/mux"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	//"strings"
)

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
