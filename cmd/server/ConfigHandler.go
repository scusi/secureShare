package main

import (
	"bufio"
	"bytes"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
)

func ConfigHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Header.Get("Apiusername")
	token := r.Header.Get("Apikey")
	if userDB.APIAuthenticate(username, token) != true {
		http.Error(w, "Unauthorized", 401)
		return
	}
	vars := mux.Vars(r)
	userID := vars["UserID"]

	switch r.Method {
	case "GET":
		// send config to client aka download
		filePath := strings.Join([]string{userID, "config"}, "/")
		data, err := fileStore.Read(filePath)
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
		// retrieve config from client and store aka upload
		var inBuf bytes.Buffer
		inWrt := bufio.NewWriter(&inBuf)
		reader, err := r.MultipartReader()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if part.FileName() == "" {
				continue
			}
			if _, err = io.Copy(inWrt, part); err != nil {
				log.Printf("Error copy file part: %s\n", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			filePath := filepath.Join(userID, "config")
			err = clientStore.Write(filePath, inBuf.Bytes())
			if err != nil {
				log.Println(err)
			}
		}
		return
	}
	return
}
