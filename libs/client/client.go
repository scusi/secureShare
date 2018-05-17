// secureShare client lib
package client

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/cathalgarvey/go-minilock"
	"github.com/cathalgarvey/go-minilock/taber"
	"golang.org/x/crypto/scrypt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"strings"
)

const defaultURL = "http://127.0.0.1:9999/"

var Debug bool

type Client struct {
	PublicKey  string
	Keys       *taber.Keys
	Salt       []byte
	Username   string
	APIToken   string
	URL        string
	httpClient *http.Client
}

func (c *Client) Do(r *http.Request) (resp *http.Response, err error) {
	resp, err = c.httpClient.Do(r)
	return
}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	log.Printf("escaping '%s'\n", s)
	return quoteEscaper.Replace(s)
}

type OptionFunc func(*Client) error

func SetURL(url string) OptionFunc {
	return func(client *Client) error {
		if url == "" {
			err := fmt.Errorf("URL is empty\n")
			return err
		}
		if strings.HasSuffix(url, "/") {
			client.URL = url
		} else {
			client.URL = url + "/"
		}
		return nil
	}
}

func SetUsername(username string) OptionFunc {
	return func(client *Client) error {
		if username == "" {
			err := fmt.Errorf("Username is empty\n")
			return err
		}
		client.Username = username
		return nil
	}
}

func SetKeys(keys *taber.Keys) OptionFunc {
	return func(client *Client) error {
		client.Keys = keys
		return nil
	}
}

func SetAPIToken(token string) OptionFunc {
	return func(client *Client) error {
		if token == "" {
			err := fmt.Errorf("APIToken is empty\n")
			return err
		}
		client.APIToken = token
		return nil
	}
}

func New(options ...OptionFunc) (c *Client, err error) {
	c = new(Client)
	c.URL = defaultURL
	for _, option := range options {
		if err := option(c); err != nil {
			return nil, err
		}
	}
	salt := make([]byte, 16)
	_, err = rand.Read(salt)
	if err != nil {
		return nil, err
	}
	c.Salt = salt
	c.httpClient = new(http.Client)
	return c, nil
}

func (c *Client) ID() (id string) {
	dk, err := scrypt.Key([]byte(c.PublicKey), c.Salt, 1<<15, 8, 1, 32)
	if err != nil {
		log.Fatal(err)
	}
	return base64.URLEncoding.EncodeToString(dk)
}

func (c *Client) SetHttpClient(hc *http.Client) {
	c.httpClient = hc
}

func (c *Client) UpdateKey(username string) (pubKey string, err error) {
	v := url.Values{}
	v.Add("username", username)
	req, err := http.NewRequest("GET", c.URL+"lookupKey?"+v.Encode(), nil)
	if err != nil {
		return
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("ERROR: Server could not answer request.\n")
		dump, errDump := httputil.DumpResponse(resp, true)
		if errDump != nil {
			log.Printf("ERROR: Could not dump Response\n")
		} else {
			log.Printf("Response:\n%s\n", dump)
		}
	} else {
		pk, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return string(pk), err
	}
	return
}

func (c *Client) Register(username, pubID string) (token string, err error) {
	v := url.Values{}
	v.Add("username", username)
	v.Add("pubID", pubID)
	// does not work
	//req, err := http.NewRequest("POST", c.URL+"register", strings.NewReader(v.Encode()))
	req, err := http.NewRequest("GET", c.URL+"register?"+v.Encode(), nil)
	if err != nil {
		return
	}
	if Debug {
		dump, _ := httputil.DumpRequestOut(req, false)
		log.Printf("%s", dump)
	}
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	if Debug {
		dump, _ := httputil.DumpResponse(resp, true)
		log.Printf("%s", dump)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	return fmt.Sprintf("%s", body), nil
}

// UploadFile will upload a given file for a given user on secureShare
func (c *Client) UploadFile(recipient string, data []byte) (fileID string, err error) {
	recipientList := strings.Split(recipient, ",")
	log.Printf("UploadFile: recipientList: %v\n", recipientList)
	log.Printf("UploadFile: length of data: %d\n", len(data))
	buf := bytes.NewReader(data)
	log.Printf("UploadFile: data = %d byte\n", len(data))
	fieldname := "file"
	filename := "data.file"
	//bodyReader, bodyWriter := io.Pipe()
	var body bytes.Buffer
	bodyWriter := bufio.NewWriter(&body)
	mimeW := multipart.NewWriter(bodyWriter)
	// WIP create a recipientList
	rh := make(textproto.MIMEHeader)
	rh.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"`, escapeQuotes("recipientList")))
	//rh.Set("Content-Type", "multipart/form-data")
	part, err := mimeW.CreatePart(rh)
	if err != nil {
		return
	}
	for _, recipient := range recipientList {
		part.Write([]byte(recipient + "\n"))
	}

	fdct := mimeW.FormDataContentType()
	fh := make(textproto.MIMEHeader)
	fh.Set("Content-Disposition",
		fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
			escapeQuotes(fieldname), escapeQuotes(filename)))
	fh.Set("Content-Type", "application/octet-stream")
	log.Printf("mime header: %s\n", fh)
	part, err = mimeW.CreatePart(fh)
	if err != nil {
		return
	}
	log.Printf("new part created")
	//n, err := part.Write(data)
	n, err := io.Copy(part, buf)
	if err != nil {
		return
	}
	log.Printf("%d byte written to mime part\n", n)
	mimeW.Close()
	bodyWriter.Flush()
	bodyReader := bufio.NewReader(&body)
	// build http request
	req, err := http.NewRequest("POST", c.URL+"upload/", bodyReader)
	if err != nil {
		return
	}
	req.Header.Add("Content-Type", fdct)
	req.Header.Add("APIUsername", c.Username)
	req.Header.Add("APIKey", c.APIToken)
	/*
	 */
	if Debug {
		dump, err := httputil.DumpRequestOut(req, false)
		if err != nil {
			log.Fatal(err)

		}
		log.Printf("%s", dump)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode == 200 {
		fileID, err := ioutil.ReadAll(resp.Body)
		return string(fileID), err
	} else {
		err := fmt.Errorf("Request could not be processed by the server\n")
		dump, errDump := httputil.DumpResponse(resp, true)
		if errDump != nil {
			log.Printf("Could not dump response: %s\n", errDump.Error())
		}
		log.Printf("RESPONSE:\n%s\n", dump)
		return "", err
	}
}

func (c *Client) List() (fileList string, err error) {
	req, err := http.NewRequest("GET", c.URL+"list/", nil)
	req.Header.Add("APIUsername", c.Username)
	req.Header.Add("APIKey", c.APIToken)
	if Debug {
		dump, errDump := httputil.DumpRequestOut(req, true)
		if errDump != nil {
			log.Printf("Could not dump request '%s'\n", errDump.Error())
		}
		log.Printf("RequestDump:\n%s\n", dump)
	}
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("Response is NOT OK, Status: %s\n", resp.Status)
		dump, errDump := httputil.DumpResponse(resp, true)
		if errDump != nil {
			log.Printf("Could not dump response '%s'\n", errDump.Error())
		}
		log.Printf("ResponseDump:\n%s\n", dump)
		return
	}
	list, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	return string(list), nil
}

func (c *Client) DownloadFile(fileID string) (filename string, fileContent []byte, err error) {
	req, err := http.NewRequest("GET", c.URL+c.Username+"/"+fileID, nil)
	req.Header.Add("APIUsername", c.Username)
	req.Header.Add("APIKey", c.APIToken)
	if Debug {
		dump, errDump := httputil.DumpRequestOut(req, true)
		if errDump != nil {
			log.Printf("Could not dump request '%s'\n", errDump.Error())
		}
		log.Printf("RequestDump:\n%s\n", dump)
	}
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("Response is NOT OK, Status: %s\n", resp.Status)
		dump, errDump := httputil.DumpResponse(resp, true)
		if errDump != nil {
			log.Printf("Could not dump response '%s'\n", errDump.Error())
		}
		log.Printf("ResponseDump:\n%s\n", dump)
		return
	}
	fileContent, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	senderId, filename, content, err := minilock.DecryptFileContents(fileContent, c.Keys)
	if err != nil {
		log.Printf("decryption error: '%s'\n", err.Error())
	}
	log.Printf("SenderID was: %s\n", senderId)
	return filename, content, err
}
