// secureShare client lib
package client

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/cathalgarvey/go-minilock"
	"github.com/cathalgarvey/go-minilock/taber"
	"github.com/google/uuid"
	"golang.org/x/crypto/scrypt"
	"gopkg.in/yaml.v2"
	"h12.me/socks"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/scusi/secureShare/libs/client/addressBook"
	"github.com/scusi/secureShare/libs/message"
)

const defaultURL = "https://securehare.scusi.io/"

var Debug bool

type Client struct {
	PublicKey    string       // encodeID of the user
	Keys         *taber.Keys  // minilock Keys
	Salt         []byte       // salt used to scrypt the encodeID
	Username     string       // scryped user encodeID
	MachineID    string       // UUID for the local machine
	MachineToken string       // auth token for this machine
	APIToken     string       // sessionID for API requests
	URL          string       // URL of the API
	Socksproxy   string       // socks5 proxy to connect to server
	httpClient   *http.Client // http.Client to talk to the API
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

func SetSocksproxy(sproxy string) OptionFunc {
	return func(client *Client) error {
		if sproxy == "" {
			err := fmt.Errorf("provided socksproxy is empty\n")
			return err
		}
		client.Socksproxy = sproxy
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
		pubID, err := keys.EncodeID()
		if err != nil {
			return err
		}
		client.PublicKey = pubID
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

// sets the http.Client to be used for requests to secureShareServer
func (c *Client) SetHttpClient(hc *http.Client) {
	c.httpClient = hc
}

func New(options ...OptionFunc) (c *Client, err error) {
	c = new(Client)
	if uuid.SetNodeID(uuid.NodeID()) != true {
		err = fmt.Errorf("Could not set nodeID")
		return
	}
	u, err := uuid.NewUUID()
	if err != nil {
		err = fmt.Errorf("Could not create new UUID")
		return
	}
	c.MachineID = hex.EncodeToString(u.NodeID())
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
	if c.Socksproxy != "" {
		dialSocksProxy := socks.DialSocksProxy(socks.SOCKS5, c.Socksproxy)
		tr := &http.Transport{Dial: dialSocksProxy}
		c.httpClient = &http.Client{Transport: tr}
	} else {
		c.httpClient = new(http.Client)
	}
	return c, nil
}

func (c *Client) SaveLocal(filename string) (err error) {
	cy, err := yaml.Marshal(c)
	/* // make sure that the path exists
	clientConfigFile = filepath.Join(
		usr.HomeDir, ".config",
		"secureshare", "client", c.Username, "config.yml")
	*/
	clientConfigPath := filepath.Dir(filename)
	err = os.MkdirAll(clientConfigPath, 0700)
	if err != nil {
		return
	}
	// write actual config file to disk
	err = ioutil.WriteFile(filename, cy, 0700)
	if err != nil {
		return
	}
	log.Printf("your configuration has been saved under: '%s'\n", filename)
	return
}
func RestoreLocal(filename string) (c *Client, err error) {
	// load client from config
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	err = yaml.Unmarshal(data, c)
	if err != nil {
		return
	}
	return
}

func (c *Client) SaveRemote() (err error) {
	err = c.SaveConfigOnServer()
	return
}

func RestoreRemote(keys *taber.Keys, serverURL string) (c *Client, err error) {
	if serverURL == "" {
		serverURL = defaultURL
	}
	hc := new(http.Client)
	// get userID from publicKey
	pubID, err := keys.EncodeID()
	if err != nil {
		return
	}
	getUsernameURL := serverURL + "usernameFromPubID"
	v := url.Values{}
	v.Add("pubID", pubID)
	req, err := http.NewRequest("GET", getUsernameURL+"?"+v.Encode(), nil)
	if err != nil {
		return
	}
	resp, err := hc.Do(req)
	if err != nil {
		return
	}
	username, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	log.Printf("username: '%s'\n", username)

	restoreURL := serverURL + "config/" + string(username)
	req, err = http.NewRequest("GET", restoreURL, nil)
	if err != nil {
		return
	}
	resp, err = hc.Do(req)
	if err != nil {
		return
	}
	configBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	senderID, _, rr, err := minilock.DecryptFileContents(configBytes, keys)
	if err != nil {
		return
	}
	if senderID != pubID {
		err = fmt.Errorf("senderID ('%s') does not match pubID ('%s')\n", senderID, pubID)
		return
	}
	// unmarshal
	var cl = new(Client)
	err = json.Unmarshal(rr, &cl)
	if err != nil {
		return
	}
	cl.SetHttpClient(new(http.Client))
	c = cl
	return
}

// ID - returns the clientID / secureShareUsername
func (c *Client) ID() (id string) {
	dk, err := scrypt.Key([]byte(c.PublicKey), c.Salt, 1<<15, 8, 1, 32)
	if err != nil {
		log.Fatal(err)
	}
	return base64.URLEncoding.EncodeToString(dk)
}

// UpdateKey - asks the secureShareServer for the actual key of a given user
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

func (c *Client) SaveConfigOnServer() (err error) {
	// marshal client
	clientBytes, err := json.Marshal(c)
	if err != nil {
		return
	}
	// encrypt clientBytes
	// TODO: minilock.EncryptFileContents()
	minilockBytes, err := minilock.EncryptFileContents("config", clientBytes, c.Keys, c.Keys)
	if err != nil {
		return
	}
	// create save request
	bodyReader := bytes.NewReader(minilockBytes)
	urlString := c.URL + "config/" + c.Username
	req, err := http.NewRequest("POST", urlString, bodyReader)
	if err != nil {
		return
	}
	if Debug {
		dump, _ := httputil.DumpRequestOut(req, false)
		log.Printf("%s", dump)
	}
	// send request
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	if Debug {
		dump, _ := httputil.DumpResponse(resp, true)
		log.Printf("%s", dump)
	}
	// check response
	if resp.StatusCode != 200 {
		log.Printf("status code (%d) is NOT OK\n", resp.StatusCode)
		body, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			return readErr
		}
		log.Printf("Server error: '%s'\n", body)
		err = fmt.Errorf("Server error: '%s'\n", body)
		return
	}
	// return
	return
}

func (c *Client) GetConfigOnServer() (err error) {
	urlString := c.URL + "config/" + c.Username
	req, err := http.NewRequest("GET", urlString, nil)
	if err != nil {
		return
	}
	if Debug {
		dump, _ := httputil.DumpRequestOut(req, false)
		log.Printf("%s", dump)
	}
	// send request
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	if Debug {
		dump, _ := httputil.DumpResponse(resp, true)
		log.Printf("%s", dump)
	}
	// check response
	if resp.StatusCode != 200 {
		log.Printf("status code (%d) is NOT OK\n", resp.StatusCode)
		body, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			return readErr
		}
		log.Printf("Server error: '%s'\n", body)
		err = fmt.Errorf("Server error: '%s'\n", body)
		return
	}
	// read body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	// decrypt body
	senderID, _, rr, err := minilock.DecryptFileContents(body, c.Keys)
	if err != nil {
		return
	}
	if senderID != c.PublicKey {
		err = fmt.Errorf("config senderID not correct: '%s' vs. '%s'\n", senderID, c.PublicKey)
		return
	}
	// unmarshal
	err = json.Unmarshal(rr, c)
	if err != nil {
		return
	}
	return
}

// Register - register a new user at the secureShareServer
func (c *Client) Register(pubID string) (user, token, mID, mToken string, err error) {
	v := url.Values{}
	v.Add("pubID", pubID)
	v.Add("MachineID", c.MachineID)
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
	if resp.StatusCode != 200 {
		log.Printf("status code (%d) is NOT OK\n", resp.StatusCode)
		body, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			return "", "", "", "", readErr
		}
		log.Printf("Server error: '%s'\n", body)
		err = fmt.Errorf("Server error: '%s'\n", body)
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	// decrypt and parse response
	registerResp := new(message.RegisterResponse)
	// decrypt body
	senderID, _, rr, err := minilock.DecryptFileContents(body, c.Keys)
	if err != nil {
		return
	}
	// TODO: check if senderID is the serverID
	log.Printf("register response senderID: '%s'\n", senderID)
	// unmarshal decrypted register response
	err = yaml.Unmarshal(rr, registerResp)
	if err != nil {
		return
	}
	// return to client
	return registerResp.Username, registerResp.APIToken,
		registerResp.MachineID, registerResp.MachineToken, nil
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

func (c *Client) SaveAddressbook(a *addressbook.Addressbook) (err error) {
	// save addressbook
	// get user home dir
	usr, err := user.Current()
	if err != nil {
		return
	}

	addressbookPath := filepath.Join(usr.HomeDir, ".config", "secureshare", "client", c.Username)
	addressbookPath = filepath.Join(addressbookPath, "addressbook.yml")
	adata, err := yaml.Marshal(&a)
	if err != nil {
		return
	}
	if Debug {
		log.Printf("addrbook to save: %s\n", adata)
	}
	err = ioutil.WriteFile(addressbookPath, adata, 0700)
	if err != nil {
		return
	}
	return
}
