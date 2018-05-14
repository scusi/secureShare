// secureShare client lib
package client

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/cathalgarvey/go-minilock"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"strings"
)

const defaultURL = "http://127.0.0.1:9999/"

type Client struct {
	ID         string
	Username   string
	Password   string
	APIToken   string
	URL        string
	HttpClient *http.Client
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

func SetPassword(password string) OptionFunc {
	return func(client *Client) error {
		if password == "" {
			err := fmt.Errorf("Password is empty\n")
			return err
		}
		client.Password = password
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
	c.HttpClient = new(http.Client)
	keys, err := minilock.GenerateKey(c.Username, c.Password)
	if err != nil {
		return
	}
	c.ID, err = keys.EncodeID()
	if err != nil {
		return
	}

	return c, nil
}

// UploadFile will upload a given file for a given user on secureShare
func (c *Client) UploadFile(recipient string, data []byte) (fileID string, err error) {
	recipientList := strings.Split(recipient, ",")
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
	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		log.Fatal(err)

	}

	log.Printf("%s", dump)

	resp, err := c.HttpClient.Do(req)
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

func (c *Client) ListFiles() (err error) {
	return
}

func (c *Client) DownloadFile(fileID string) (filename string, fileContent []byte, err error) {
	req, err := http.NewRequest("GET", c.URL+c.ID+"/"+fileID, nil)
	req.Header.Add("APIUsername", c.Username)
	req.Header.Add("APIKey", c.APIToken)
	resp, err := c.HttpClient.Do(req)
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

	senderId, filename, content, err := minilock.DecryptFileContentsWithStrings(fileContent, c.Username, c.Password)
	if err != nil {
		log.Printf("decryption error: '%s'\n", err.Error())
	}
	log.Printf("SenderID was: %s\n", senderId)
	return filename, content, err
}
