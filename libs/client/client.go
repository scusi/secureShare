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

type Client struct {
	Username   string
	Password   string
	APIToken   string
	HttpClient *http.Client
}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	log.Printf("escaping '%s'\n", s)
	return quoteEscaper.Replace(s)
}

type OptionFunc func(*Client) error

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
	for _, option := range options {
		if err := option(c); err != nil {
			return nil, err
		}
	}
	c.HttpClient = new(http.Client)
	return c, nil
}

// UploadFile will upload a given file for a given user on secureShare
func (c *Client) UploadFile(recipient string, data []byte) (err error) {
	buf := bytes.NewReader(data)
	log.Printf("UploadFile: data = %d byte\n", len(data))
	fieldname := "file"
	filename := "data.file"
	//bodyReader, bodyWriter := io.Pipe()
	var body bytes.Buffer
	bodyWriter := bufio.NewWriter(&body)
	mimeW := multipart.NewWriter(bodyWriter)
	fdct := mimeW.FormDataContentType()
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition",
		fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
			escapeQuotes(fieldname), escapeQuotes(filename)))
	h.Set("Content-Type", "applaication/octet-stream")
	log.Printf("mime header: %s\n", h)
	part, err := mimeW.CreatePart(h)
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
	req, err := http.NewRequest("POST", "http://127.0.0.1:9999/"+recipient+"/", bodyReader)
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
		return
	}
	if resp.StatusCode == 200 {
		return nil
	} else {
		err := fmt.Errorf("Request could not be processed by the server\n")
		log.Printf("RESPONSE:\n%+v\n", resp)
		return err
	}
}

func (c *Client) ListFiles() (err error) {
	return
}

func (c *Client) DownloadFile(fileID string) (filename string, data []byte, err error) {
	myID := "HZfb8HL4tL7bGJBZq2ha1oyQkf3ePTsLCBBqKog8ESz4y"
	req, err := http.NewRequest("GET", "http://127.0.0.1:9999/"+myID+"/"+fileID, nil)
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return
	}
	fileContent, err := ioutil.ReadAll(resp.Body)
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
