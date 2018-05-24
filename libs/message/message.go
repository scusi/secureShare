// message - defines secureShare messages for client and server
package message

import ()

type RegisterResponse struct {
	Username string
	APIToken string
}

type RegisterRequest struct {
	PublicKey string
	Seed      []byte
}
