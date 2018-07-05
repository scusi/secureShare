// message - defines secureShare messages for client and server
package message

import ()

type RegisterResponse struct {
	Username     string
	MachineID    string
	MachineToken string
	APIToken     string
}

type RegisterRequest struct {
	PublicKey string
	MachineID string
	Seed      []byte
}
