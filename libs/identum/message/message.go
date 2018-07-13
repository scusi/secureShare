package message

import (
	"encoding/json"
)

type MessageType int

const (
	NOP       MessageType = iota // 0
	Add                          // 1
	Remove                       // 2
	RemoveAll                    // 3
	Lock                         // 4
	Unlock                       // 5
	Encrypt                      // 6
	Decrypt                      // 7
)

type Message struct {
	Type    MessageType
	Content interface{}
}

func (mt MessageType) String() string {
	switch mt {
	case MessageType(0):
		return "NOP"
	case 1:
		return "Add"
	case 2:
		return "Remove"
	case 3:
		return "RemoveAll"
	case 4:
		return "Lock"
	case 5:
		return "Unlock"
	case 6:
		return "Encrypt"
	case 7:
		return "Decrypt"
	}
	return "unknown message type"
}

func New(t MessageType, content interface{}) (m *Message) {
	m = new(Message)
	m.Type = t
	m.Content = content
	return
}

func Marshal(m *Message) (mBytes []byte, err error) {
	mBytes, err = json.Marshal(m)
	if err != nil {
		return
	}
	return
}

func Unmarshal(mBytes []byte) (mt MessageType, content interface{}, err error) {
	var m Message
	err = json.Unmarshal(mBytes, &m)
	if err != nil {
		return
	}
	return m.Type, m.Content, err
}
