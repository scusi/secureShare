# secureShare

a system to share files securely.

## Design Principles

### Secure by Design

_secureShare_ is based on minilock encryption.
Files are ancrypted before sent to the server, encryption keys never leav the local machine.

### Send once, reach many

_secureShare_ supports sending the same file to multiple users.

### ZeroKnowledge 

The _secureShareSever_ has as little information about the client and the content beeing transfereed as possible.

The server never has access to the content beeing transfered, since it is encrypted end-to-end useing minilock.
The server does not know the user, all the server knows is the public minilock-EncodeID of users that gets files send.
The server does not even see the filename, since it is alos protected by minilock encryption.

### beeing certain about the sender

minilock also signs data with the private-key of the sender.
So the recipient always can be sure who sent the content.


## Usage Examples

### List available files

```secureShare -list```

### Send a file

takes a file, encrypt it and send it to a server.

```secureShare -send Important.zip -recipient HZfb8HL4tL7bGJBZq2ha1oyQkf3ePTsLCBBqKog8ESz4y```

### Receive a file 

asks server for a given fileID, downloads file, decrypts it and saves it to disk.

```secureShare -receive 2be44e36```

### Server

takes files from clients and stores them until someone picks the file up.

```secureShareServer -conf config.yml```

A typical server config file looks like:

```
listenaddr: "127.0.0.1:9999"
certfile: "cert.pem"
keyfile: "key.pem"
datadir: "data"
usersfile: "users.yml"
```

#### Config file options

* listenaddr:	is the listening address where _secureShareServer_ waits for connections
* certfile:	is the path tho the PEM encoded TLS certificate beeing used to provide TLS transport security (aka HTTPS)
		if certfile is empty TLS support is disabled.
* keyfile:	is the path to the PEM encoded TLS key beeing used to provide TLS transport security (aka HTTPS)
		if keyfile is empty TLS support is disabled.
* datadir:	is the path to the directory where uploaded data is stored
		The data directory will be created if not existing and filesystem permissions allow so.
* usersfile:	is the path to the yaml encoded file that holds information about the users.

