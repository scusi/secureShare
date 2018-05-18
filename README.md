# secureShare

a system to share files securely.

## Design Principles

### Secure by Design

_secureShare_ is based on minilock encryption.
Files are ancrypted before sent to the server, encryption keys never leave the local machine.

### Send once, reach many

_secureShare_ supports sending the same file to multiple users.

### ZeroKnowledge 

The _secureShareSever_ has as little information about the client and the content beeing transfered as possible.

The server never has access to the content beeing transfered, since it is encrypted end-to-end useing minilock.
The server does not know the user, all the server knows is the public minilock-EncodeID of users that gets files send.
The server does not even see the filename, since it is also protected by minilock encryption.

### beeing certain about the sender

minilock also signs data with the private-key of the sender.
So the recipient always can be sure who sent the content.


## Usage Examples

### Setup secureShare

Before you can use secureShare the first time you need to register.

```secureShare -register```

You will be asked for your email (username) and a password.
From that username and password minilock keys will be generated.
Then your public minilock ID (encodeID) is sent to the server.
The server issues an APIToken which is sent back to the client.
Subsequent requests are then authenticated by username and APIToken.

### Add other people to your addressbook

_secureShare_ has an addressbook build in. The addressbook makes it possible 
to use alias names - which are easier to remember instead of cryptic strings - 
as recipient names.

You can add a contact like this:

```secureShare -addContact <secureShareUsername> -alias bob```

Replace <secureShareUsername> with the actual username.
A _secureShareUsername_ looks like this 

 'IWy_5D8aM-IotdWyEbDt9IvDaNP_l8HtPFP3d_TaFl0='

### List available files

```secureShare -list```

### Send a file

takes a file, encrypt it and send it to a server.

```secureShare -send Important.zip -recipient bob```

### Receive a file 

asks server for a given fileID, downloads file, decrypts it and saves it to disk.

```secureShare -receive 2be44e36```

### Server

#### before you start the first time

Before you can run the server you need to have a users file, where the serverstores information about registered users.
In order to create an empty users file runn the following command:

```
secureShareServerNewUserDB
```

Above command will create a users.yml file in the local directory.
Make sure the path to this file is set correctly in config.yml

takes files from clients and stores them until someone picks the file up.

#### starting the server

```secureShareServer -conf config.yml```

#### example server config

A typical server config file looks like:

```
listenaddr: "127.0.0.1:9999"
certfile: "cert.pem"
keyfile: "key.pem"
datadir: "data"
usersfile: "users.yml"
```

#### Server config options

* listenaddr:	is the listening address where _secureShareServer_ waits for connections
* certfile:	is the path tho the PEM encoded TLS certificate beeing used to provide TLS transport security (aka HTTPS)
		if certfile is empty TLS support is disabled.
* keyfile:	is the path to the PEM encoded TLS key beeing used to provide TLS transport security (aka HTTPS)
		if keyfile is empty TLS support is disabled.
* datadir:	is the path to the directory where uploaded data is stored
		The data directory will be created if not existing and filesystem permissions allow so.
* usersfile:	is the path to the yaml encoded file that holds information about the users.

## Releases

Precompiled binaries for various operating systems and architectures can be found unter [releases](https://github.com/scusi/secureShare/releases/)
