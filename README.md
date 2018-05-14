# secureShare

a system to share files securely.

## Design

### Sender

takes a file, encrypt it and send it to a server.

```secureShare -send Important.zip -recipient HZfb8HL4tL7bGJBZq2ha1oyQkf3ePTsLCBBqKog8ESz4y```

### Recipient

asks server for a given fileID, downloads file, decrypts it and saves it to disk.

```secureShare -receive 2be44e36```

### Server

takes files from clients and stores them until someone picks the file up.

```secureShareServer -conf config.yml```

