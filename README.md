# secureShare

a system to share files securely.

## Design

### Sender

takes a file, encrypt it and send it to a server.

### Recipient

asks server for a given fileID, downloads file, decrypts it and saves it to disk.

### Server

takes files from clients and stores them until someone picks the file up.

