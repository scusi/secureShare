# Server authentication

The server stores a salted hash of the users minilock encodeID.
The client sends recipient information only as salted hash value.
The Client authenticates to the server with the salted hash of its encodeID 
and the APIToken issued by the server.

For this to work the client needs to store and maintain the salt value used to
hash its encodeID.

basically the salted hash of the users encodeID is used as a username in 
secureShare.

The server also has a minilock keypair, in order to enable clients to
communicate with the server securely.


client							server
---------------------------------------------------------------

Registration:

1) generate keypair
2) generate salt
3) hash pubkey with salt
4) send salted pubkey to server
				5) server saves salted pubkey
				6) server issues a APIToken and
				   sends it to the client
7) client saves salt, keypair
   and APIToken

Notes: Either a user:
- can have only one client
- has to share the same APIToken among clients
- or secureShare can hold multiple APITokens per user account
  in order to support several clients per user

---------------------------------------------------------------

List available Files:

1) client sends list request
   to server, auth via 
   pubkey (saltedHash) and APIToken.
				2) server authenticates client and
				   sends a list with waiting files.

---------------------------------------------------------------

Send a file:

1) client encrypts and sends
   file to server.
   				2) server stores file within the
				   dir for the recipient
3) recipient client downloads
   file, decrypts and saves.
   				4) server deletes file.

---------------------------------------------------------------
