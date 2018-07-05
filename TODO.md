- [DONE] server does not need a 'cleartext' username, pubID should do.
  exchange username with pubID on the server side
- [DONE] client should not store password or (if) just bcrypted
- [DONE] add addressbook so you can send files to contacts without need to lookup the corresponding minilock ID manually.
- add a function to unregister / delete account to client and server
- add a function to get a new APIToken on client and server side
- add a go routine that deletes old files
  define old: 72 hours?
- a function to inform the user that there is a file for him/her would be handy.
  problems:
  - you have to keep meta data for this, have you?
  - how to inform them securely?
  ideas:
  - the client could have a email addr of the recipient and add it to the upload request.
    the server could inform the user and forget the email address right away.
  - a messaging functionality could be added right in the client.
  - the client could poll from time to time for new files.
