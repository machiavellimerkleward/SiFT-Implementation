# Simple File Transfer v0.7

This document specifies version 0.7 of the Simple File Transfer (SiFT) protocol. SiFT can be used by a client to send file commands to a server, which executes those commands. SiFT supports the following 7 commands (same as for SiFT v0.5 and SiFT v0.6):

- __pwd__ --> Print current working directory: Returns to the client the name of the current working directory on the server.
- __lst__ --> List content of the current working directory: Returns to the client the list of files and directories in the current working directory on the server. 
- __chd__ --> Change directory: Changes the current working directory on the server. The name of the target directory is provided as an argument to the chd command.
- __mkd__ --> Make directory: Creates a new directory on the server. The name of the directory to be created is provided as an argument to the mkd command.
- __del__ --> Delete file or directory: Deletes a file or a directory on the server. The name of the file or directory to be deleted is provided as an argument to the del command.
- __upl__ --> Upload file: Uploads a file from the client to the server. The name of the file to be uploaded is provided as an argument to the upl command and the file is put in the current working directory on the server.
- __dnl__ --> Download file: Downloads a file from the current working directory of the server to the client. The name of the file to be downloaded is provided as an argument to the dnl command.

SiFT allows the client and the server to communicate via a network and execute the above commands remotely. It assumes that the client and the server uses the TCP/IP protocol to establish a connection and to send data reliably to each other. By reliability, we mean that the bytes sent by a party arrive to the other party, and they arrive in the order that they were sent. The server listens and accepts client connection requests on TCP port 5150.

Unlike earlier versions, SiFT v0.7 implements a shared secret key established dynamically between the client and the server. A 32-byte AES key is derived from the shared secret. The static key used in SiFT v0.6 is replaced with this freshly derived key and passed to the MTP sub-protocol.

## Overview of sub-protocols

SiFT v0.7 has the same sub-protocols as SiFT v0.6, with the addition of one with sub-protocol, the Init Protocol. The following sub-procotols remain from SiFTv0.6: Message Transfer Protocol (MTP), Login Protocol, Commands Protocol, Upload Protocol, and Download Protocol. The following figure shows how these sub-protocols are related to each other: 


```
  +-------------+  +--------------+  +-----------------+  +---------------+  +-----------------+
  |Init Protocol|  |Login Protocol|  |Commands Protocol|  |Upload Protocol|  |Download Protocol|
  +-------------+  +--------------+  +-----------------+  +---------------+  +-----------------+
  +--------------------------------------------------------------------------------------------+
  |                             Message Transfer Protocol (MTP)                                |
  +--------------------------------------------------------------------------------------------+
```

SiFT v0.7 messages are carried by the Message Transfer Protocol (MTP), which provides cryptographic protection to them. Messages are encrypted, their integrity is protected, and sequence numbers are used to detect replay attacks. The MTP uses symmetric key cryptographic primitives, which require shared secret keys dynamically established between the client and the server during the Init Protocol. 

The Init Protocol is used to establish a standard shared secret meant to replace the previously used static key. The Login Protocol is used to authenticate the client to the server via a username / password mechanism right after the establishment of a connection between them. After the Login Protocol, the Commands Protocol is used to send file commands of the client to the server and responses to those commands. Moreover, the upload command is followed by the execution of the Upload Protocol, which is responsible for the actual upload of the selected file to the server, and the download command is followed by the execution of the Download Protocol, which is responsible for the actual download of the selected file from the server. All messages of the Login, Commands, Upload, and Download Protocols are cryptographically protected by MTP.

## SiFT v0.7 Message Transfer Protocol 

The SiFT v0.7 Message Transfer Protocol (MTP) uses cryptography to encrypt SiFT messages (i.e., commands and their arguments sent by the client to the server and the server's responses to them, as well as the files that are uploaded to or downloaded from the server), to protect their integrity, and to ensure their authenticity. MTP also uses sequence numbering of messages to protect against replay attacks. 

More specifically, SiFT v0.7 MTP uses AES in GCM mode, which provides encryption, integrity protection, and origin authentication of MTP messages. The AES-GCM authentication tag covers all MTP message header fields and the encrypted payload. The header contains a message sequence number explicitly. 

While initially, the 256-bit key is initialized to contain 32 `00` bytes (a static all-zero key), this is changed after the completion of the Init Protocol, which returns and passes the freshly derived 32-byte key to the server and client on their respective ends. The server and client must then pass this new session key to the Message Transfer Protocol before the beginning of subsequent protocols. Thus, before the Login Protocol begins, the client and the server will have run the handshake described below by the Init Protocol, which establishes a fresh session key that replaces the static key, and the Message Transfer Protocol will have receieved this new key, and will then use it for the encryption of the Login Protocol and all further protocols.

### Message formats

SiFT v0.7 MTP messages have the following format:

```
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|  ver  |  typ  |  len  |  sqn  |          rnd          |  rsv  |
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|                                                               |
	+                                                               +
	|                                                               |
	.                                                               .
	.                    encrypted payload (epd)                    .
	.                                                               .
	|                                                               |
	+                                                               +
	|                                                               |
	+               +---+---+---+---+---+---+---+---+---+---+---+---+
	|               |                      mac                      |
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

SiFT v0.7 MTP messages have a 16-byte header that consists of the following fields:

- __ver__: A 2-byte _version number_ field, where the first byte is the major version (i.e., 0 in case of v0.7) and the second byte is the minor version (i.e., 7 in case of v0.7). This means that messages conforming this specification must start with the byte sequence `00 07`.
- __typ__: A 2-byte _message type_ field that specifies the type of the payload in the message. The following message types are supported by SiFT v0.6:
	- `00 00` : _login_req_ (login request)
	- `00 10` : _login_res_ (login response)
	- `01 00` : _command_req_ (command request)
	- `01 10` : _command_res_ (command response)
	- `02 00` : _upload_req_0_ (upload request containing a file fragment)
	- `02 01` : _upload_req_1_ (upload request containing the last file fragment)
	- `02 10` : _upload_res_ (upload response)
	- `03 00` : _dnload_req_ (download request)
	- `03 10` : _dnload_res_0_ (download response containing a file fragment)
	- `03 11` : _dnload_res_1_ (download response containing the last file fragment)
  - `04 00` : _init_req_0 (initializtion request 0, sending client public key and ID)
  - `04 01` : _init_req_1 (initialization request 1, verifying shared message integrity and shared secret establishment)
  - `04 10` : _init_res_0 (initialization response 0, receiving server public key and ID)
  - `04 11` : _init_res_1 (initialization response 1, verifying shared message integrity and shared secret establishment)
- __len__: A 2-byte _message length_ field that contains the length of the entire message (including the header) in bytes (using big endian byte order).
- __sqn__: A 2-byte _message sequence number_ field that contains the sequence number of this message (using big endian byte order).
- __rnd__: A 6-byte _random_ field that contains freshly generated random bytes.
- __rsv__: A 2-byte _reserved_ field which is not used in this version of the protocol (reserved for future versions). The value of this field in messages conforming this specification should be `00 00`.

The values for the message types are defined according to the following concept:
- The first byte encodes the type of the interaction between the client and the server (i.e., `00` for login, `01` for commands, `02` for upload, `03` for download, and `04` for initialization).
- The first nibble of the second byte specifies whether the message is a request (i.e., a message sent from the client to the server) or a response (i.e., a message sent from the server to the client). Requests always have `0`, whereas responses always have `1` in this nibble.
- The second nibble of the second byte differentiates sub-types of a given message type. This is relevant for the Init Protocol requests and responses, for the different stages of the handshake, and then later for the for upload request and download response messages. For upload and download, files are uploaded to and downloaded from the server in fragments and sub-types are used to indicate if a message contains a fragment that will be followed by other fragments (value `0`) or the last fragment of the file (value `1`), which will not be followed by further fragments. 

The header is followed by the AES-GCM enrcrypted payload (__epd__) and the AES-GCM authentication tag (__mac__). The mac field in this version of the protocol must be 12 bytes long. 

### Processing

When a TCP connection is established by the client to the server (serving clients on TCP port 5150), the first message the client must send is a initialization request_0 (type `04 00`) message, to begin the shared secret establishment handshake (detailed further below in the Init Protocol). The server must respond with an initialization response_0 (type `04 10`), to which the client must send an initialization request_1 (type `04 01`). Finally, the server must send an initialization response_1 (type `04 11`), after which the session key has been derived, and must be shared with the MTP. Subsequently, a login request (type `00 00`) message is sent and, in case of successful authentication, the server must respond with a login response (type `00 10`) message. After the login exchange, the client sends command requests (type `01 00`) and the server responds with command responses (type `01 10`).

For building the MTP message that carries the login request, the client generates a fresh 6-byte random value r and it fills in the message header fields as follows:
- ver = `00 07`
- typ = `00 00`
- len is calculated as the sum of the length of the header (16), the length of the encrypted payload (same as the length of the payload), and the length of the mac field (12)
- sqn = `00 01` (i.e., message sequence numbering is started from 1) 
- rnd = r (i.e., the 6-byte fresh random value generated before)
- rsv = `00 00`

The client then encrypts the payload of the login request and produces an authentication tag on the message header and the encrypted payload using AES in GCM mode with the static all-zero key and the nonce sqn+rnd (here + means concatenation of byte strings). The MTP message carrying the login request is formed by concatenating the 16-byte message header, the encrypted payload (epd), and the authentication tag (mac).

When the server recieves the login request message, it checks the sequence number sqn in the header. Then it verifies the mac and decrypts the epd field using AES in GCM mode with the static all-zero key and the nonce sqn+rnd (obtained from the message header). The decrypted payload of the login request contains data (username and password) that allows the authentication of the client to the server.

For building the MTP message that carries the login response, the server generates a fresh 6-byte random value r' using a cryptographic random number generator. It fills in the message header fields as follows:
- ver = `00 07`
- typ = `00 10`
- len is calculated as the sum of the length of the header (16), the length of the encrypted payload (same as the length of the payload), and the length of the mac field (12)
- sqn = `00 01` (i.e., this is the first message from the server to the client) 
- rnd = r' (i.e., the 6-byte fresh random value generated before)
- rsv = `00 00`

The server then encrypts the payload of the login response and produces an authentication tag on the message header and the encrypted payload using AES in GCM mode with the static all-zero key and the nonce sqn+rnd. The MTP message carrying the login response is formed by concatenating the 16-byte message header, the encrypted payload (epd), and the authentication tag (mac).

All subsequent MTP messages are produced in the same way as described above: 
- the message header is produced with the appropriate message type (depending on the payload to be sent), the appropriate length, the next sending sequence number, and a fresh 6-byte random value, 
- the encrypted payload and the mac fields are produced by processing the message header and the payload with AES in GCM mode using the the static all-zero key and the nonce sqn+rnd,
- the message is sent and the inceremented sending sequence number is stored (as the sequence number of the last message sent).

When such an MTP message is received, the receiving party 
- verifies if the sequence number sqn in the message is larger than the last received sequence number, 
- verifies the mac and decrypts the encrypted payload with AES in GCM mode using the static all-zero key and the nonce sqn+rnd, and
- if all verifications are successful, the stored receiving sequence number is set to the sqn value received in the message header.

A message that does not pass all verifications must be silently discarded (no error message is sent in the MTP protocol) and the connection between the client and the server must be closed. Closing the connection is initiated by the receiving party that encountered the offending message.

# SiFT v0.7 Init Protocols

Shared Secret Establishment, Technical Specifics (see step-by-step for specifications on when to drop the connection)
The server holds a long-term Eliptical Curve Cryptography ECC P-256 key pair (S_PK, S_SK). The client should generate a fresh ephemeral P-256 key pair (C_PK, C_SK) and a random 8-byte client ID (C_ID) for every session. The client opens with init request 0, which carries the DER-encoded C_PK followed by C_ID, sent inside an MTP message protected by the zero key.
The server should then import C_PK, create a random 8-byte server ID (S_ID), and reply with init response 0. Its payload is C_ID, S_PK, (C_ID | S_PK) signed by ECDSA with P-256 curve (DSS, SHA256), followed by S_ID, encrypted to C_PK with HPKE and AES-256-GCM. It is sent as the 65-byte HPKE encapsulated key followed by the ciphertext. The client decrypts it with C_SK, verifies the signature of (C_ID | S_PK) with S_PK, and recovers S_PK and S_ID. The client then computes the SHA-256 hash of S_PK, shows its hex digest to the user, and asks for a y or n answer. Any answer other than y or n, and any n, aborts the session. On y, the client continues with the key derivation below and sends init request 1, which carries the SHA256 hash of req_0 updated with the derived shared secret, encrypted with S_PK using HPKE and AES-256-GCM, again as encapsulated key plus ciphertext. The server decrypts it with S_SK, derives the secret on its own, and compares the hash of its received messages from the client updated with its derived secret. The server then compiles a SHA256 hash of its pre-public key encryption res_0, updated with its calculation of the shared secret, and sends this message encrypted with C_PK using HPKE and AES-256-GCM to the client, who then verifies against their SHA256 hash.

Key Derivation and Switch, Technical Specifics
Both sides should run ECDH on P-256 and feed the result into HKDF-SHA256 to produce a 32-byte key. The salt is SHA-256(C_ID | S_ID) and the context string is sift session key. This key is the session key that is meant to replace the static zero key. The MTP message format does not change, since the header still carries the sequence number and the random value that form the GCM nonce, and only the key differs. The sequence number restarts at the beginning of the session and increases with every message, which provides replay detection.

Server Signature
To authenticate the identity of the server, the server signs the session C_ID, to ensure freshness and active communication with the server, and the S_PK, to verify the veracity of the communicated S_PK. This uses ECDSA signature generation on P-256 curve.

Requirements and Security Considerations
The client key pair and both IDs must be fresh for every session, so no session key is ever reused. Both sides must use the same public-key scheme (ECC P-256 with HPKE and AES-256-GCM) for the encrypted handshake messages. While the server verifies its identity with a freshly signed S_PK, verified by the accompanying signed C_ID, there is no such verification of the client. Furthermore, a necessary security consideration is the ability of a malicious attacker to continually create new, valid connections to the server and, across sessions, brute-force username and password combinations. Further, due to the establishment of a standing server PK, if this PK is breached, forward secrecy is not guarenteed. However, this protocol defends against malicious listeners and meet in the middle attacks through its use of public key encryption for both parties, the requirement of a freshly-signed server hash of its S_PK, and its final verification of the hashes of sent and received messages before the initiation of any further protocols or transfer of sensitive information.

A detailed explanation of each step of the protocol is presented below:

Firstly, upon connection to the server, the client generates its new ephemeral public/private key pair (with the specifications stated above) and also generates an 8-byte Client Session ID with a cryptographic random number generator (referred to as Client ID or C_ID). The client then sends the only cleartext message of the protocol, the concatenation of the client's public key and client session ID. This message is then the first update to the client's SHA256 hash of its sent/outgoing messages, to ensure symmetry between the messages the client sends to the server entity and the messages that server receives, and vice-versa.

Client (req_0) --> Client_Public_Key | Client_ID

Upon receiving this message, the server makes its first update to its SHA256 hash of received/incoming messages. The server then imports the ECC public key of the client and C_ID, and creates its own randomly generated 8-byte Server Session ID (S_ID). The server then uses the Client Public Key to encrypt all following messages before the establishment and derivation of the shared session key, as a procaution against active listening during session key establishment and against middleman attacks. This public key encryption is performed with Hybrid Public Key Encryption, HPKE, using an AEAD mode of AES-256 in GCM mode (HPKE.AEAD.AES256_GCM). With the HPKE encryptor instantialized with the C_PK, a secure signature is then established to verify the authenticity of the server's public key hash value, and its freshness, to prevent against server impersonation. This secure signature uses ECDSA:
A message consisting of the C_ID and the Server's Public Key is created, then hashed with SHA256 and given to an ECDSA signer object, using `fips-186-3`, for the hash to be signed. The session-specific Client ID is signed alongside the Server Public Key to ensure session freshness and prevent injection attacks. The outgoing message to the client is then created by the concatenation of the client ID, the server public key, the signature, and the server's session ID. This message is added to the server's SHA256 hash of its outgoing messsages. Then, using HPKE, this entire message is then encrypted with the client's public key and sent to the client.

Server (res_0) --> ClientPublicKeyEncryption [C_ID | server PK  | Signature (C_ID | S_PK) | S_ID]

The Client then receives this message and decrypts with its private key via the same HPKE standards. It adds this decrypted message to its SHA256 hash of received messages, then attempts to validate the received signature. As the signed message of C_ID + S_PK is contained at the beginning of the received message, it alongside the received signature is given to an appropriate signature verification function, once which uses the same ECDSA signature specifications for the DSS verifier (`fips-186-3`) and SHA256 hashing. If this verification fails, the connection is to be dropped immediately. If the verification succeeds, the hex value of the SHA256 hash of the S_PK is then calculated and presented via UI to the user to manually verify with a Y/N statement, accepting "y","Y","n, and "N". If the user rejects this hash, the connection is to be immediately dropped. If accepted, the client then begins the derivation of the session key based on the previously communicated information. A key derivation function is created using a 16-byte salt consisting of the SHA256 hash of the concatenated C_ID + S_ID, and an HMAC-based key derivation function HKDF to derive a new 32 byte key (using SHA256, the salt, and the context bytes of "sift session key"). This KDF is then used in an ECC Diffie-Hellman key agreement function to derive the session key using the client's emphemeral private key and the server's static public key. The client's outgoing message hash, containing req_0, is updated with this new session key, and this hash value is encrypted with the server's public key via HPKE, using the same specifications as before. This hash message represents the last message sent by the client in the Init Protocol, and will serve as a dual confirmation that 1, the server has receieved all the outgoing client messages without modification, verifying integrity, and 2, that the server has correctly derived the same session key on its end. As Diffie-Hellmen protocols function, the session key is never sent across the channel, and is instead independently derived by both parties. 

Client (req_1) --> ServerPublicKeyEncryption [hash of req_0 and session key]

Finally, when the server receives this message, it completes its own computation of the session key, using the same logic as above. The KDF uses HKDF with SHA256, the 16-byte salt of the concatenated C_ID + S_ID, and context bytes of "sift session key". An ECC key agreement function, using the static server private key, the ephemeral client public key, and the KDF, derives the 32-byte session key. This session key is added to the SHA256 hash of the req_0 message received by the client, and then compared against the hash received in the req_1 message. If the hashes do not match, the connection is dropped. If the hashes match, the server then adds the shared secret to its own SHA256 hash of its sent messages, the pre-encryption res_0. This hash is then HPKE encrypted with the client's public key for a final time, then sent to the client for verification. Finally, the Init Protocol sends this session key to the Server, who passes it to the MTP before the beginning of the Login Protocol.

Server (res_1) --> ClientPublicKeyEncryption[hash of (C_ID | server PK  | Signature (C_ID | S_PK) | S_ID) and session key]

Finally, the client receives this hash, HPKE decrypts for a final time with its ephemeral private key, and verifies this hash against the hash of the decrypted res_0 updated with the session key. If these hashes do not match, the connection is dropped. Otherwise, the Init Protocol sends this session key to the Client, who passes it to the MTP before the beginning of the Login Protocol.

## SiFT v0.7 Login, Commands, Upload and Download Protocols

All other protocols (Login, Commands, Upload and Download) are the same as in SiFT v0.6.

## Examples
The following examples illustrate a sequence of messages sent and received by the client and the server when using the protocols specified in this document. These examples complement the specification above and hopefully help understanding and implementing the protocols of SiFT v0.7.

### Login Protocol
The following is an example for a login request message, when a user with username 'alice' and password 'aaa' is logging in: 

```
alice\n
aaa
```

This login request payload may be carried by the following MTP message (byte string printed in hex format, arranged in lines, and tagged with the field names (and field sizes), but in implementations this should be a continuous sequence of bytes):

```
HDR (16): 000600000025000175d5e3d168820000
EPD  (9): 6950b60dcfb68a02cb
MAC (12): 122fcbde0bd1e7379a455629
```

The following is an example for the corresponding login response message:

```
f76fc58d4ed409c8c1a890a8faaaf51e810d8e4795dcf54c62a09d29eecc114f
```

This hexadecimal number is the SHA-256 hash of the login request (converted to a byte string) in hex format represented as a string.

This login response payload may be carried by the following MTP message (byte string printed in hex format, arranged in lines, and tagged with the field names (and field sizes), but in implementations this should be a continuous sequence of bytes):

```
HDR (16): 00060010005c00015b9acfabc2750000
EPD (64): 575a98837ba2d9e3f4b74e41dc8446a0
          362f3663da53def6c021d7d593b4119a
          6730f09acb8ff7e8f156689bf37dd572
          5cbe5015f758c2b4b89353be87543c57
MAC (12): f69a652676c007e671a3fccf
```

### Commands Protocol
Example for a command request, when the user changes to directory `testdir`:

```
chd\n
testdir
```

and its corresponding command response:

```
chd\n
919963f263c2d6889fb91f9fea17abc5f11aa112b9a46a71c3e179ae43c617d3\n
success
```

The command response contains the command (chd) and the SHA-256 hash of the command request above. The operation was successful.

The following is an example for a command request:

```
chd\n
test2
```

that failed:

```
chd\n
59124f965c19a8de84e96bc4dc7445efe085cc98097e9887641ba5691289a499\n
failure\n
Directory does not exist
```

The following is an example for a command request, when the user wants to know the current working directory:

```
pwd
```

and its corresponding command response:

```
pwd\n
a1159e9df3670d549d04524532629f5477ceb7deec9b45e47e8c009506ecb2c8\n
success\n
testdir/
```

So the user is in the directory `testdir`, where he/she can list the directory content by sending the following command request:

```
lst
```

and he/she receives the following command response:

```
lst\n
274088a0cde8b724153ed9396a946299f10c19c6cf593a19ce57c52580a32dcb\n
success\n
dGVzdF8xLnR4dA==
```

In the response, the directory listing is encoded in Base64. After decoding, we would get `test_1.txt` (i.e., the directory `testdir` contains a single file called `test_1.txt`).

All these command request and command response messages are carried in MTP messages. E.g., the command responses above is carried by the following MTP message (byte string printed in hex format, arranged in lines, and tagged with the field names (and field sizes)):

```
HDR (16): 0006011000790007d1a9a5820f420000
EPD (93): 13d824170a5bdf0f59f0d56e76db83c7
          06a7334184b952d13ff7334de26ac0e6
          7fe497e9bcec955737307db77ef6d5ad
          e269603ceb51837172f710cf3c5494e2
          b1e3f029ab0fba5d73250c516b83cfb6
          c3dfcaeca04fd33db0d3fe4c2f
MAC (12): 03aae49f2d9d6564858ec6a4
```

### Example for an upload 
The following is an example for an __upl__ command request, when the user wants to upload a file named `test_2.txt` with size 2350 bytes and hash value `b1a8b752...`:

```
upl\n
test_2.txt\n
2350\n
b1a8b752fef9179e7691cf63104ebb913bbbc1b55040af3b379ab3608ff1881b
```

This may be carried in the following MTP message:

```
HDR (16): 000601000070000a1578804f0cae0000
EPD (84): 5eedc2b5d0f01c9979f6ae6513088988
          4d8772e3d1bf45efd8dcbea6c4982c7b
          2fe1e9ae1dd7dd01ef3b0368893b0f83
          b46b481851ca25fb42c7a41ebef5979b
          741ff17c7188df7f0788c35ef12c88ae
          e6c5ba2c
MAC (12): 4bd55864c3437ca3e1b996a6
```

The corresponding __upl__ command response is:

```
upl\n
3ca3dbad248f619e6388d5ec32f8ffe38921291fe08ef2d284c5e432392d31a7\n
accept
```

and its MTP message is:

```
HDR (16): 00060110006700087959a8c6b38e0000
EPD (75): 2129303978818cab3cd3a67e40bd988d
          5766d1bcb671a96c6f0c2da0c794060b
          f70d8fa36924d35836ba58be9904242d
          cf66e0b8384b233a25258745fae93263
          12086d3bb250e4d3f08fdd
MAC (12): a592f2a3a4be3a1281899dd2
```

Then the file is uploaded in 1024-byte fragments by the Upload Protocol. The last fragment (302 bytes) is the following:

```
eam, believes the group only cooperates with the creators of Flame and Stuxnet from a position of superiority: "Equation Group are definitely the masters, and they are giving the others, maybe, bread crumbs. From time to time they are giving them some goodies to integrate into Stuxnet and Flame."[11]\n
```

and it is carried in the following MTP message:

```
HDR  (16): 00060201014a000de361564cb1040000
EPD (302): 287a517107485f9e26b5734bc775842c
           610bec3556f1e6e9cc1f5da4e650b935
           29ad857d36b3e0796831aac0c370d258
           85da9fc74fcd365fcd33f476f4d84523
           e29f073e579b236206abd988bac4deb6
           1ff68e679b3be01de88dde916c2f93ad
           50e880140b8eea5d67c58e87a0021076
           b4bbf67004fe4a30b9fde227566948cd 
           ... 
MAC  (12): daaaec671b9a86f586b3ced7
```

With this, the upload is complete, and the server sends an upload response message:

```
b1a8b752fef9179e7691cf63104ebb913bbbc1b55040af3b379ab3608ff1881b\n
2350
```

and  it is carried in the following MTP message:

```
HDR (16): 0006021000610009272bca1806070000
EPD (69): 9f5d1438f6dbb8f571dc1f35f5dec178
          7f77a60a698f258ff36b10e8375fde56
          5ecb3f8caf6680737fd3dd6a8212fe04
          835d2c092ed6af8c5927c0b0e29b98ca
          56a1477b8a
MAC (12): 6c6e9c8e85a2fd7766427ee7
```

### Example for a download 
The following is an example for a __dnl__ command request, when the user wants to download a file named `test_2.txt`:

```
dnl\n
test_2.txt
```

and its corresponding __dnl__ command response:

```
dnl\n
e0c810c0b393712e6438eec29b7fbf88f960fdd229da193e9d139099b6c58f58\n
accept\n
2350\n
b1a8b752fef9179e7691cf63104ebb913bbbc1b55040af3b379ab3608ff1881b
```

If the user wants to proceed, then the following download request is sent:

```
ready
```

the MTP message of which is:

```
HDR (16): 000603000021000f3be07fa0c1db0000
EPD  (5): 6481c166cb
MAC (12): 06f212d63a967aa3d8098834
```

The file is then downloaded by the Download Protocol. The MTP message of the last fragement (of size 302 bytes) is the following:

```
HDR  (16): 00060311014a000dd8d629177d940000
EPD (302): 42830f6c65ce2b09dfe24f2f1692f551
           95d5f171fc5ec2556d29930853a2b26c
           66420d425a48be38b8689d01c78ebc8b
           d6638d1ac62dde6c7335a6acb36130d9
           216fae388175fcd3e48eb9b0bcdbcd73
           ffcb466f2e3c819ab4dcfa04a2287190
           ea67e5aefcb8df9e1745cc958727544c
           7177af4248008ecfd305536cfc031c70 
           ...
MAC  (12): af0daa3ad9804ac3f92f943a
```
