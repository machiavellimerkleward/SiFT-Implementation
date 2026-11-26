Here are the specifications for the Init Protocol!

The goal of this project assignment is to extend your existing SiFT v0.6 protocol with a new sub-protocol called Init Protocol, the main responsibilities of which are: 

(i) the establishment of a fresh shared secret between the client and server
(ii) the derivation of a 32-byte AES key from the shared secret
(iii) the passing of the derived key to the MTP sub-protocol, which should then replace its initial static key with this freshly derived key.

TODO:
- define byte sizes of all subsequently mentioned variables
- modify MTP message types so that the server knows whether a message is an INIT message or not

(i) is accomplished through a standard shared secret establishment protocol. 
- Assume initial 32-byte key of zeros, for the transfer of initial information encoded with public keys for the session key establishment
- Client creates new emphemeral public/private key pair (and possible entity ID?)
- Client sends establishing information to Server
    - Encrypted with the Server PK, the client sends their public key to the server (alongside their ID number?)
- Server receives Client information and sends its own establishing information to Client
    - Server creates a fresh session ID number
    - The server uses this public key to encrypt its own public key and ID, then sends this info over (?)
- Client verifies Server authenticity
    - Client (decodes) the public key of the server and computes its SHA256 hash value
    - Client provides PK hash to user to inspect, option to continue if accepted or kill connection if rejected
- Client and Server then establish their shared secret
    - Client selects random x and computes [math formula]
    - Client sends the S_PK encrypted (ID, client-half of math formula)
    - Server selects random y and computes [math formula]
    - Server sends the C_PK encrypted (SID, server-half of math formula, KDF salting numbers) -- ask!
    - With both halves, each party computes s, the shared secret for the session

(ii) Key Derivation
- With both parties knowing s, both Server and Client then use this shared secret to derive a fresh key, via the shared KDF salting numbers, to be used throughout the session as the session key
    - As both parties share s and KDFn, they both then use these inputs into the same key derivation function (HKDF), and derive the session key
- Both Server and Client then replace their preexisting static 32-bit keys with the base keys


- Before continuing to login protocol, the HMAC of the protocol's messages is sent to verify message integrity and lack of injections -- this is done by Server encrypting its history with the derived key(?) and sending it to Client, who verifies the hash against their own, then sends their encrypted log to the Server, who finally verifies it against their own hash.
- If this operation succeeds, it is OK for user to continue to Login Protocol


Specifics:
- A strong shared secret is used between the parties (DH?)
- From this strong shared secret, the key is derived via a secure key derivation function (HKDF)
- Key derivation requires the communication of the correct pseudorandom extrator salting numbers
- The session key is never used alone, but rather is always salted with random numbers, communicated in the header
- Before a shared secret key is established, each message is encrypted as before, with a static zero key and its random numbers
- Thus, the MTP does not need to be modified (??)

Requirements (to be implemented):
- Replay detection -- implemented?
- Freshness
- Session keys should be deleted if the session fails
- Both server and client must use a consistent type of public key encryption/decryption (!!!)

Security Concerns:
- Due to the establishment of a standing server PK, if this PK is breached, forward secrecy is not guarenteed

(iii)
- After the completion of the shared secret establishment and key derivation, this information is sent to the MTP

Questions:
- where/how should the shared secret be established
- how to do public/private keypair generation for the two parties?
- the client should generate a new key with every new instance? 
- the server will have a longstanding PK accessed via an encrypted file and a passcode
- how to make an encrypted file in such a way? existing formatting or by ourselves?