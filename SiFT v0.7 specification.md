Here are the specifications for the Init Protocol!

The goal of this project assignment is to extend your existing SiFT v0.6 protocol with a new sub-protocol called Init Protocol, the main responsibilities of which are: 

(i) the establishment of a fresh shared secret between the client and server
(ii) the derivation of a 32-byte AES key from the shared secret
(iii) the passing of the derived key to the MTP sub-protocol, which should then replace its initial static key with this freshly derived key.

(i) is accomplished through a standard shared secret establishment protocol. 
- Client creates new emphemeral public/private key pair
- The client sends their public key to the server 
- The server uses this public key to encrypt its own public key, then sends this info over (????)
- Client (decodes) the public key of the server and computes its SHA256 has value
- Client provides PK hash to user to inspect, option to continue if accepted or kill connection if rejected
- Client and Server then establish their shared secret (somehow!)
- Before continuing to login protocol, the HMAC of the protocol's messages is sent to verify message integrity and lack of injections -- this is done by Server encrypting its history with the derived key(?) and sending it to Client, who verifies the hash against their own, then sends their encrypted log to the Server, who finally verifies it against their own hash.
- If this operation succeeds, it is OK for user to continue to Login Protocol
- Before Login Protocol begins, a shared secret is established between the two parties (somehow, possibly earlier)

Specifics:
- A strong shared secret is used between the parties (DH?)
- From this strong shared secret, the key is derived via a secure key derivation function (HKDF?)
- Key derivation requires the communication of the correct pseudorandom extrator salting numbers

Requirements (to be implemented):
- Replay detection -- implemented?
- Freshness
- Session keys should be deleted if the session fails

(ii)
- Both server and client then use this shared secret to derive a fresh key to be used throughout the session, and every message has a differently salted key, 
- Or is it that the key is consistent, but the salting is what keeps it fresh? -- Yes
- Replace their preexisting static 32-bit keys with the base keys
- Key derivation 

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