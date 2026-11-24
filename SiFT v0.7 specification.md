Here are the specifications for the Init Protocol!

The goal of this project assignment is to extend your existing SiFT v0.6 protocol with a new sub-protocol called Init Protocol, the main responsibilities of which are: 

(i) the establishment of a fresh shared secret between the client and server
(ii) the derivation of a 32-byte AES key from the shared secret
(iii) the passing of the derived key to the MTP sub-protocol, which should then replace its initial static key with this freshly derived key.

(i) is accomplished through a standard shared secret establishment protocol. 
- The client sends their public key to the server 
- The server uses this public key to encrypt its own public key, then sends this info over (????)
- Client (decodes) the public key of the server and computes its SHA256 has value
- Client provides PK hash to user to inspect, option to continue if accepted or kill connection if rejected
- If this operation succeeds, it is OK for user to continue to Login Protocol
- Before Login Protocol begins, a shared secret is established between the two parties (somehow, possibly earlier)

(ii)
- Both server and client then use this key to derive a fresh key to be used in the first message - every message has a differently derived key, derived via the random numbers (?)
- Or is it that the key is consistent, but the salting is what keeps it fresh?
- Replace their preexisting static 32-bit keys with the base keys
- Key derivation 


Questions:
- where/how should the shared secret be established
- how to do public/private keypair generation for the two parties?
- the client should generate a new key with every new instance? 
- the server will have a longstanding PK accessed via an encrypted file and a passcode
- how to make an encrypted file in such a way? existing formatting or by ourselves?