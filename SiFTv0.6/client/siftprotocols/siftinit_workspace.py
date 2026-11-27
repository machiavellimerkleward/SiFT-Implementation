#ECDH new imports
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF

#TODO ask about secure syntax 
# generates a key
def make_key():
    key = ECC.generate(curve='P-256')
    public_k = key.public_key().export_key(format="DER")
    return key, public_k

#TODO  key derivation example function

def derive_key(private_key, public_key, client_public, server_public):
    salt = SHA256.new(client_public + server_public).digest()
    
    def kdf(secret):
        return HKDF(secret, 32, salt, SHA256, context="sift session key")
    
    return key_agreement(
        static_priv=private_key,
        static_pub=ECC.import_key(public_key),
        kdf=kdf
    )

with open("private.pem", "wt") as f:
    f.write(key.export_key(format="PEM", passphrase="ait-budapest"))