from Crypto.PublicKey import ECC
from Crypto.Hash import SHAKE128
from Crypto.Protocol.DH import key_agreement

# This KDF has been agreed in advance
def kdf(x):
        return SHAKE128.new(x).read(32)

# In a real scenario, this key already exists
U = ECC.generate(curve='p256')
Upub = U.public_key()

# In a real scenario, this key is received from the peer
# and it is verified as authentic
V = ECC.generate(curve='p256')
Vpub = V.public_key()

session_key = key_agreement(static_priv=U, static_pub=Vpub, kdf=kdf)
session_2 = key_agreement(static_priv=V, static_pub=Upub, kdf=kdf)
print(session_key)
print(session_2)
