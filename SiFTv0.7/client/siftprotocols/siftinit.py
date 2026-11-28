from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Signature import DSS
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol import HPKE
from Crypto.Protocol.KDF import HKDF

from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error

class SiFT_INIT_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg


class SiFT_INIT:
    def __init__(self, mtp):

        self.DEBUG = False
        # --------- CONSTANTS ------------
        self.id_size = 8
        self.enc_size = 65
        self.signature_size = 64
        self.coding = 'utf-8'
        # --------- STATE ------------
        self.mtp = mtp
        self.client_outgoing_msg_h = SHA256.new()
        self.client_incoming_msg_h = SHA256.new()
        self.server_public_key = None
        self.server_ID = None
        self.client_public_key = None
        self.client_private_key = None
        self.client_ID = None


    # Signs the SHA256 hash value of the server public key with its private key for exporting
    def signature(self, server_public_key, server_private_key, client_ID): 
        msg = client_ID + server_public_key

        h = SHA256.new()
        h.update(msg)

        signer = DSS.new(server_private_key, 'fips-186-3') # according to the FIPS 186-3 standard, the resulting signature will be randomized
        signature = signer.sign(h)
        return signature

    # Uses the server's public key to validate a given message and signature
    def signature_validation(self, msg, signature, serv_pub_key): 
        h = SHA256.new()
        h.update(msg)

        verifier = DSS.new(serv_pub_key, 'fips-186-3')

        try:
            verifier.verify(h, signature)
        except ValueError:
            raise SiFT_INIT_Error('Signature is invalid.')


    def generate_ephemeral_keypair(self):
        key = ECC.generate(curve='P-256')
        public_k = key.public_key().export_key(format="DER")
        return key, public_k

    def receive_user_response(self, response):
        response.encode(self.coding)
        if response == "N" or response == "n":
            raise SiFT_INIT_Error('Server public key hash has been rejected')
        elif response == "Y" or response == "y":
            return True
        else:
            raise SiFT_INIT_Error('Invalid response to y/n question')
        return False

    def derive_server_key(self, personal_priv_k, peer_pub_k, client_ID, server_ID):
        salt = SHA256.new(client_ID + server_ID).digest()
    
        def kdf(secret):
            return HKDF(secret, 32, salt, SHA256, context=b'sift session key')
    
        return key_agreement(
        static_priv=personal_priv_k,
        eph_pub=peer_pub_k,
        kdf=kdf
        )
    
    def derive_client_key(self, personal_priv_k, peer_pub_k, client_ID, server_ID):
        salt = SHA256.new(client_ID + server_ID).digest()
    
        def kdf(secret):
            return HKDF(secret, 32, salt, SHA256, context=b'sift session key')
    
        return key_agreement(
        eph_priv=personal_priv_k,
        static_pub=peer_pub_k,
        kdf=kdf
        )
    

    def initiate_session_server(self, server_public_key, server_private_key):
        server_outgoing_msg_h = SHA256.new()
        server_incoming_msg_h = SHA256.new()

        # Try to Receive Initialization Request with Client Public Key and ID
        try:
            msg_type, msg_payload_r = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to receive initialization request --> ' + e.err_msg)
        if msg_type != self.mtp.type_init_req_0:
            raise SiFT_INIT_Error('Initialization request 0 expected, but received something else')

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload_r)) + '):')
            print(msg_payload_r[:max(512, len(msg_payload_r))])
            print('------------------------------------------')
        # DEBUG 

        # Update hash of receieved messages with the first message (in cleartext)
        server_incoming_msg_h.update(msg_payload_r)
        
        # Parse client public key and client session ID
        client_public_key = ECC.import_key(msg_payload_r[:-self.id_size])
        self.client_ID = msg_payload_r[-self.id_size:]

        # Encrypt server public key and ID with received client public key, and create a signature of server public key hash + client ID to ensure freshness
        encryptor = HPKE.new(receiver_key=client_public_key,
                     aead_id=HPKE.AEAD.AES256_GCM)
        self.server_ID = get_random_bytes(self.id_size)

        signature = self.signature(server_public_key=server_public_key, server_private_key=server_private_key, client_ID=self.client_ID)

        # data = client ID + server PK  + signature (client ID + server PK) + server ID
        msg_payload_s = self.client_ID + server_public_key + signature + self.server_ID

        # Update hash of sent messages
        server_outgoing_msg_h.update(msg_payload_s)

        data = encryptor.enc + encryptor.seal(msg_payload_s)

        # Try to Send ID and Signed Public Key
        try:
            self.mtp.send_msg(self.mtp.type_init_res_0, data)
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to send PK0 response --> ' + e.err_msg)

        # Try to Receive Shared Secret Initialization Request
        try:
            msg_type, msg_payload_r = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to receive initialization request --> ' + e.err_msg)
        if msg_type != self.mtp.type_init_req_1:
            raise SiFT_INIT_Error('Initialization request 1 expected, but received something else')

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload_r)) + '):')
            print(msg_payload_r[:max(512, len(msg_payload_r))])
            print('------------------------------------------')
        # DEBUG 
        
        # Parse and decrypt received Diffie Hellman information
        data_r = msg_payload_r[self.enc_size:]
        enc_r = msg_payload_r[:self.enc_size]

        decryptor = HPKE.new(receiver_key=server_private_key,
                             aead_id=HPKE.AEAD.AES256_GCM,
                             enc=enc_r)

        data = decryptor.unseal(data_r)

        secret = self.derive_server_key(personal_priv_k=server_private_key, 
                                        peer_pub_k=client_public_key, 
                                        client_ID=self.client_ID, 
                                        server_ID= self.server_ID)

        # Update incoming hash with shared secret
        server_incoming_msg_h.update(secret)
        server_incoming_msg_h = server_incoming_msg_h.digest()

        if server_incoming_msg_h != data:
            raise SiFT_INIT_Error('Failed to establish shared secret')
        
        server_outgoing_msg_h.update(secret)
        server_outgoing_msg_h = server_outgoing_msg_h.digest()

        encryptor = HPKE.new(receiver_key=client_public_key,
                             aead_id=HPKE.AEAD.AES256_GCM)

        msg_payload_s = encryptor.enc + encryptor.seal(server_outgoing_msg_h)

        # Send Finish Message with hash of outgoing values and the shared secret
        try:
            self.mtp.send_msg(self.mtp.type_init_res_1, msg_payload_s)
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to send PK1 response --> ' + e.err_msg)
        
        
        return secret


    def pk_exchange_client(self):

        # Initialize Ephemeral Key Information
        self.client_private_key, client_public_key = self.generate_ephemeral_keypair()
        self.client_ID = get_random_bytes(self.id_size)
        self.client_private_key = self.client_private_key
        self.client_public_key = client_public_key

        # Commence Initialization Requests

        # First message to the server -- sends Client public key and Client session ID
        msg_payload_s = client_public_key + self.client_ID

        self.client_outgoing_msg_h.update(msg_payload_s)

        # Send PK and ID to the server
        try:
            self.mtp.send_msg(self.mtp.type_init_req_0, msg_payload_s)
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to send PK0 request --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print(msg_payload_s[:max(512, len(msg_payload_s))])
            print('------------------------------------------')
        # DEBUG 

        # Receive + decrypt server PK and ID
        try:
            msg_type, msg_payload_r = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to receive Server PK0 response --> ' + e.err_msg)
        if msg_type != self.mtp.type_init_res_0:
            raise SiFT_INIT_Error('Initialization response 0 expected, but received something else')


        # Decrypt message and extract server PK + client ID, fresh signature, and server ID

        data_r = msg_payload_r[self.enc_size:]
        enc = msg_payload_r[:self.enc_size]

        decryptor = HPKE.new(receiver_key=self.client_private_key,
                             aead_id=HPKE.AEAD.AES256_GCM,
                             enc=enc)

        # data = client ID + server PK  + signature (client ID + server PK) + server ID
        data = decryptor.unseal(data_r)

        self.client_incoming_msg_h.update(data)

        msg = data[:-(self.id_size+self.signature_size)]
        self.server_public_key = ECC.import_key(data[self.id_size:-(self.signature_size+self.id_size)]) # after first 8 bytes to last 64 + 8 bytes
        self.signature = data[-(self.id_size+self.signature_size):-self.id_size] # last 64 + 8 bytes to last 8 bytes
        self.server_ID = data[-self.id_size:] # last 8 bytes


        # Validate the signature computed on the client ID and server public key
        self.signature_validation(msg, self.signature, self.server_public_key)

        # Offer hash of signed + verified received server PK bytes for user to verify
        pubk_hash = SHA256.new(data[self.id_size:-(self.signature_size+self.id_size)])
        pubk_hash = pubk_hash.digest().hex()

        return pubk_hash
        

    def initiate_session_client(self, response):
        result = self.receive_user_response(response=response)
        if result != True:
            raise SiFT_INIT_Error('Hash verification unable to proceed')

        secret = self.derive_client_key(personal_priv_k=self.client_private_key, 
                                        peer_pub_k=self.server_public_key, 
                                        client_ID=self.client_ID, 
                                        server_ID=self.server_ID)

        encryptor = HPKE.new(receiver_key=self.server_public_key,
                     aead_id=HPKE.AEAD.AES256_GCM)

        enc_r = encryptor.enc

        # Update the outgoing hash with the shared secret
        self.client_outgoing_msg_h.update(secret)
        self.client_outgoing_msg_h = self.client_outgoing_msg_h.digest()

        msg_payload_s = enc_r + encryptor.seal(self.client_outgoing_msg_h)

        # Send the Finish Message with the hash of the client's outgoing message and shared secret
        try:
            self.mtp.send_msg(self.mtp.type_init_req_1, msg_payload_s)
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to send PK1 request --> ' + e.err_msg)
        

        # Receive server Finish Message with its hash of its sent message and shared secret
        try:
            msg_type, msg_payload_r = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to receive Server PK1 response --> ' + e.err_msg)
        if msg_type != self.mtp.type_init_res_1:
            raise SiFT_INIT_Error('Initialization response 1 expected, but received something else')

        data_r = msg_payload_r[self.enc_size:]
        enc = msg_payload_r[:self.enc_size]

        decryptor = HPKE.new(receiver_key=self.client_private_key,
                             aead_id=HPKE.AEAD.AES256_GCM,
                             enc=enc)

        data = decryptor.unseal(data_r)

        self.client_incoming_msg_h.update(secret)
        self.client_incoming_msg_h = self.client_incoming_msg_h.digest()

        # If the message hashes are assymetric, indicating a problem establishing the shared secret or malicious interference, quit
        if data != self.client_incoming_msg_h:
            raise SiFT_INIT_Error('Finishing message hashes do not align')
        

        return secret