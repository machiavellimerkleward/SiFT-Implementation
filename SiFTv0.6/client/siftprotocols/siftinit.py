from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
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
        self.id_size = 8 #TODO check
        self.enc_size = 65
        self.coding = 'utf-8'
        # --------- STATE ------------
        self.mtp = mtp
        self.server_key = None
        self.server_ID = None
        self.client_public_key = None
        self.client_private_key = None
        self.client_ID = None



# TODO QUESTIONS!
    # Ask where to verify sesson entity ID and ask about size
    # What is the rsv field in the MTP? is it used in this version?
    # Should the Client make its first request an ask for the Server's PK, then encrypt ALL subsequent info with it, instead of sending over its PK,ID immediately?
    # Ask about what exactly should and shouldn't be encrypted -- public keys? IDs?
    # How should the permenent server key be created/accessed? write to a file --> 
    # Is it okay to write the server key to an init variable?
    # Is the given hash value okay?


    # TODO create/import helper functions
    # TODO figure out how to verify the session ID information throughout
    # TODO gather messages into one and cross-verify message hashes

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

    def replace_session_key():
        # new_key = --> the derived session key, already in another method
        return new_key

    def inspect_init_hash():
        # TODO - compile all message bodies into a large byte object, then take the 
        return
        

    def initiate_session_server(self, server_public_key, server_private_key):

        #TODO - save every received message body into a long running string, then take its hash at the very end

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

        client_public_key = ECC.import_key(msg_payload_r[:-self.id_size])
        self.client_ID = msg_payload_r[-self.id_size:]

        # Encrypt server public key and ID with received client public key
        encryptor = HPKE.new(receiver_key=client_public_key,
                     aead_id=HPKE.AEAD.AES256_GCM)
        self.server_ID = get_random_bytes(self.id_size)

        msg_payload_s = server_public_key + self.server_ID
        data = encryptor.enc + encryptor.seal(msg_payload_s)

        # Try to Send Public Key and ID
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
        
        data_r = msg_payload_r[self.enc_size:]
        enc = msg_payload_r[:self.enc_size]

        decryptor = HPKE.new(receiver_key=server_private_key,
                             aead_id=HPKE.AEAD.AES256_GCM,
                             enc=enc)

        data = decryptor.unseal(data_r)

        secret = self.derive_server_key(personal_priv_k=server_private_key, 
                                        peer_pub_k=client_public_key, 
                                        client_ID=self.client_ID, 
                                        server_ID= self.server_ID)

        if data != secret:
            print('Failed to establish shared secret')
        

        # TODO FIX, duplicate statement
        # if msg_type != self.mtp.type_init_req_1:
            # raise SiFT_INIT_Error('Initialization request expected, but received something else')
        
        # return new_key # ?


    def pk_exchange_client(self):
        #TODO - save every received message body into a long running string, then take its hash at the very end

        # Initialize Ephemeral Key Information
        client_private_key, client_public_key = self.generate_ephemeral_keypair()
        self.client_ID = get_random_bytes(self.id_size)
        self.client_private_key = client_private_key
        self.client_public_key = client_public_key
        
        # IF requesting server PK immediately
        # try:
        #     self.mtp.send_msg(self.mtp.type_init_req_0, public_k)
        # except SiFT_MTP_Error as e:
        #     raise SiFT_INIT_Error('Unable to send PK request --> ' + e.err_msg)

        # Commence Initialization Requests

        # First message to the server -- sends Client public key and Client session ID
        msg_payload_s = client_public_key + self.client_ID

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

        # self.server_key = ECC.import_key(msg_payload_r)

        # Decrypt message and extract server PK and ID
        data_r = msg_payload_r[self.enc_size:]
        enc = msg_payload_r[:self.enc_size]

        decryptor = HPKE.new(receiver_key=client_private_key,
                             aead_id=HPKE.AEAD.AES256_GCM,
                             enc=enc)

        data = decryptor.unseal(data_r)

        self.server_key = ECC.import_key(data[:-self.id_size])
        self.server_ID = data[-self.id_size:]        

        # TODO Offer hash of server PK to user to verify

        pwdhash = SHA256.new(data[:-self.id_size])
        pwdhash = pwdhash.hexdigest()

        return pwdhash
        

    def initiate_session_client(self, response):
        result = self.receive_user_response(response=response)
        if result != True:
            raise SiFT_INIT_Error('Hash verification unable to proceed')

        secret = self.derive_client_key(personal_priv_k=self.client_private_key, 
                                        peer_pub_k=self.server_key, 
                                        client_ID=self.client_ID, 
                                        server_ID=self.server_ID)

        encryptor = HPKE.new(receiver_key=self.server_key,
                     aead_id=HPKE.AEAD.AES256_GCM)

        enc = encryptor.enc

        msg_payload_s = enc + encryptor.seal(secret)

        try:
            self.mtp.send_msg(self.mtp.type_init_req_1, msg_payload_s)
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to send PK1 request --> ' + e.err_msg)

        # Declare the shared secret and encrypt with server PK

        return

        # self.mtp.
        # return new_key # ?