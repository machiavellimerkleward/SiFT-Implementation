from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF

from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error


class SiFT_INIT_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg


class SiFT_INIT:
    def __init__(self, mtp):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        # --------- STATE ------------
        self.mtp = mtp
        self.id_size = 8 #TODO check


# TODO QUESTIONS!
    # Ask where to verify sesson entity ID and ask about size
    # What is the rsv field in the MTP? is it used in this version?
    # Should the Client make its first request an ask for the Server's PK, then encrypt ALL subsequent info with it, instead of sending over its PK,ID immediately?
    # Ask about 


    # TODO create/import helper functions
    # TODO figure out how to verify the session ID information throughout

    def generate_ephemeral_keypair(self):
        key = ECC.generate(curve='P-256')
        public_k = key.public_key().export_key(format="DER")
        return key, public_k

    def replace_session_key():
        # new_key = --> the derived session key, already in another method
        return new_key
        
    # First message to the server -- sends Client public key and Client session ID
    def build_init_req(self, public_k, entity_ID):
        parsed_req, i = {}, 0
        #  Should not be a struct, but a combination of bytes



        # init_req_struct = {}
        # init_req_struct['Client_PubK'] = public_k
        # init_req_struct['Client_Session_ID'] = entity_ID
        # init_req_str = init_req_struct['Client_PubK']
        # init_req_str += self.delimiter + init_req_struct['Client_Session_ID'] 
        # return init_req_str.encode(self.coding)

    # def parse_init_req_1(self):
    #     init_req_fields = init_req.decode(self.coding).split(self.delimiter)
    #     init_req_struct = {}
    #     init_req_struct['Client_PubK'] = init_req_fields[0]
    #     init_req_struct['Client_Session_ID'] = init_req_fields[1]
    #     return init_req_struct

    def build_init_res(self):
        return

    def parse_init_res(self):
        return 

    def initiate_session_server(self):

        #TODO - save every received message body into a long running string, then take its hash at the very end

        # Try to receive Initialization Request
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to receive initialization request --> ' + e.err_msg)
            #TODO is this the correct type of error? 

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))])
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_init_req_0:
            raise SiFT_INIT_Error('Initialization request expected, but received something else')

        

        # Process Initialization Request
        entity_ID = get_random_bytes(self.id_size)
        
        # return new_key # ?

    def initiate_session_client(self):
        #TODO - save every received message body into a long running string, then take its hash at the very end

        # Initialize Ephemeral Key Information
        private_key, public_key = self.generate_ephemeral_keypair()
        entity_ID = get_random_bytes(self.id_size)

        
        # IF requesting server PK immediately
        # try:
        #     self.mtp.send_msg(self.mtp.type_init_req_0, public_k)
        # except SiFT_MTP_Error as e:
        #     raise SiFT_INIT_Error('Unable to send PK request --> ' + e.err_msg)

        # Build an Initialization Request
        msg_payload = public_key + entity_ID
        # Send PK and ID to the server
        try:
            self.mtp.send_msg(self.mtp.type_init_req_0, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to send PK1 request --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print(msg_payload[:max(512, len(msg_payload))])
            print('------------------------------------------')
        # DEBUG 

        # Receive server PK and ID
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to receive Server PK1 response --> ' + e.err_msg)

        # TODO raise error if it's the wrong message type

        server_pk = ECC.import_key(msg_payload)
        



        
        # self.mtp.
        # return new_key # ?