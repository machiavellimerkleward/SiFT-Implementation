from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error
from Crypto.Random import get_random_bytes


class SiFT_INIT_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg


class SiFT_INIT:
    def __init__(self, mtp):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
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

    def replace_session_key():
        # new_key = --> the derived session key, already in another method
        return new_key
        

    def build_init_req_1(self, public_k, entity_ID):
        init_req_struct = {}
        init_req_struct['Client_PubK'] = public_k
        init_req_struct['Client_Session_ID'] = entity_ID
        init_req_str = init_req_struct['Client_PubK']
        init_req_str += self.delimiter + init_req_struct['Client_Session_ID'] 
        return init_req_str.encode(self.coding)

    def parse_init_req_1(self, init_req):
        init_req_fields = init_req.decode(self.coding).split(self.delimiter)
        init_req_struct = {}
        init_req_struct['Client_PubK'] = init_req_fields[0]
        init_req_struct['Client_Session_ID'] = init_req_fields[1]
        return init_req_struct

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
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_init_req_0:
            raise SiFT_INIT_Error('Initialization request expected, but received something else')

        

        # Process Initialization Request
        entity_ID = get_random_bytes(self.id_size)
        
        return new_key # ?

    def initiate_session_client(self):
        #TODO - save every received message body into a long running string, then take its hash at the very end

        # Initialize Ephemeral Key Information
        # private_k, public_k = create_ephemeral_key()
        entity_ID = get_random_bytes(self.id_size)

        # Build an Initialization Request
        
        # IF requesting server PK immediately
        # try:
        #     self.mtp.send_msg(self.mtp.type_init_req_0, public_k)
        # except SiFT_MTP_Error as e:
        #     raise SiFT_INIT_Error('Unable to send PK request --> ' + e.err_msg)

        
        msg_payload = self.build_init_req_1(public_k=0, entity_ID=entity_ID)
        try:
            self.mtp.send_msg(self.mtp.type_init_req_1, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_INIT_Error('Unable to send PK request --> ' + e.err_msg)

        # Try to send Initialization Request

        
        self.mtp.
        return new_key # ?