#python3

import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket, key):

		self.DEBUG = False
		# --------- CONSTANTS ------------
		self.version_major = 0
		self.version_minor = 6
		self.msg_hdr_ver = b'\x00\x06'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2

		#Jen edits-------
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.size_msg_hdr_rsv = 2
		self.size_mac_len = 12
		self.rsv = b'\x00\x00'
		self.key = key

		# initialize sqns to one
		self.sqn_s = 1
		self.sqn_r = 1
		#----------------

		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.type_init_req_0 = b'\x04\x00'
		self.type_init_res_0 = b'\x04\x10'
		self.type_init_req_1 = b'\x04\x01'
		self.type_init_res_1 = b'\x04\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1,
						  self.type_init_req_0, self.type_init_res_0,
						  self.type_init_req_1, self.type_init_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket


	def change_state_key(self, new_key):
		self.key = new_key

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len

		#jenifer edits-------------------
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'] = msg_hdr[i:i+self.size_msg_hdr_rsv]
		#---------------------------------
		
		return parsed_msg_hdr


	# receives n bytes from the peer socket
	def receive_bytes(self, n):

		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received


	# tries to receive the encrypted message, if valid, incrementing sqn
	def receive_msg(self):
		
		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		if parsed_msg_hdr['sqn'] != self.sqn_r.to_bytes(self.size_msg_hdr_sqn,"big"):
			raise SiFT_MTP_Error('Invalid sequence number')
		

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		if len(msg_body) != msg_len - self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message body reveived')


		# receives and parses message, returns msg_type and msg_payload
		# decrypts and verifies MAC using the provided nonce (in header) and MAC (final bytes)
		
		encrypted_payload = msg_body[:-self.size_mac_len]
		mac = msg_body[-self.size_mac_len:]
		nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
		cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac_len)

		try:
			cipher.update(msg_hdr)
			plaintext = cipher.decrypt_and_verify(encrypted_payload, mac)
		except (ValueError, KeyError) as e:
			raise SiFT_MTP_Error('MAC verification failed')			
		#--------------------------
		self.sqn_r += 1

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(encrypted_payload)) + '): ')
			print('MAC (' + str(len(mac)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG 

		return parsed_msg_hdr['typ'], plaintext


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):

		# build encrypted message
		msg_sqn = self.sqn_s.to_bytes(self.size_msg_hdr_sqn, byteorder="big")
		msg_rnd = get_random_bytes(self.size_msg_hdr_rnd)
		
		nonce = msg_sqn + msg_rnd

		msg_size = self.size_msg_hdr + len(msg_payload) + self.size_mac_len
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')

		cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac_len)

		# header = 		ver  	   |    typ   |  	 len    |  	sqn   |	  rnd 	|   rsv
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_sqn + msg_rnd + self.rsv
		self.sqn_s += 1

		cipher.update(msg_hdr)
		ciphertext, authtag = cipher.encrypt_and_digest(msg_payload)

		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_payload)) + '): ')
			print('MAC (' + str(len(authtag)) + '): ')
			print(msg_payload.hex())
			print('------------------------------------------')
		# DEBUG 

		try:
			self.send_bytes(msg_hdr + ciphertext + authtag)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

