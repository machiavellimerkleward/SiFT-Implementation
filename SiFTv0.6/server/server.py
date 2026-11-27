#python3

import sys, threading, socket, getpass
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error
from siftprotocols.siftinit import SiFT_INIT, SiFT_INIT_Error
from siftprotocols.siftlogin import SiFT_LOGIN, SiFT_LOGIN_Error
from siftprotocols.siftcmd import SiFT_CMD, SiFT_CMD_Error
from Crypto.PublicKey import ECC


class Server:
    def __init__(self):
        # ------------------------ CONFIG -----------------------------
        self.server_usersfile = 'users.txt' 
        self.server_usersfile_coding = 'utf-8'
        self.server_usersfile_rec_delimiter = '\n'
        self.server_usersfile_fld_delimiter = ':'
        self.server_rootdir = './users/'
        self.server_ip = socket.gethostbyname('localhost')
        # self.server_ip = socket.gethostbyname(socket.gethostname())
        # self.server_ip = '192.168.20.xy'
        self.server_port = 5150
        self.key = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
        # -------------------------------------------------------------
        self.server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.server_socket.bind((self.server_ip, self.server_port))
        self.server_socket.listen(5)
        print('Listening on ' + self.server_ip + ':' + str(self.server_port))
        self.accept_connections()


    def load_users(self, usersfile):
        users = {}
        with open(usersfile, 'rb') as f:
            allrecords = f.read().decode(self.server_usersfile_coding)
        records = allrecords.split(self.server_usersfile_rec_delimiter)
        for r in records:
            fields = r.split(self.server_usersfile_fld_delimiter)
            username = fields[0]
            usr_struct = {}
            usr_struct['pwdhash'] = bytes.fromhex(fields[1])
            usr_struct['icount'] = int(fields[2])
            usr_struct['salt'] = bytes.fromhex(fields[3])
            usr_struct['rootdir'] = fields[4]
            users[username] = usr_struct
        return users


    def accept_connections(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, addr, )).start()


    def handle_client(self, client_socket, addr):
        print('New client on ' + addr[0] + ':' + str(addr[1]))

        #Instantialize Message Transfer Protocol
        mtp = SiFT_MTP(client_socket, self.key)

        # Generate Server Keypair
        # key = ECC.generate(curve='P-256')
        # private_k = key.export_key(format='DER',passphrase='XXX',use_pkcs8=True, protection='PBKDF2WithHMAC-SHA1AndAES256-CBC')
        # f = open("private_key.der", "wb")
        # f.write(private_k)
        # public_k = key.public_key().export_key(format="DER")
        # f = open("public_key.der", "wb")
        # f.write(public_k)

        # Instantialize Init Protocol
        initp = SiFT_INIT(mtp)

        f = open("private_key.der", "rb")
        private_kb = f.read()
        private_k = ECC.import_key(private_kb, passphrase='ait-budapest')
        f = open("public_key.der", "rb")
        public_k = f.read()
        
        try:
            initp.initiate_session_server(public_k, private_k)
        except SiFT_INIT_Error as e:
            print('SiFT_INIT_Error: ' + e.err_msg)
            print('Closing connection with client on ' + addr[0] + ':' + str(addr[1]))
            client_socket.close()
            return

        # Initialize Login Protocol
        loginp = SiFT_LOGIN(mtp)
        users = self.load_users(self.server_usersfile)
        loginp.set_server_users(users)

        try:
            user = loginp.handle_login_server()
        except SiFT_LOGIN_Error as e:
            print('SiFT_LOGIN_Error: ' + e.err_msg)
            print('Closing connection with client on ' + addr[0] + ':' + str(addr[1]))
            client_socket.close()
            return

        cmdp = SiFT_CMD(mtp)
        cmdp.set_server_rootdir(self.server_rootdir)
        cmdp.set_user_rootdir(users[user]['rootdir'])

        while True:
            try:
                cmdp.receive_command()
            except SiFT_CMD_Error as e:
                print('SiFT_CMD_Error: ' + e.err_msg)
                print('Closing connection with client on ' + addr[0] + ':' + str(addr[1]))
                client_socket.close()
                return


# main
if __name__ == '__main__':
    server = Server()