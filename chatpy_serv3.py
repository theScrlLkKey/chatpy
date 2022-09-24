import time
import socket
import select
import cryptography.fernet
from cryptography.fernet import Fernet

# rewritten server - old one was garbage

# definitions
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
HEADER_LENGTH = 10
hostname = socket.gethostname()
loc_ip = socket.gethostbyname(hostname)
IP = '0.0.0.0'
clients = {}
connectedusers = []
keyreqmsgs = ['!req', '!erelog']


def decrypt(enc_data, func_key):
    f = Fernet(func_key)
    decrypted_data = f.decrypt(enc_data)
    return decrypted_data


def encrypt(func_mes, func_key):
    f = Fernet(func_key)
    encrypted_data = f.encrypt(func_mes)
    return encrypted_data


def receive_msg(func_socket):
    try:
        func_header = func_socket.recv(HEADER_LENGTH)
        if not len(func_header):
            return False
        func_length = int(func_header.decode('utf-8').strip())
        return {'header': func_header, 'data': func_socket.recv(func_length)}
    except:
        # bad programming ik ill figure it out
        return False


# ask for setup
PORT = int(input('Port: '))

# create socket
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((IP, PORT))
server_socket.listen()
sockets_list = [server_socket]

# misc setup
print(f'Listening for connections on {IP}({loc_ip}):{PORT}...')
keyusr = 'enc_distr'.encode('utf-8')  # emulate key bot
keyusr_header = f"{len(keyusr):<{HEADER_LENGTH}}".encode('utf-8')
# server username
srvusr = '#server#'.encode('utf-8')
srvusr_header = f"{len(srvusr):<{HEADER_LENGTH}}".encode('utf-8')

# generate key
key = Fernet.generate_key()
keydec = key.decode('utf-8')
print('Key generated: ' + keydec)

# main loop
while True:
    try:
        while True:
            # sleep to not hog resources
            time.sleep(0.05)
            # get current time
            time_tuple = time.localtime()
            formattedTime = time.strftime("%H:%M:%S", time_tuple)
            fTime_enc = formattedTime.encode('utf-8')
            # not fully sure what this does? not in the tutorial that this hellspawn descended from so im rewriting it
            read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)
            for notif_socket in read_sockets:
                if notif_socket == server_socket:
                    # accept new connection
                    client_socket, client_address = server_socket.accept()
                    user = receive_msg(client_socket)
                    if user is False:
                        # user did not connect correctly
                        continue
                    sockets_list.append(client_socket)
                    clients[client_socket] = user
                    client_ip, client_port = client_address
                    connectedusers.append(user['data'].decode('utf-8'))
                    print(f'<{formattedTime}> {client_ip}:{client_port}|{user["data"].decode("utf-8")} connected')
                    for client_socket in clients:
                        if client_socket != notif_socket:
                            # notify clients of join
                            msg = user['data'].decode('utf-8') + ' has joined the chat!'
                            msg = msg.encode('utf-8')
                            msg_header = f'{len(msg):<{HEADER_LENGTH}}'.encode('utf-8')
                            client_socket.send(user['header'] + user['data'] + msg_header + msg)
                else:
                    # client sent message
                    # contains username + header and message + header
                    message = receive_msg(notif_socket)
                    if message is False:
                        # client disconnected
                        sockets_list.remove(notif_socket)
                        disconnected_client = clients[notif_socket]["data"].decode("utf-8")
                        print(f'<{formattedTime}> {disconnected_client} disconnected.')
                        connectedusers.remove(disconnected_client)
                        del clients[notif_socket]
                        # notify users
                        msg = disconnected_client + ' has left the chat!'  # ihatethisihatethis
                        msg = msg.encode('utf-8')
                        msg_header = f'{len(msg):<{HEADER_LENGTH}}'.encode('utf-8')
                        for client_socket in clients:
                            if client_socket != notif_socket:
                                # username header, username, message header, message
                                # send as disconnected user's username even though we dont use it; could be sent under "server" username
                                client_socket.send(message['header'] + message['data'] + msg_header + msg)
                        continue
                    user = clients[notif_socket]
                    # print message, if it is not encrypted then dont print it
                    try:
                        print(f'<{formattedTime}> {user["data"].decode("utf-8")}: {decrypt(message["data"], key)}')
                    except cryptography.fernet.InvalidToken:
                        print(f'<{formattedTime}> {user["data"].decode("utf-8")}: {message["data"].decode("utf-8")}')

                    # decrypt or decode message
                    try:
                        dec_message = decrypt(message['data'], key)
                        dec_message = dec_message.decode('utf-8')
                    except cryptography.fernet.InvalidToken:
                        dec_message = message['data'].decode('utf-8')
                    # check for commands
                    if dec_message in keyreqmsgs or ' joined the chat!' in dec_message:
                        time.sleep(0.5)
                        msg = keydec
                        msg = msg.encode('utf-8')
                        msg_header = f'{len(msg):<{HEADER_LENGTH}}'.encode('utf-8')
                        # only send key to newly connected client
                        notif_socket.send(keyusr_header + keyusr + msg_header + msg)
                    elif dec_message == '!servusrls':
                        # user list
                        msg = ', '.join(sorted(connectedusers, key=str.lower))
                        msg = msg.encode('utf-8')
                        msg = encrypt(msg, key)
                        msg_header = f'{len(msg):<{HEADER_LENGTH}}'.encode('utf-8')
                        for client_socket in clients:
                            client_socket.send(srvusr_header + srvusr + msg_header + msg)
                    elif # TODO kick command, request ip command, proper pm support,
                    elif ' joined the chat!' in message['data'].decode('utf-8') or ' left the chat!' in message['data'].decode('utf-8'):
                        # dont send these; backwards compatibility
                        pass
                    # relay message
                    else:
                        for client_socket in clients:
                            if client_socket != notif_socket:
                                client_socket.send(user['header'] + user['data'] + message['header'] + message['data'])

            for notif_socket in exception_sockets:
                # someone didnt disconnect correctly
                sockets_list.remove(notif_socket)
                disconnected_client = clients[notif_socket]["data"].decode("utf-8")
                print(f'<{formattedTime}> {disconnected_client} disconnected improperly.')
                connectedusers.remove(disconnected_client)
                del clients[notif_socket]
                # notify of leave
                try:
                    msg = disconnected_client + ' has left the chat!'
                    msg = msg.encode('utf-8')
                    msg_header = f'{len(msg):<{HEADER_LENGTH}}'.encode('utf-8')
                    for client_socket in clients:
                        if client_socket != notif_socket:
                            client_socket.send(srvusr_header + srvusr + msg_header + msg)
                except Exception as err:
                    print('Client err occurred: ' + str(err))

    except Exception as err:
        # with this, nothing can break our code
        time_tuple = time.localtime()
        formattedTime = time.strftime("%H:%M:%S", time_tuple)
        print(f'<{formattedTime}> ' + str(err))
        time.sleep(0.05)
