import time
import socket
import select
import hashlib
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
authedusers = []
keyreqmsgs = ['!req', '!erelog']


def decrypt(enc_data, func_key):
    f = Fernet(func_key)
    decrypted_data = f.decrypt(enc_data)
    return decrypted_data


def encrypt(func_mes, func_key):
    f = Fernet(func_key)
    encrypted_data = f.encrypt(func_mes)
    return encrypted_data


def send_msg(func_msg, send_usr, func_socket=None, encryptmsg=True):
    # send user is user to send as, userheader+user
    # func socket is the socket to send to, none for all sockets
    func_msg = func_msg.encode('utf-8')
    if encryptmsg:
        func_msg = encrypt(func_msg, key)
    func_header = f'{len(func_msg):<{HEADER_LENGTH}}'.encode('utf-8')
    if func_socket:
        func_socket.send(send_usr + func_header + func_msg)
    else:
        for func_client_socket in clients:
            func_client_socket.send(send_usr + func_header + func_msg)


def receive_msg(func_socket):
    try:
        func_header = func_socket.recv(HEADER_LENGTH)
        if not len(func_header):
            return False
        func_length = int(func_header.decode('utf-8').strip())
        return {'header': func_header, 'data': func_socket.recv(func_length)}
    except OSError:
        return False


def get_socket_by_user(func_usr):
    j = 1
    for i in clients:
        if clients[sockets_list[j]]['data'].decode('utf-8') == func_usr:
            return sockets_list[j]
        else:
            if not i:
                print('? how did we get here')
            j += 1
    return False


# ask for setup
PORT = int(input('Port: '))
master_auth = hashlib.sha256(input('Master password: ').encode('utf-8')).hexdigest()  # generate sha256 hash

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
                        if disconnected_client in authedusers:
                            del authedusers[disconnected_client]
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
                    # print message, if it is not encrypted then print it
                    try:
                        print(f'<{formattedTime}> {user["data"].decode("utf-8")}: {decrypt(message["data"], key).decode("utf-8")}')
                    except cryptography.fernet.InvalidToken:
                        print(f'<{formattedTime}> {user["data"].decode("utf-8")}:* {message["data"].decode("utf-8")}')

                    # decrypt or decode message
                    dec_user = user["data"].decode("utf-8")
                    try:
                        dec_message = decrypt(message['data'], key)
                        dec_message = dec_message.decode('utf-8')
                    except cryptography.fernet.InvalidToken:
                        dec_message = message['data'].decode('utf-8')
                    # check for commands
                    if dec_message in keyreqmsgs or ' joined the chat!' in dec_message:
                        # send key
                        time.sleep(0.5)
                        send_msg(keydec, keyusr_header + keyusr, notif_socket, False)
                        print(f'<{formattedTime}> Sent key to {dec_user}')
                    elif ';auth ' in dec_message:
                        # authenticate user
                        auth_attempt = hashlib.sha256(dec_message.split(' ')[1].encode('utf-8')).hexdigest()
                        if auth_attempt == master_auth:
                            authedusers.append(dec_user)
                            send_msg('You have been authenticated as an admin!', srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user} You have been authenticated as an admin!')
                        else:
                            send_msg('Incorrect password.', srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user} Incorrect password.')

                    elif ';kick ' in dec_message:  # add auth
                        to_kick = dec_message.split(' ')[1]
                        kick_socket = get_socket_by_user(to_kick)
                        if kick_socket:
                            send_msg(f'You have been kicked. Reason: ', srvusr_header + srvusr, kick_socket)
                            sockets_list.remove(kick_socket)
                            disconnected_client = clients[kick_socket]["data"].decode("utf-8")
                            connectedusers.remove(disconnected_client)
                            del clients[kick_socket]
                            if disconnected_client in authedusers:  # unlikely lol
                                del authedusers[disconnected_client]
                            kick_socket.close()
                            send_msg(f'{to_kick} has been kicked.', srvusr_header + srvusr)
                            print(f'<{formattedTime}> {to_kick} kicked by {dec_user} | Reason: ')
                        else:
                            send_msg('User does not exist.', srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user}: User does not exist.')
                    elif dec_message == ';usrls':
                        # user list
                        msg = ', '.join(sorted(connectedusers, key=str.lower))
                        send_msg(msg, srvusr_header + srvusr, notif_socket['data'])
                        print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{notif_socket["data"]}: {msg}')
                    elif ';pm ' in dec_message:
                        pm_rusr = dec_message.split(' ')[1]
                        pm_msg = dec_message.split(' ', 2)
                        del pm_msg[0]
                        del pm_msg[0]
                        pm_msg = ''.join(pm_msg)
                        pm_socket = get_socket_by_user(pm_rusr)
                        if pm_socket:  # only send if valid user
                            # make private message prefix
                            emuusr = f'PM from {dec_user}'.encode('utf-8')
                            emuusr_header = f"{len(emuusr):<{HEADER_LENGTH}}".encode('utf-8')
                            # send
                            send_msg(pm_msg, emuusr_header + emuusr, pm_socket)
                            print(f'<{formattedTime}> {emuusr.decode("utf-8")}|{pm_rusr}: {pm_msg}')
                        else:
                            send_msg('User does not exist.', srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user}: User does not exist.')
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
                if disconnected_client in authedusers:
                    del authedusers[disconnected_client]
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
        print(f'<{formattedTime}> error: ' + str(err))
        time.sleep(0.05)
