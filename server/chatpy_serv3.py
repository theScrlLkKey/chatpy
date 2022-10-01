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


def admin_msg(func_msg, func_sendas):
    func_sendas = f'Admin PM from {func_sendas}'.encode('utf-8')
    func_header = f"{len(func_sendas):<{HEADER_LENGTH}}".encode('utf-8')
    for func_usr in authedusers:
        send_msg(func_msg, func_header + func_sendas, get_socket_by_user(func_usr))


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
blocked_usernames = [srvusr.decode('utf-8'), ' ', '']

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
                    dec_user = user["data"].decode("utf-8")
                    # username already online, or username is blocked
                    if dec_user in connectedusers or dec_user in blocked_usernames or 'PM from' in dec_user or len(dec_user) > 25:
                        send_msg(keydec, keyusr_header + keyusr, client_socket, False)  # send key
                        print(f'<{formattedTime}> {client_ip}:{client_port}|{dec_user} not connected, username in use or blocked')
                        send_msg('That username is in use or not allowed.', srvusr_header + srvusr, client_socket)
                        time.sleep(0.1)
                        client_socket.close()  # only to remove them
                        sockets_list.remove(client_socket)
                        del clients[client_socket]
                    else:
                        connectedusers.append(dec_user)
                        print(f'<{formattedTime}> {client_ip}:{client_port}|{user["data"].decode("utf-8")} connected')
                        for client_socket in clients:
                            if client_socket != notif_socket:
                                # notify clients of join
                                msg = dec_user + ' has joined the chat!'
                                msg = msg.encode('utf-8')
                                msg_header = f'{len(msg):<{HEADER_LENGTH}}'.encode('utf-8')
                                # send as user's username even though we dont use it; could be sent under "server" username
                                # we will see about the above claim: client_socket.send( + msg_header + msg)
                                client_socket.send(srvusr_header + srvusr + msg_header + msg)
                else:
                    # client sent message
                    # contains username + header and message + header
                    message = receive_msg(notif_socket)
                    if message is False:
                        # client disconnected
                        sockets_list.remove(notif_socket)
                        disconnected_client = clients[notif_socket]['data'].decode('utf-8')
                        disconnected_header = clients[notif_socket]['header']
                        print(f'<{formattedTime}> {disconnected_client} disconnected.')
                        connectedusers.remove(disconnected_client)
                        del clients[notif_socket]
                        if disconnected_client in authedusers:
                            authedusers.remove(disconnected_client)
                        # notify users
                        msg = disconnected_client + ' has left the chat!'  # ihatethisihatethis
                        msg = msg.encode('utf-8')
                        msg_header = f'{len(msg):<{HEADER_LENGTH}}'.encode('utf-8')
                        for client_socket in clients:
                            if client_socket != notif_socket:
                                # username header, username, message header, message
                                # send as disconnected user's username even though we dont use it; could be sent under "server" username
                                # we will see about the above claim: disconnected_header + disconnected_client.encode('utf-8')
                                client_socket.send(srvusr_header + srvusr + msg_header + msg)
                        continue
                    user = clients[notif_socket]
                    # print message, if it is not encrypted then print it
                    try:
                        print(f'<{formattedTime}> {user["data"].decode("utf-8")}: {decrypt(message["data"], key).decode("utf-8")}')
                    except cryptography.fernet.InvalidToken:
                        print(f'<{formattedTime}> {user["data"].decode("utf-8")}:* {message["data"].decode("utf-8")}')

                    dec_user = user["data"].decode("utf-8")
                    # decrypt or decode message
                    try:
                        dec_message = decrypt(message['data'], key)
                        dec_message = dec_message.decode('utf-8')
                    except cryptography.fernet.InvalidToken:
                        dec_message = message['data'].decode('utf-8')
                    # send key to new user
                    if dec_message == ';req' or ' joined the chat!' in dec_message:
                        if dec_user not in connectedusers:
                            # send key
                            time.sleep(0.5)
                            send_msg(keydec, keyusr_header + keyusr, notif_socket, False)
                            print(f'<{formattedTime}> Sent key to {dec_user}')
                    elif ' joined the chat!' in message['data'].decode('utf-8') or ' left the chat!' in message['data'].decode('utf-8'):
                        # dont send these; backwards compatibility
                        pass
                    # check for commands
                    # admin stuff
                    elif ';auth ' in dec_message:
                        # authenticate user
                        auth_attempt = hashlib.sha256(dec_message.split(' ')[1].encode('utf-8')).hexdigest()
                        if dec_user in authedusers:
                            send_msg('You are already an admin!', srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user} You are already an admin!')
                        elif auth_attempt == master_auth:
                            admin_msg(f'{dec_user} is now an admin!', srvusr.decode('utf-8'))
                            authedusers.append(dec_user)
                            send_msg('You have been authenticated as an admin!', srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user} You have been authenticated as an admin!')
                        else:
                            send_msg('Incorrect password.', srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user} Incorrect password ({dec_message.split(" ")[1]})')
                            admin_msg(f'{dec_user} failed to login as admin, tried: {dec_message.split(" ")[1]}', srvusr.decode("utf-8"))
                    elif dec_message == ';deauth':
                        if dec_user in authedusers:
                            authedusers.remove(dec_user)
                            send_msg('Logged out.', srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user} Logged out.')
                            admin_msg(f'{dec_user} is no longer an admin.', srvusr.decode('utf-8'))
                        else:
                            send_msg('You are not an admin.', srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user} You are not an admin.')
                    elif ';cgpw ' in dec_message:
                        if dec_user in authedusers:
                            master_auth = hashlib.sha256(dec_message.split(' ')[1].encode('utf-8')).hexdigest()
                            admin_msg('Password changed.', srvusr.decode("utf-8"))
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user}: Password changed to {dec_message.split(" ")[1]}')
                        else:
                            send_msg('You do not have permission to use this command.', srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user}: You do not have permission to use this command.')
                    elif ';kick ' in dec_message:
                        if dec_user in authedusers:
                            to_kick = dec_message.split(' ')[1]
                            try:
                                reason_kick = dec_message.split(' ', 2)[2]
                            except IndexError:
                                reason_kick = ''
                            kick_socket = get_socket_by_user(to_kick)
                            if kick_socket:
                                send_msg(f'You have been kicked. Reason: {reason_kick}', srvusr_header + srvusr, kick_socket)
                                sockets_list.remove(kick_socket)
                                disconnected_client = clients[kick_socket]["data"].decode("utf-8")
                                connectedusers.remove(disconnected_client)
                                del clients[kick_socket]
                                if disconnected_client in authedusers:  # unlikely lol
                                    authedusers.remove(disconnected_client)
                                kick_socket.close()
                                admin_msg(f'{to_kick} has been kicked by {dec_user}. Reason: {reason_kick}', srvusr.decode('utf-8'))
                                send_msg(f'{to_kick} has been kicked.', srvusr_header + srvusr)
                                print(f'<{formattedTime}> {to_kick} kicked by {dec_user} | Reason: {reason_kick}')
                            else:
                                send_msg('User does not exist.', srvusr_header + srvusr, notif_socket)
                                print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user}: User does not exist.')
                        else:
                            send_msg('You do not have permission to use this command.', srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user}: You do not have permission to use this command.')
                    elif ';apm ' in dec_message:  # admin only chat
                        if dec_user in authedusers:
                            apm_msg = dec_message.split(' ')[1]
                            admin_msg(apm_msg, dec_user)
                            print(f'<{formattedTime}> Admin PM from {dec_user}|{", ".join(sorted(authedusers, key=str.lower))}: {apm_msg}')
                        else:
                            send_msg('You do not have permission to use this command.', srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user}: You do not have permission to use this command.')
                    elif ';reqinfo ' in dec_message:
                        if dec_user in authedusers:
                            req_usr = dec_message.split(' ')[1]
                            send_msg(str(get_socket_by_user(req_usr)), srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user} {str(get_socket_by_user(req_usr))}')
                        else:
                            send_msg('You do not have permission to use this command.', srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user}: You do not have permission to use this command.')
                    # non admin
                    elif dec_message == ';usrls':
                        # user list
                        msg = f'Users online - {", ".join(sorted(connectedusers, key=str.lower))} - Total: {len(connectedusers)}'
                        send_msg(msg, srvusr_header + srvusr, notif_socket)
                        print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user}: {msg}')
                    elif ';pm ' in dec_message:
                        pm_rusr = dec_message.split(' ')[1]
                        pm_msg = dec_message.split(' ', 2)[2]
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
                    elif dec_message == ';ping':
                        send_msg('Pong! Did you mean !ping?', srvusr_header + srvusr, notif_socket)
                    elif ';reqauth ' in dec_message:
                        req_usr = dec_message.split(' ')[1]
                        if req_usr in authedusers:
                            send_msg('True', srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user} True')
                        else:
                            send_msg('False', srvusr_header + srvusr, notif_socket)
                            print(f'<{formattedTime}> {srvusr.decode("utf-8")}|{dec_user} False')
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
                    authedusers.remove(disconnected_client)
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
