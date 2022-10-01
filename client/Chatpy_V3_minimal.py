import time
import errno
import socket
import cryptography.fernet
from cryptography.fernet import Fernet

# minimal version of chatpyV3, can be run from a terminal

# definitions
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
HEADER_LENGTH = 10
printTime = 'null'


def encrypt(func_mes, func_key):
    f = Fernet(func_key)
    encrypted_data = f.encrypt(func_mes)
    return encrypted_data


def decrypt(encrypted_data, func_key):
    f = Fernet(func_key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data


def close():
    client_socket.close()
    input('Press enter to exit...')
    exit()


def send_message(func_msg, func_enc=True):
    func_msg = func_msg.encode('utf-8')
    if func_enc:
        func_msg = encrypt(func_msg, key)
    func_msg_header = f"{len(func_msg):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(func_msg_header + func_msg)


# ask for ip and port
# todo: load from file
IP = str(input('IP address/hostname: '))
while True:
    try:
        PORT = int(input('Port: '))
        break
    except ValueError:
        print('Port must be a number.')

# connect
while True:
    try:
        client_socket.connect((IP, PORT))
        break
    except OSError:
        print('Error connecting to server')
        IP = str(input('IP address/hostname: '))
        while True:
            try:
                PORT = int(input('Port: '))
                break
            except ValueError:
                print('Port must be a number.')
client_socket.setblocking(False)
print(f'Connected to {IP}:{PORT}! Type exit to quit, and ctrl+c to send a message.')

# setup username
cli_username = input('Username: ')
cli_username = cli_username.replace(' ', '_')  # ensure that there isnt any spaces
username = cli_username.encode('utf-8')
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
client_socket.send(username_header + username)

# authenticate
auth_attempt = 10
send_message('!req')
while username != 'enc_distr':
    try:
        username_header = client_socket.recv(HEADER_LENGTH)
        if not len(username_header):
            print('Server refused connection')
            close()
        username_length = int(username_header.decode('utf-8').strip())
        username = client_socket.recv(username_length).decode('utf-8')
        if auth_attempt < 1:
            print('Unable to secure connection')
            close()
        auth_attempt -= 1
    except IOError as Err:
        if Err.errno == errno.EAGAIN or Err.errno == errno.EWOULDBLOCK:
            continue
message_header = client_socket.recv(HEADER_LENGTH)
message_length = int(message_header.decode('utf-8').strip())
message = client_socket.recv(message_length).decode('utf-8')
key = message
print('Secured!')

# start mainloop
while True:
    try:
        while True:
            try:
                # get current time
                time_tuple = time.localtime()
                printTime = time.strftime("%I:%M%p", time_tuple)
                # receive username
                username_header = client_socket.recv(HEADER_LENGTH)
                if not len(username_header):
                    print('Disconnected from server.')
                    close()
                username_length = int(username_header.decode('utf-8').strip())
                username = client_socket.recv(username_length).decode('utf-8')
                # receive message
                message_header = client_socket.recv(HEADER_LENGTH)
                message_length = int(message_header.decode('utf-8').strip())
                message = client_socket.recv(message_length)
                try:
                    message = decrypt(message, key)
                    message = message.decode('utf-8')
                except cryptography.fernet.InvalidToken:
                    message = message.decode('utf-8')
                # check for formatting, then print
                if '/me ' in message:
                    print(f'{printTime} |​⃰ {username} {message.split("/me ")[1]}')
                else:
                    print(f'{printTime} |{username}: {message}')
            except IOError as Err:
                # no new messages
                if Err.errno == 10054:
                    print('Disconnected from server.')
                    close()
                elif Err.errno != errno.EAGAIN and Err.errno != errno.EWOULDBLOCK:  # cross-platform compatibility
                    print(f'Error: {Err}')
                    close()
                else:
                    time.sleep(0.05)

    # exception for ctrl+c
    except KeyboardInterrupt:
        # check for commands, then send
        s_input = input(f'{printTime} |{cli_username}: ')
        if s_input == 'exit':
            close()
        send_message(s_input)
