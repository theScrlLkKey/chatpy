import socket
import select
import errno
import time
import urllib.request
from cryptography.fernet import Fernet
import os
import zlib
from os import walk

# userinfo bot

def encrypt(message, key):
    """
    Given a filename (str) and key (bytes), it encrypts the file and write it
    """

    f = Fernet(key)
    file_data = message

    encrypted_data = f.encrypt(file_data)
    return (encrypted_data)


def decrypt(encrypted_data, key):
    """
    Given a filename (str) and key (bytes), it decrypts the file and write it
    """

    f = Fernet(key)

    decrypted_data = f.decrypt(encrypted_data)
    return (decrypted_data)


HEADER_LENGTH = 10

ip = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')

# IP = str(input('Ip Address: '))
# PORT = int(input('Port(Must be a number): '))
# my_username = input("Username: ")

# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to a given ip and port
hostname = socket.gethostname()
IP = socket.gethostbyname(hostname)
PORT = int(input('Port: '))
while True:
    try:

        client_socket.connect((IP, PORT))
        break
    except:
        print('Error connecting to server. Check ip and port and try again.')
        IP = str(input('Ip Address: '))
        PORT = int(input('Port(Must be a number): '))

print('Connected!')
my_username = 'Userinfo'
try:
    os.chdir('usrinfo')
except:
    os.mkdir('usrinfo')
    os.chdir('usrinfo')

# Set connection to non-blocking state, so .recv() call won;t block, just return some exception we'll handle
client_socket.setblocking(False)

# Prepare username and header and send them
# We need to encode username to bytes, then count number of bytes and prepare header of fixed size, that we encode to bytes as well
username = my_username.encode('utf-8')
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
client_socket.send(username_header + username)

message = '!req'

message = message.encode('utf-8')
message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
client_socket.send(message_header + message)
trytoreauth = 10
while True:
    trytoreauth -= 1
    try:
        # Receive our "header" containing username length, it's size is defined and constant
        username_header = client_socket.recv(HEADER_LENGTH)

        # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        if not len(username_header):
            print('Connection closed by the server')
            exit()

        # Convert header to int value
        username_length = int(username_header.decode('utf-8').strip())

        # Receive and decode username
        username = client_socket.recv(username_length).decode('utf-8')

        # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
        message_header = client_socket.recv(HEADER_LENGTH)
        message_length = int(message_header.decode('utf-8').strip())
        message = client_socket.recv(message_length).decode('utf-8')
        if username == 'enc_distr':
            key = message
            print('Authenticated!')
            break
        else:
            continue
    except:
        continue

named_tuple = time.localtime()  # get struct_time
sttime = int(time.strftime("%H", named_tuple))

while True:
    try:
        # Now we want to loop over received messages (there might be more than one) and print them
        while True:

            # Receive our "header" containing username length, it's size is defined and constant
            username_header = client_socket.recv(HEADER_LENGTH)

            # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
            if not len(username_header):
                exit()

            # Convert header to int value
            username_length = int(username_header.decode('utf-8').strip())

            # Receive and decode username
            username = client_socket.recv(username_length).decode('utf-8')
            rusenme = username

            # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
            message_header = client_socket.recv(HEADER_LENGTH)
            message_length = int(message_header.decode('utf-8').strip())
            message = client_socket.recv(message_length)
            ogmessage = message
            if 'joined the chat!' in message.decode('utf-8') or 'left the chat!' in message.decode('utf-8') or '!relog' in message.decode('utf-8') or '!req' in message.decode('utf-8'):
                message = message.decode('utf-8')
            else:
                try:
                    message = decrypt(message, key)
                    message = message.decode('utf-8')
                    rmessage = message
                except:
                    continue

            named_tuple = time.localtime()  # get struct_time
            cutime = int(time.strftime("%H", named_tuple))

            # Print message
            # # Print message
            # if message == '!userinfo':
            #     smessage = '!msg '
            #     message = smessage.encode('utf-8')
            #     message = encrypt(message, key)
            #     message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            #     client_socket.send(message_header + message)
            # elif message == '!userinfo':
            #     smessage = '/me rolls by'
            #     message = smessage.encode('utf-8')
            #     message = encrypt(message, key)
            #     message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            #     client_socket.send(message_header + message)
            #     sttime = cutime
            #
            # elif message == '!chkusr':
            #     smessage = '!chkusrback'
            #     message = smessage.encode('utf-8')
            #     message = encrypt(message, key)
            #     message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            #     client_socket.send(message_header + message)
            # elif 'joined the chat!' in message and 'joined the chat!' in ogmessage.decode('utf-8'):
            #     time.sleep(1)
            #     smessage = '!msg ' + username + f'hi {username}. you can make a bio for yourself, do !msg Userinfo enroll <bio>. to find another users bio, do !userinfo <user>. add your pronouns with !msg Userinfo pronouns <abc/xyz> and ill correct people when they refer to you.'
            #     message = smessage.encode('utf-8')
            #     message = encrypt(message, key)
            #     message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            #     client_socket.send(message_header + message)

            if message == '!userinfo':
                #. add your pronouns with !msg Userinfo pronouns <abc/xyz> and ill correct people when they refer to you.
                smessage = f'!msg {username} hi {username}. you can make a bio for yourself, do !msg Userinfo setbio <bio>. to find another users bio, do !userinfo <user>. use !userinfo greet to display your own bio. '
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)


            elif '!msg userinfo setbio ' in message.lower():
                try:
                    mes_trim = message.split(' ', 2)[2]
                    mes_trim = mes_trim.split()
                    mes_trim.pop(0)
                    mes_trim = ' '.join(mes_trim)
                    # print(mes_trim)
                except:
                    smessage = f"!msg {username} not a valid command"
                    message = smessage.encode('utf-8')
                    message = encrypt(message, key)
                    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(message_header + message)
                    continue

                with open(f'{str(zlib.crc32(username.encode("utf-8")))}.txt', 'w+') as data:
                    data.write(str(mes_trim))

                smessage = f'!msg {username} successfully added bio. access it with !userinfo {username}, or !userinfo greet.'
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)

            elif message == '!userinfo greet':
                try:
                    with open(f'{str(zlib.crc32(username.encode("utf-8")))}.txt', "r") as pfile:
                        gotbio = pfile.read()

                    # print(postMeta)
                    # {title} ;`; {opname} ;`; {ptime} ;`; {post}')
                    # print(f'fetchedpost {postMeta[0]} ;`; {postMeta[1]} ;`; {postMeta[2]} ;`; {post}')

                    smessage = f"{username}'s bio: \n{gotbio}"
                    message = smessage.encode('utf-8')
                    message = encrypt(message, key)
                    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(message_header + message)
                except Exception as e:
                    smessage = f"you dont have a bio, {username}!"
                    message = smessage.encode('utf-8')
                    message = encrypt(message, key)
                    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(message_header + message)

            elif '!userinfo ' in message:
                try:
                    mes_trim = message.split(' ', 1)[1]
                except:
                    smessage = f"not a valid command"
                    message = smessage.encode('utf-8')
                    message = encrypt(message, key)
                    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(message_header + message)
                    continue

                try:

                    with open(f'{str(zlib.crc32(mes_trim.encode("utf-8")))}.txt', "r") as pfile:
                        gotbio = pfile.read()

                    # print(postMeta)
                    # {title} ;`; {opname} ;`; {ptime} ;`; {post}')
                    # print(f'fetchedpost {postMeta[0]} ;`; {postMeta[1]} ;`; {postMeta[2]} ;`; {post}')

                    smessage = f"{mes_trim}'s bio: \n{gotbio}"
                    message = smessage.encode('utf-8')
                    message = encrypt(message, key)
                    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(message_header + message)
                except Exception as e:
                    smessage = f"no bio found for {mes_trim}."
                    message = smessage.encode('utf-8')
                    message = encrypt(message, key)
                    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(message_header + message)


            elif message == '!chkusr':
                smessage = '!chkusrback'
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)

            elif 'joined the chat!' in message and 'joined the chat!' in ogmessage.decode('utf-8'):  # igore if already enrolled
                time.sleep(1)
                smessage = '!msg ' + username + f' hello. make a bio for yourself. !userinfo for more info.'
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)



    except IOError as e:
        # This is normal on non blocking connections - when there are no incoming data error is going to be raised
        # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
        # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
        # If we got different error code - something happened
        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
            print('Reading error: {}'.format(str(e)))
            exit()

        # We just did not receive anything
        time.sleep(0.05)


