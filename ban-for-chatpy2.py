import socket
import select
import errno
import time
import urllib.request
from cryptography.fernet import Fernet


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
my_username = 'I ban u'

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
with open('banlist.txt', 'r') as data:
    bans = data.read()
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
            if ' joined the chat!' in message.decode('utf-8') or ' left the chat!' in message.decode('utf-8') or '!relog' in message.decode('utf-8') or '!req' in message.decode('utf-8'):
                message = message.decode('utf-8')
                rmessage = message
            else:
                try:
                    message = decrypt(message, key)
                    message = message.decode('utf-8')
                    rmessage = message
                except:
                    continue




            # Print message
            if '!ban ' in message:
                busenm = message.strip('!ban ')
                smessage = '!reip ' + busenm
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
                trytoban = 35
                while True:
                    trytoban -= 1
                    if trytoban < 1:
                        rip = ';;;'
                        break
                    time.sleep(0.2)
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
                        message = client_socket.recv(message_length)
                        if username == busenm:
                            rip = decrypt(message, key)
                            rip = rip.decode("utf-8")
                            rip = rip.strip('!ip ')
                            break
                        else:
                            continue
                    except:
                        continue
                if rip == ';;;':
                    smessage = 'Ban failed'
                    message = smessage.encode('utf-8')
                    message = encrypt(message, key)
                    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(message_header + message)
                    break
                smessage = 'Enter password on console...'
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
                inputpass = input('Ban requested by ' + rusenme + ' for ' + busenm +' ('+ rip + '). Enter password to continue: ')
                if inputpass == 'banPass1234!@#$':
                    print('Ban authenticated.')
                    with open('banlist.txt', 'a+') as data:
                        data.write(str(rmessage).strip('!ban ') + ' ' + rip + ' ; ')
                    smessage = '!kick ' + busenm
                    message = smessage.encode('utf-8')
                    message = encrypt(message, key)
                    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(message_header + message)
                else:
                    print('Wrong password.')
                with open('banlist.txt', 'r') as data:
                    bans = data.read()

            elif ' joined the chat!' in message or '!ip ' in message:
                if str(message).strip(' joined the chat!') in bans or str(message).strip('!ip ') in bans:
                    time.sleep(1)
                    smessage = '!kick ' + rusenme
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

# while True:
#
#     message = ''
#
#     # If message is not empty - send it
#     if message:
#         # Encode message to bytes, prepare header and convert to bytes, like for username above, then send
#         message = message.encode('utf-8')
#         message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
#         client_socket.send(message_header + message)
#
#     try:
#         # Now we want to loop over received messages (there might be more than one) and print them
#         while True:
#
#             # Receive our "header" containing username length, it's size is defined and constant
#             username_header = client_socket.recv(HEADER_LENGTH)
#
#             # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
#             if not len(username_header):
#                 print('Connection closed by the server')
#                 sys.exit()
#
#             # Convert header to int value
#             username_length = int(username_header.decode('utf-8').strip())
#
#             # Receive and decode username
#             username = client_socket.recv(username_length).decode('utf-8')
#
#             # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
#             message_header = client_socket.recv(HEADER_LENGTH)
#             message_length = int(message_header.decode('utf-8').strip())
#             message = client_socket.recv(message_length).decode('utf-8')
#
#             # Print message
#             print(f'{username}: {message}')
#
#     except IOError as e:
#         # This is normal on non blocking connections - when there are no incoming data error is going to be raised
#         # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
#         # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
#         # If we got different error code - something happened
#         if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
#             print('Reading error: {}'.format(str(e)))
#             sys.exit()
#
#         # We just did not receive anything
#
#
#     except Exception as e:
#         # Any other exception - something happened, exit
#         print('Reading error: '.format(str(e)))
#         sys.exit()
