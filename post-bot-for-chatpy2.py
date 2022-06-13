import socket
import select
import errno
import time
import os
from os import walk
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
my_username = 'Forum post manager'

try:
    os.chdir('forum')
except:
    os.mkdir('forum')

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



            # Print message
            if message == '/post':
                smessage = f'!msg {username} Hi! I control the forum here. Run "/post new" to post a new submission, "/post list" for all posts (sorted by new), and "/post read <post ID>" to read a post."'
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)

            elif '/post new ' in message:
                mes_trim = message.split(' ', 1)[1]
                mes_trim = mes_trim.split()
                mes_trim.pop(0)
                mes_trim = ' '.join(mes_trim)
                post = mes_trim.split(' ;;; ')[0]
                title = mes_trim.split(' ;;; ')[1]
                title = ''.join(c for c in title if c not in '<>:"/\|?*')

                named_tuple = time.localtime()  # get struct_time
                ctime = time.strftime("%I[%M[%p[%m-%d-%Y", named_tuple)

                with open(f'{username}```{title}```{ctime}```.txt', 'w+') as data:
                    data.write(str(post))

                smessage = f'!msg {username} Message posted!'
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)

                ptime = ctime.split('[')
                ptime = f'{ptime[0]}:{ptime[1]} - {ptime[2]} {ptime[3]}'
                print(f'''Post created ({title}) at {ptime} by {username} ''')

            elif message == '/post list':
                postList = []
                cwd = os.getcwd()
                files = []

                for (dirpath, dirnames, filenames) in walk(cwd):
                    files.extend(filenames)
                    break
                filenumls = {}
                j = 0
                for file in files:
                    filenumls[str(j)] = file
                    j += 1
                j = 1
                i = 0
                for file in files:
                    try:
                        # print(filenumls[str(i)])
                        plugn = filenumls[str(i)].split('```')
                        # print(plugn)
                        ptime = plugn[2]
                        ptime = ptime.split('[')
                        ptime = f'{ptime[0]}:{ptime[1]}{ptime[2]} {str(ptime[3])[:6]}{str(ptime[3])[8:]}'
                        # print(ptime)
                        plugntr = f'{plugn[1]} -{plugn[0]} [{ptime}]'
                        # print(plugntr)
                        postList.append(f'{j}: {plugntr}')
                        j += 1
                        i += 1
                    except:
                        i += 1

                newline = "\n"
                smessage = f'!msg {username} Most recent 10 posts: \n{newline.join(reversed(postList))}'
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)

            elif message == '/post list_int':
                postList = []
                cwd = os.getcwd()
                files = []

                for (dirpath, dirnames, filenames) in walk(cwd):
                    files.extend(filenames)
                    break
                filenumls = {}
                j = 0
                for file in files:
                    filenumls[str(j)] = file
                    j += 1
                j = 1
                i = 0
                for file in files:
                    try:
                        # print(filenumls[str(i)])
                        plugn = filenumls[str(i)].split('```')
                        # print(plugn)
                        ptime = plugn[2]
                        ptime = ptime.split('[')
                        ptime = f'{ptime[0]}:{ptime[1]}{ptime[2]} {str(ptime[3])[:6]}{str(ptime[3])[8:]}'
                        # print(ptime)
                        plugntr = f'{plugn[1]} -{plugn[0]} [{ptime}]'
                        # print(plugntr)
                        postList.append(f'{j}: {plugntr}')
                        j += 1
                        i += 1
                    except:
                        i += 1

                smessage = f'!msg {username} postlistint ;;; {" ;;; ".join(reversed(postList))}'
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)

            elif '/post fetch ' in message or '/post read ' in message:
                mes_trim = message.split(' ', 2)[2]
                mes_trim = str(int(mes_trim)-1)

                postList = []
                cwd = os.getcwd()
                files = []

                for (dirpath, dirnames, filenames) in walk(cwd):
                    files.extend(filenames)
                    break
                filenumls = {}
                j = 0
                for file in files:
                    filenumls[str(j)] = file
                    j += 1
                j = 1
                i = 0
                for file in files:
                    try:
                        plugn = filenumls[str(i)].split('```')
                        ptime = plugn[2]
                        ptime = ptime.split('[')
                        ptime = f'{ptime[0]}:{ptime[1]}{ptime[2]} {str(ptime[3])[:6]}{str(ptime[3])[8:]}'
                        plugntr = f'{plugn[1]} &&& {plugn[0]} &&& {ptime}'
                        postList.append(f'{plugntr}')
                        j += 1
                        i += 1
                    except:
                        i += 1

                with open(filenumls[mes_trim], "r") as pfile:
                    post = pfile.read()

                postMeta = postList[int(mes_trim)]
                postMeta = postMeta.split(' &&& ')
                # print(postMeta)
                # {title} ;`; {opname} ;`; {ptime} ;`; {post}')
                # print(f'fetchedpost {postMeta[0]} ;`; {postMeta[1]} ;`; {postMeta[2]} ;`; {post}')

                smessage = f'!msg {username} fetchedpost ;`; {postMeta[0]} ;`; {postMeta[1]} ;`; {postMeta[2]} ;`; {post}'
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

            elif 'joined the chat!' in message and 'joined the chat!' in ogmessage.decode('utf-8'):
                time.sleep(1)
                smessage = '!msg ' + username + f" Hello {username}! This chatroom has a forum! Run /post for info."
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
        continue

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
#         continue
#
#     except Exception as e:
#         # Any other exception - something happened, exit
#         print('Reading error: '.format(str(e)))
#         sys.exit()