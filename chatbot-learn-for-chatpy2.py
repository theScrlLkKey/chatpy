import socket
import select
import errno
import time
import urllib.request
import random
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

cb = 0
stuffToSay = []
about = """
Hi! I'm Chatbot! I learn from what is in chat!
So if you spam 'the' a lot, I will say 'the' more often!
Please activate me (with !chatbot on) after you have said something at least once.
To train me, turn me off with !chatbot off,
then have a normal, one-sided conversation with yourself for about 15 messages, and turn me back on!

Note: I am not any form of ai or neural network, so don't expect much from me.
"""

def getStr(t):
    a = ''
    while t > 1:
        a = a + random.choice(stuffToSay) + ' '
        t=t-1
    a = a + random.choice(stuffToSay) + '.'
    return a
    

    

    



HEADER_LENGTH = 10



ip = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')





#IP = str(input('Ip Address: '))
#PORT = int(input('Port(Must be a number): '))
#my_username = input("Username: ")

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
my_username = 'Chatbot'


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



##message = my_username + ' joined the chat!'
##
##message = message.encode('utf-8')
##message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
##client_socket.send(message_header + message)
while True:
    try:
        # Now we want to loop over received messages (there might be more than one) and print them
        while True:

            # Receive our "header" containing username length, it's size is defined and constant
            username_header = client_socket.recv(HEADER_LENGTH)

            # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
            if not len(username_header):
                sys.exit()

            # Convert header to int value
            username_length = int(username_header.decode('utf-8').strip())

            # Receive and decode username
            username = client_socket.recv(username_length).decode('utf-8')

            # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
            message_header = client_socket.recv(HEADER_LENGTH)
            message_length = int(message_header.decode('utf-8').strip())
            message = client_socket.recv(message_length)
            try:
                if 'joined the chat!' in message.decode('utf-8') or 'left the chat!' in message.decode('utf-8') or username == 'enc_distr' or '!usetaken' in message.decode('utf-8') or '!erelog' in message.decode('utf-8'):
                    message = message.decode('utf-8')
                    rmessage = message
                else:
                    message = decrypt(message, key)
                    message = message.decode('utf-8')
                    rmessage = message
            except:
                message = 'Null'
                rmessage = message

            # Print message
            if message == '!chatbot on':
                cb = 1
                smessage = 'Hi peeps its chatbot!!!'

                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
                
            elif '!chatbot off' in message:
                cb = 0
                smessage = "Ok, chatbot go bye bye."
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            elif '!chatbot about' in message:
                
                smessage = about
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)



            
            talk = random.randint(1,2)
            if talk == 2:
                talk = random.randint(1,2)
            if talk == 1 and cb == 1:
                smessage = getStr(random.randint(1,5))
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            if username != 'enc_distr':
                stuffToSay=stuffToSay+list(rmessage.split(" "))
            print(stuffToSay)
                


            

    except IOError as e:
        # This is normal on non blocking connections - when there are no incoming data error is going to be raised
        # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
        # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
        # If we got different error code - something happened
        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
            print('Reading error: {}'.format(str(e)))
            sys.exit()

        # We just did not receive anything
        continue
    
##while True:
##
##
##    message = ''
##    
##    
##
##    # If message is not empty - send it
##    if message:
##
##        # Encode message to bytes, prepare header and convert to bytes, like for username above, then send
##        message = message.encode('utf-8')
##        message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
##        client_socket.send(message_header + message)
##
##    try:
##        # Now we want to loop over received messages (there might be more than one) and print them
##        while True:
##
##            # Receive our "header" containing username length, it's size is defined and constant
##            username_header = client_socket.recv(HEADER_LENGTH)
##
##            # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
##            if not len(username_header):
##                print('Connection closed by the server')
##                sys.exit()
##
##            # Convert header to int value
##            username_length = int(username_header.decode('utf-8').strip())
##
##            # Receive and decode username
##            username = client_socket.recv(username_length).decode('utf-8')
##
##            # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
##            message_header = client_socket.recv(HEADER_LENGTH)
##            message_length = int(message_header.decode('utf-8').strip())
##            message = client_socket.recv(message_length).decode('utf-8')
##
##            # Print message
##            print(f'{username}: {message}')
##
##    except IOError as e:
##        # This is normal on non blocking connections - when there are no incoming data error is going to be raised
##        # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
##        # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
##        # If we got different error code - something happened
##        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
##            print('Reading error: {}'.format(str(e)))
##            sys.exit()
##
##        # We just did not receive anything
##        continue
##
##    except Exception as e:
##        # Any other exception - something happened, exit
##        print('Reading error: '.format(str(e)))
##        sys.exit()
##
##
