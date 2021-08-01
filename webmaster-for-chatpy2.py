import socket
import select
import errno
import time
import urllib.request
import sys
from cryptography.fernet import Fernet
import random


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


def setup():
    print('kjdshdsgfjkhfjdg')


chtname = 'A chatroom'
chttop = 'Everything :)'
uservar = ['Webmaster, ']
about = """
Hi. I'm Decky. The guy who made this thing. This chat program was made in python 3 with socket.
Source code for the server, client, and bot is available over at lightos.ddns.net/downloads.
On this server we have the Webmaster and Chatbot, both of which I made myself.
If you want to learn more about chatbot do !.chatbot about.
If you want to report a bug, do !.bug report <problem here> and I will get to it asap!
Have fun and be sure to do !.webmaster rules to see the rules!

Note: the server and client were made in two days as a side project so there will definitely be bugs I haven't caught.
Note 2: to run the above commands, omit the . from the beginning of the command.
"""
rules = """
Rule 0.5: always copy your rules from a bigger platform.

Rule 0.8: find that irc, the only big platform like yours, doesn't have any real rules.

Rule 0.85: give up and write your own rules.

Rule 1: Don't spam. Chatbot doesn't like it, and neither do I.

Rule 2: Don't use Unicode characters/emojis, please.  The server finds that annoying (and Chatbot does too).

Rule 3: I know swearing is fun, but Chatbot is young and we don't want to teach him curses quite yet. 

Rule 4: Don't annoy people on purpose. You WILL get tempbanned.

Rule 5: Chatbot gets reset every time I have to reset the server due to crashes, and everyone gets kicked. Please don't purposefully crash the server.

Rule 6: If/when the server crashes and has to restart, teach Chatbot this link: https://www.youtube.com/watch?v=dQw4w9WgXcQ (please don't this is a joke lol)

Rule 7: Stop reading these immediately and go have fun!

Rule 8: I said stop.

Rule 9: No.

Rule 10: STOP!

Rule 11: DON'T READ ANY FURTHER!

Rule 12: DON'T DO ITTTTTTTTTTT

Rule 13: lol
"""

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
my_username = 'Webmaster'

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

##message = my_username + ' (' + ip +')' + ' joined the chat!'
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
            usernamelist = username + ', '
            # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
            message_header = client_socket.recv(HEADER_LENGTH)
            message_length = int(message_header.decode('utf-8').strip())
            message = client_socket.recv(message_length)
            ogmessage = message
            if 'joined the chat!' in message.decode('utf-8') or 'left the chat!' in message.decode(
                    'utf-8') or '!relog' in message.decode('utf-8'):
                message = message.decode('utf-8')
            else:
                message = decrypt(message, key)
                message = message.decode('utf-8')

            # Print message
            if message == '!webmaster greet':
                smessage = 'Hi!'
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            elif message == '!webmaster':
                smessage = "Hello, I'm the Webmaster. Do !webmaster commands to see the things I can do!"
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            elif message == '!webmaster commands':
                smessage = f'!msg {username} Commands: greet, name, topic, myname, time, userlist, about, rules, say <thing to say>, math <equation>, randhex, randnum <number of digits>. Put a !.webmaster before any of these commands (remove the . ). Non-webmaster commands: !.msg <username> <message>, !.relog, !.ping, !.< <status>, !.> <username> (remove the . )'
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            elif message == '!webmaster name':
                smessage = 'The name of this chatroom is: ' + chtname
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            elif message == '!webmaster rename':
                smessage = 'Asking for name now...'
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
                chtname = input('Name? ')
            elif message == '!webmaster topic':
                smessage = 'The topic of this chatroom is: ' + chttop
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            elif message == '!webmaster changetop':
                smessage = 'Asking for topic now...'
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
                chttop = input('Topic? ')
            elif message == '!webmaster myname':
                smessage = f'!msg {username} Your name is: ' + username
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            elif message == '!webmaster time':
                named_tuple = time.localtime()  # get struct_time
                ctime = time.strftime("%m/%d/%Y, %I:%M:%S %p", named_tuple)
                smessage = 'The time is: ' + ctime
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            # elif message == '!webmaster userlist':
            #     userlst = ''
            #     for value in uservar:
            #         userlst = userlst + value
            #     smessage = userlst
            #     message = smessage.encode('utf-8')
            #     message = encrypt(message, key)
            #     message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            #     client_socket.send(message_header + message)
            elif message == '!webmaster userlist':
                ogusername = str(username)
                usercount = 1
                userlst = 'Webmaster'
                rtrys = 50
                smessage = '!chkusr'
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
                print('Asking users')
                time.sleep(1)
                retrys = 4
                while True:
                    # print(rtrys)
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
                        if 'joined the chat!' in message.decode('utf-8') or 'left the chat!' in message.decode(
                                'utf-8') or '!relog' in message.decode('utf-8'):
                            message = message.decode('utf-8')
                        else:
                            message = decrypt(message, key)
                            message = message.decode('utf-8')
                        if message == '!chkusrback':
                            userlst = userlst + ', ' + username
                            usercount = usercount + 1

                        else:
                            print('user did not check back')

                        continue
                    except:
                        if retrys < 1:
                            # smessage = userlst
                            # message = smessage.encode('utf-8')
                            # message = encrypt(message, key)
                            # message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                            # client_socket.send(message_header + message)

                            # print(userlst)
                            # rtrys = rtrys - 1
                            # if rtrys < 0:
                            userlst += '''
Total users online: ''' + str(usercount)
                            smessage = '!msg ' + ogusername + ' ' + userlst
                            # print(smessage)
                            message = smessage.encode('utf-8')
                            message = encrypt(message, key)
                            message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                            client_socket.send(message_header + message)
                            break
                        else:
                            time.sleep(0.2)
                            retrys -= 1



            elif message == '!webmaster about':
                smessage = about
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            elif message == '!webmaster rules':
                smessage = '!msg ' + username + ' ' + rules
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            elif message == '!webmaster setup':
                smessage = 'Starting setup...'
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
                setup()
            elif '!webmaster say ' in message:
                ttsay = message.replace('!webmaster say ', '')
                smessage = ttsay
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            elif '!webmaster math ' in message:
                ttsay = message.strip('!webmaster math ')
                try:
                    print(ttsay)
                    ttsay = 'ttsay = ' + ttsay
                    exec(ttsay)
                    if type(ttsay) == int or type(ttsay) == float:
                        ttsay = str(ttsay)
                    else:
                        ttsay = 'Undefined'
                except:
                    ttsay = 'Undefined'
                smessage = ttsay
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            elif message == '!webmaster randhex':
                ttsay = ''
                for i in range(8):
                    ttsay = ttsay + str(random.choice('0123456789abcdef'))
                smessage = ttsay
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            elif '!webmaster randnum ' in message:
                digits = message.strip('!webmaster randnum ')
                if int(digits) > 998:
                    digits = 999
                ttsay = ''
                try:
                    for i in range(int(digits)):
                        ttsay = ttsay + str(random.choice('0123456789'))
                except:
                    ttsay = 'Digit quantity must be a number'
                smessage = str(ttsay)
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            elif message == '!webmaster randnum':
                ttsay = ''
                try:
                    for i in range(int(1)):
                        ttsay = ttsay + str(random.choice('0123456789'))
                except:
                    ttsay = 'Digit quantity must be a number'
                smessage = str(ttsay)
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            elif '!webmaster' in message:
                smessage = "I know you want something from me, but I'm not sure what."
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            elif 'joined the chat!' in message and 'joined the chat!' in ogmessage.decode('utf-8'):
                uservar.append(usernamelist)
                time.sleep(1)
                smessage = '!msg ' + username + " Welcome to " + chtname + ", " + username + "! " + "We're talking about " + chttop + "! Do !webmaster commands to see the things I can do, and please read !webmaster rules and !webmaster about!"
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            # elif 'left the chat!' in message:
            #    uservar.remove(usernamelist)
            #   smessage = "Bye "+username+"!"
            #  message = smessage.encode('utf-8')
            # message = encrypt(message, key)
            # message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            # client_socket.send(message_header + message)

            elif message == '!relog':
                print('Re-authentication requested...')
                while True:
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
                            print('Re-authenticated!')
                            break
                        else:
                            continue
                    except:
                        continue







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
    except:
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
