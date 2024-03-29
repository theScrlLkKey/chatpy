import socket
import errno
import time
import urllib.request
from cryptography.fernet import Fernet
from pythonping import ping
from pynput import keyboard
import ctypes
import plyer.platforms.win.notification
# change back to win10toast when nuitka gets updated


def getWindow():
    hwnd = ctypes.windll.user32.GetForegroundWindow()
    length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
    buff = ctypes.create_unicode_buffer(length + 1)
    ctypes.windll.user32.GetWindowTextW(hwnd, buff, length + 1)
    return hwnd


def encrypt(message, key):
    """
    Given a filename (str) and key (bytes), it encrypts the file and write it
    """

    f = Fernet(key)
    file_data = message

    encrypted_data = f.encrypt(file_data)
    return encrypted_data


def decrypt(encrypted_data, key):
    """
    Given a filename (str) and key (bytes), it decrypts the file and write it
    """

    f = Fernet(key)

    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data


def intping(destToPing):
    # destToPing = 'www.google.com'
    response_list = ping(destToPing, size=40, count=8)
    ptime = response_list.rtt_avg_ms
    return ptime

# there is definitely a better way to do the following bit of code, but i cant think of it currently. belive me tho, i dont want to do it like this
def get_sendmsg():
    # im sorry programming gods
    global key
    global sttime
    global stimef
    global message
    global username
    global usrstatus
    global trytoreauth
    global named_tuple
    global message_header
    global message_length
    global username_header
    global username_length

    message = input(f'{print_time_str} |{my_username}{sep} ')
    senmessage = message
    if message == 'exit' or message == 'Exit':
        if stlent == 'y':
            # ?
            dummy_var = 1
        else:
            message = my_username + ' has left the chat!'
            message = message.encode('utf-8')
            message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            client_socket.send(message_header + message)
        exit()
    if message == '!erelog':
        message = '!relog'
        message = message.encode('utf-8')

        message = encrypt(message, key)
        message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')

        client_socket.send(message_header + message)
        print(f'Server{sep} Serverwide restart requested')
        while True:
            try:
                # Receive our "header" containing username length, it's size is defined and constant
                username_header = client_socket.recv(HEADER_LENGTH)

                # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
                if not len(username_header):
                    print('Connection closed by the server')
                    input('Press enter to exit...')
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
                    print(f'Server{sep} Restart complete')
                    break
                else:
                    continue
            except:
                continue
    elif message == '!relog':
        message = '!erelog'
        message = message.encode('utf-8')

        message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')

        client_socket.send(message_header + message)
        print(f'Server{sep} Restart requested')
        while True:
            try:
                # Receive our "header" containing username length, it's size is defined and constant
                username_header = client_socket.recv(HEADER_LENGTH)

                # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
                if not len(username_header):
                    print('Connection closed by the server')
                    input('Press enter to exit...')
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
                    print(f'Server{sep} Restart complete')
                    break
                else:
                    continue
            except:
                continue

    elif message == '!ping':
        print('Server' + sep + ' Your ping is ' + str(intping(IP)) + 'ms.')

    # If message is not empty - send it
    elif message:
        if '!<' in message:
            usrstatus = message.split(' ', 1)[1]
            print(f'Status set to: {my_username} {usrstatus}')

        elif message == '/post list':
            message = '/post list_int'
        elif message == '/post new':
            title = input('Post title: ')
            post = input('Write post:\n')
            message = f'/post new {post} ;;; {title}'
        # Encode message to bytes, prepare header and convert to bytes, like for username above, then send
        message = message.encode('utf-8')
        try:
            message = encrypt(message, key)
        except:
            print(f'Server{sep} Message failed to send. Refreshing encryption key.')
            message = '!erelog'
            message = message.encode('utf-8')

            message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')

            client_socket.send(message_header + message)
            # print('Re-authentication requested...')
            trytoreauth = 10
            while True:
                trytoreauth -= 1
                try:
                    # Receive our "header" containing username length, it's size is defined and constant
                    username_header = client_socket.recv(HEADER_LENGTH)

                    # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
                    if not len(username_header):
                        print('Connection closed by the server')
                        input('Press enter to exit...')
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
                        print(f'Server{sep} Key refreshed')
                        message = encrypt(message, key)
                        break
                    else:
                        continue
                except:
                    continue

        message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')

        client_socket.send(message_header + message)

        named_tuple = time.localtime()  # get struct_time
        stimef = int(time.strftime("%M", named_tuple))
        sttime = stimef
        sttime += 360


path = 'config.txt'

HEADER_LENGTH = 10

# get current hwnd hopefully
curhwnd = getWindow()

try:
    ip = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')
except:
    print('No internet!')
    input('Press enter to exit...')
    exit()

IP = '127.0.0.1'
PORT = 1234
stlent = ''
sep = ':'
hbc = ''
sendm = 'm'
shct = 'Tab + Space'


#print('Starting chatpy now...')
#time.sleep(1)

load = input('Load config from last time? (Y/n): ').lower()
if load == 'y' or load == '':
    try:

        with open(path, 'r') as data:
            conf = data.read()
            exec(conf)
    except FileNotFoundError:
        print('No config file found. Loading defaults...')
        with open(path, 'w+') as data:
            data.write("""
IP = '""" + str(IP) + """'
PORT = """ + str(PORT) + """
sep = '""" + str(sep) + """'
stlent = '""" + str(stlent) + """' 
hbc = '""" + str(hbc) + """' 
sendm = '""" + str(sendm) + "'")


else:    
    IP = str(input('IP Address/hostname: '))
    while True:
        try:
            PORT = int(input('Port: '))
            break
        except:
            print('Port must be a number.')
        
    sep = input('Separator between username and message (Eg. Tim>> hi or Tim: hi): ')
    sendm = input('Use modern (ctrl+shift) or legacy (ctrl+c, NOT SUPPORTED IN THIS VERSION) shortcut to enter send mode? (M/l): ').lower()
    if sendm == '':
        sendm = 'm'
    hbc = input('Hide (most) bot commands? (y/N): ').lower()
#    stlent = input('Stealth entry/exit? Not supported on servers running webmaster. (y/N)') i am removing this because reasons.  thnik about it.
    stlent = ''
    with open(path,'w+') as data:
        data.write("""
IP = '"""+str(IP)+"""'
PORT = """+str(PORT)+"""
sep = '"""+str(sep)+"""'
stlent = '"""+str(stlent)+"""' 
hbc = '"""+str(hbc) + """' 
sendm = '""" + str(sendm) + "'")

#my_username = input("Username: ")

# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to a given ip and port
while True:
    try:

        client_socket.connect((IP, PORT))
        break
    except:
        print('Error connecting to server. Check IP/port and try again.')
        IP = str(input('IP Address: '))
        while True:
            try:
                PORT = int(input('Port: '))
                break
            except:
                print('Port must be a number.')
        with open(path,'w+') as data:
            data.write("""
IP = '"""+str(IP)+"""'
PORT = """+str(PORT)+"""
sep = '"""+str(sep)+"""'
stlent = '"""+str(stlent)+"""' 
hbc = '"""+str(hbc) + """' 
sendm = '""" + str(sendm) + "'")
        
hotkey_active = False

if sendm == 'm':
    shct = 'Ctrl + Shift'
elif sendm == 'l':
    shct = 'Ctrl + C'

print('Connected to '+IP+':'+str(PORT)+' (Ping: '+str(intping(IP))+f'ms)! Press {shct} to talk, use !msg <username> <message> to send a private mesage, use @<username> to ping, and type exit to quit.')
my_username = input("Username: ")
my_username = my_username.replace(' ', '_')


# Set connection to non-blocking state, so .recv() call won;t block, just return some exception we'll handle
client_socket.setblocking(False)

# Prepare username and header and send them
# We need to encode username to bytes, then count number of bytes and prepare header of fixed size, that we encode to bytes as well
username = my_username.encode('utf-8')
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
client_socket.send(username_header + username)


print_time_str = 'null'

if stlent == 'y':
    dummy_var = 1
else:
    named_tuple = time.localtime()  # get struct_time
    stimef = int(time.strftime("%M", named_tuple))
    sttime = stimef
    sttime += 15
    message = my_username + ' joined the chat!'
    "' (' + ip + ')' +"
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
                input('Press enter to exit...')
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
    smessage = '!ip ' + ip
    message = smessage.encode('utf-8')
    message = encrypt(message, key)
    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(message_header + message)


usrstatus = ''

# init keyboard listener
if sendm == 'm':
    def on_activate():
        # OH MY GOD AAAA
        global hotkey_active
        hotkey_active = True


    def for_canonical(f):
        return lambda k: f(l.canonical(k))


    hotkey = keyboard.HotKey({keyboard.Key.ctrl, keyboard.Key.shift}, on_activate)

    l = keyboard.Listener(
        on_press=for_canonical(hotkey.press),
        on_release=for_canonical(hotkey.release))
    l.start()
else:
    pass

while True:

    # Wait for user to input a message
    try:
        named_tuple = time.localtime()  # get struct_time
        print_time_str = time.strftime("%I:%M%p", named_tuple)

        named_tuple = time.localtime()  # get struct_time
        curtime = int(time.strftime("%M", named_tuple))
        if curtime > sttime:
            message = my_username + ' has left the chat!'
            message = message.encode('utf-8')
            message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            client_socket.send(message_header + message)
            print('Disconnected. You were idle for too long.')
            client_socket.close()
            input('Press enter to exit...')
            exit()

        message = ''
        #time.sleep(0.001)


        # If message is not empty - send it
        if message:

            # Encode message to bytes, prepare header and convert to bytes, like for username above, then send

            message = message.encode('utf-8')
            message = encrypt(message, key)
            message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            client_socket.send(message_header + message)

        if hotkey_active and getWindow() == curhwnd:
            get_sendmsg()
            hotkey_active = False
        elif hotkey_active:
            hotkey_active = False

        try:
            # Now we want to loop over received messages (there might be more than one) and print them
            while True:

                # Receive our "header" containing username length, it's size is defined and constant
                username_header = client_socket.recv(HEADER_LENGTH)

                # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
                if not len(username_header):
                    print('Connection closed by the server')
                    input('Press enter to exit...')
                    exit()

                # Convert header to int value
                username_length = int(username_header.decode('utf-8').strip())

                # Receive and decode username
                username = client_socket.recv(username_length).decode('utf-8')

                # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
                message_header = client_socket.recv(HEADER_LENGTH)
                message_length = int(message_header.decode('utf-8').strip())
                message = client_socket.recv(message_length)
                if 'joined the chat!' in message.decode('utf-8') or 'left the chat!' in message.decode('utf-8') or username == 'enc_distr' or '!usetaken' in message.decode('utf-8') or '!erelog' in message.decode('utf-8') or '!req' in message.decode('utf-8'):
                    message = message.decode('utf-8')
                    #print('not')
                else:
                    #print('dec')
                    try:
                        message = decrypt(message, key)
                        message = message.decode('utf-8')
                    except:
                        print(f'{username}{sep} Message corrupt')
                        message = '!erelog'
                        message = message.encode('utf-8')

                        message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')

                        client_socket.send(message_header + message)
                        print(f'Server{sep} Connection error')
                        trytoreauth = 10
                        while True:
                            trytoreauth -= 1
                            try:
                                # Receive our "header" containing username length, it's size is defined and constant
                                username_header = client_socket.recv(HEADER_LENGTH)

                                # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
                                if not len(username_header):
                                    print('Connection closed by the server')
                                    input('Press enter to exit...')
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
                                    print(f'Server{sep} Re-connected')
                                    break
                                else:
                                    continue
                            except:
                                continue



                # Print message
                if hbc == 'y' and '!webmaster' in message  or '!bug' in message or '!chatbot' in message: # or '!bug' in message or '!chatbot' in message or '/post' in message
                    continue
                elif message == '!usetaken '+ my_username:
                    print('That username is taken.')
                    message = my_username + ' was taken. Disconnected!'
                    message = message.encode('utf-8')
                    message = encrypt(message, key)
                    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(message_header + message)
                    client_socket.close()
                    input('Press enter to exit...')
                    exit()
                elif username == 'enc_distr' or '!req' in message:
                    continue
                elif '/post ' in message and username != 'Forum post manager':
                    continue
                elif '!file^^^' in message:
                    continue
                elif username == my_username and '!ip ' not in message:
                    print(f'{print_time_str} |Server{sep} {message}')
                    time.sleep(1)
                    message = '!usetaken ' + username
                    message = message.encode('utf-8')
                    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(message_header + message)

                elif message == '!kick '+ my_username:
                    print('You were disconnected.')
                    message = my_username + ' has left the chat!'
                    message = message.encode('utf-8')
                    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(message_header + message)
                    client_socket.close()
                    input('Press enter to exit...')
                    exit()
                elif '!ban ' in message:
                    continue
                elif ' was taken. Disconnected!' in message:
                    print(f'{print_time_str} |Server{sep} {message}')
                elif message == '!relog':
                    print(f'Server{sep} Serverwide restart requested')
                    while True:
                        try:
                            # Receive our "header" containing username length, it's size is defined and constant
                            username_header = client_socket.recv(HEADER_LENGTH)

                            # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
                            if not len(username_header):
                                print('Connection closed by the server')
                                input('Press enter to exit...')
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
                                print(f'Server{sep} Restart complete')
                                break
                            else:
                                continue
                        except:
                            continue


                elif message == '!erelog':
                    continue
                elif '!kick' in message:
                    continue
                elif '!usetaken' in message:
                    continue
                elif '!ip ' in message:
                    continue
                elif message == '!> ' + my_username:
                    message = '!< ' + usrstatus
                    message = message.encode('utf-8')
                    message = encrypt(message, key)
                    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(message_header + message)

                elif message == '!chkusr':
                    smessage = '!chkusrback'
                    message = smessage.encode('utf-8')
                    message = encrypt(message, key)
                    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(message_header + message)
                elif message == '!chkusrback':
                    continue
                elif '!reip ' in message and my_username in message:
                    time.sleep(0.5)
                    smessage = '!ip ' + ip
                    message = smessage.encode('utf-8')
                    message = encrypt(message, key)
                    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(message_header + message)
                elif '!reip' in message:
                    continue
                elif '!msg' in message:
                    try:
                        if my_username == message.split(' ')[1]:
                            message = message.split(' ', 2)
                            del message[0]
                            del message[0]

                            if 'fetchedpost' in ''.join(message):
                                message = ''.join(message)
                                message = message.split(' ;`; ')
                                message.pop(0)
                                print(f'{message[0]} ({message[1]} - {message[2]})\n\n{message[3]}')
                            elif 'postlistint' in ''.join(message):
                                message = ''.join(message)
                                message = message.split(' ;;; ')
                                message.pop(0)
                                newline = '\n'
                                print(f'All posts, sorted old to new: \n{newline.join(reversed(message))}')
                            else:
                                print(f'''{print_time_str} |Private message from {username}{sep} {', '.join(message)}''')
                                if not getWindow() == curhwnd:
                                    plyer.platforms.win.notification.instance().notify(title=f'Private message from: {username} | Chatpy', message=', '.join(message), timeout=3)
                    except:
                        continue


                elif '!< ' in message:
                    print(f'{print_time_str} |​⃰ {username} {message.split("!< ")[1]}')

                elif '/me ' in message:
                    print(f'{print_time_str} |​⃰ {username} {message.split("/me ")[1]}')
                elif f'@{my_username}' in message:
                    print(f'{print_time_str} |{username}{sep} {message}')
                    try:
                        if not getWindow() == curhwnd:
                            plyer.platforms.win.notification.instance().notify(title=f'{username} | Chatpy', message=message, timeout=3)
                        # toaster.show_toast(f'{username} | Chatpy', message, icon_path=None, duration=3, threaded=False)
                    except Exception as e:
                        print(e)
                        input('... ')

                elif 'joined the chat!' in message or 'left the chat!' in message:
                    print(f'{print_time_str} |Server{sep} {message}')

                else:
                    print(f'{print_time_str} |{username}{sep} {message}')


        except IOError as e:
            # This is normal on non blocking connections - when there are no incoming data error is going to be raised
            # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
            # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
            # If we got different error code - something happened
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print('Reading error: {}'.format(str(e)))
                client_socket.close()
                input('Press enter to exit...')
                exit()

            # We just did not receive anything
            time.sleep(0.05)

        except Exception as e:
            # Any other exception - something happened, exit
            print('Error: ' + str(e))
            client_socket.close()
            input('Press enter to exit...')
            exit()

    except KeyboardInterrupt: # legacy input handler
        try:
            if sendm == 'l':
                get_sendmsg()
            else:
                continue
        except:
            print('')


input('Press enter to exit...')




