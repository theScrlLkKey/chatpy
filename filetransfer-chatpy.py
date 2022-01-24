import socket
import errno
import time
import urllib.request
import subprocess
import sys
import os
import struct
import binascii

def rawbytes(s):
    """Convert a string to raw bytes without encoding"""
    outlist = []
    for cp in s:
        num = ord(cp)
        if num < 255:
            outlist.append(struct.pack('B', num))
        elif num < 65535:
            outlist.append(struct.pack('>H', num))
        else:
            b = (num & 0xFF0000) >> 16
            H = num & 0xFFFF
            outlist.append(struct.pack('>bH', b, H))
    return b''.join(outlist)

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
try:
    from cryptography.fernet import Fernet
except:
    print('Fetching requirements...')
    install ('cryptography')
try:
    from pythonping import ping
except:
    install ('pythonping')
def encrypt(message, key):
    """
    Given a filename (str) and key (bytes), it encrypts the file and write it
    """

    f = Fernet(key)
    file_data = message


    encrypted_data = f.encrypt(file_data)
    return(encrypted_data)

def decrypt(encrypted_data, key):
    """
    Given a filename (str) and key (bytes), it decrypts the file and write it
    """

    f = Fernet(key)


    decrypted_data = f.decrypt(encrypted_data)
    return(decrypted_data)



def ping(destToPing):
    from pythonping import ping
    # destToPing = 'www.google.com'
    response_list = ping(destToPing, size=40, count=8)
    ptime = response_list.rtt_avg_ms
    return(ptime)

path = 'ftconf.txt'

HEADER_LENGTH = 10

try:
    ip = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')
except:
    print('No internet!')
    exit()

IP = '127.0.0.1'
PORT = 1234
stlent = ''
sep = ':'
hbc = ''


#print('Starting chatpy now...')
#time.sleep(1)

load = input('Load config from last time? (Y/n)')
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
        PORT = """ + str(PORT) + """ """)



else:    
    IP = str(input('Ip Address/hostname: '))
    while True:
        try:
            PORT = int(input('Port: '))
            break
        except:
            print('Port must be a number.')
        
    sep = input('Separator between username and message(Eg. Tim>> hi or Tim: hi): ')
    hbc = input('Hide (most) bot commands? (y/N)')
#    stlent = input('Stealth entry/exit? Not supported on servers running webmaster. (y/N)') i am removing this because reasons.  thnik about it.
    stlent = ''
    with open(path,'w+') as data:
        data.write("""
IP = '"""+str(IP)+"""'
PORT = """+str(PORT)+""" """)


#my_username = input("Username: ")

# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# os.chdir('..')
# Connect to a given ip and port
while True:
    try:

        client_socket.connect((IP, PORT))
        break
    except:
        print('Error connecting to server. Check ip and port and try again.')
        IP = str(input('Ip Address: '))
        while True:
            try:
                PORT = int(input('Port: '))
                break
            except:
                print('Port must be a number.')
        with open(path,'w+') as data:
            data.write("""
IP = '"""+str(IP)+"""'
PORT = """+str(PORT)+""" """)
        

print('Connected to '+IP+':'+str(PORT)+' (Ping: '+str(ping(IP))+'ms)! Press Ctrl + C to enter file send mode, default is receive mode.')
my_username = input("Username: ")
my_username = my_username.replace(' ', '_')


# Set connection to non-blocking state, so .recv() call won;t block, just return some exception we'll handle
client_socket.setblocking(False)

# Prepare username and header and send them
# We need to encode username to bytes, then count number of bytes and prepare header of fixed size, that we encode to bytes as well
username = my_username.encode('utf-8')
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
client_socket.send(username_header + username)


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

fof = False
whfile_data = ''
rcvitr = 1
usrstatus = ''
while True:


    # Wait for user to input a message
    try:
        named_tuple = time.localtime()  # get struct_time
        curtime = int(time.strftime("%M", named_tuple))

        message = ''
        #time.sleep(0.001)
        
        

        # If message is not empty - send it
        if message:

            # Encode message to bytes, prepare header and convert to bytes, like for username above, then send

            message = message.encode('utf-8')
            message = encrypt(message, key)
            message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            client_socket.send(message_header + message)

        try:
            # Now we want to loop over received messages (there might be more than one) and print them
            while True:

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
                if 'joined the chat!' in message.decode('utf-8') or 'left the chat!' in message.decode('utf-8') or username == 'enc_distr' or '!usetaken' in message.decode('utf-8') or '!erelog' in message.decode('utf-8')  or '!req' in message.decode('utf-8'):
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
                                    # print(f'Server{sep} Re-connected')
                                    break
                                else:
                                    continue
                            except:
                                continue



                # Print message
                if hbc == 'y' and '!webmaster' in message or '!bug' in message or '!chatbot' in message:
                    continue
                elif message == '!usetaken '+ my_username:
                    print('That username is taken.')
                    message = my_username + ' was taken. Disconnected'
                    message = message.encode('utf-8')
                    message = encrypt(message, key)
                    message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                    client_socket.send(message_header + message)
                    exit()
                elif username == 'enc_distr' or '!req' in message:
                    continue
                elif username == my_username:
                    # print(f'Server{sep} {message}')
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
                    exit()
                elif '!ban ' in message:
                    continue
                elif message == '!relog':
                    # print(f'Server{sep} Serverwide restart requested')
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
                # elif '!msg' in message:
                #     try:
                #         if my_username == message.split(' ')[1]:
                #             message = message.split(' ', 2)
                #             del message[0]
                #             del message[0]
                #             # print(f'''Private message from {username}{sep} {', '.join(message)}''')
                #     except:
                #         continue


                # save recived file

                elif '!file' in message:
                    try:
                        if my_username == message.split('^^^')[1]:

                            filename = message.split('^^^')[3]

                            file_data = message.split('^^^')[2]
                            percom = int(message.split('^^^')[4])
                            complete = int(message.split('^^^')[5])
                            print(file_data)
                            if complete > 50000000:
                                if not fof:
                                    file = open(filename, "ab")
                                    fof = True
                                file.write(bytes.fromhex(file_data))  #b"".join(whfile_data.encode().decode('unicode_escape'))
                            else:
                                whfile_data += file_data
                            print(f'{rcvitr}, {percom + len(file_data)}, {complete}')
                            rcvitr += 1

                            if percom + len(file_data) >= complete:
                                try:
                                    if complete > 50000000:
                                        file.close()
                                    else:
                                        with open(filename, "wb") as file:
                                            file.write(bytes.fromhex(whfile_data))
                                    print(f'Received file from {username}')
                                except Exception as e:
                                    input(str(e))
                                rcvitr = 1
                                whfile_data = ''
                                fof = False




                    except Exception as e:
                        input(str(e))



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

        except Exception as e:
            # Any other exception - something happened, exit
            #print('Reading error: '.format(str(e)))
            exit()
    except KeyboardInterrupt:
        filenamef = ''
        usenmtos = ''
        packlen = 1
        try:
            filenamef = input('Path to file: ')
            usenmtos = input('Send to who: ')
            packlen = int(input('Length of packet (24000): '))
            sectoslep = float(input('Time between packets (0.03): '))

        except Exception as e:
            input(str(e))
            continue

        with open(filenamef, "rb") as file:
            file_dataf = file.read()

        file_dataf = bytes.hex(file_dataf)
        endper = len(file_dataf)


        if len(file_dataf) < packlen:
            startper = len(file_dataf)
            message = f'!file^^^{usenmtos}^^^{file_dataf}^^^{filenamef}^^^{startper}^^^{endper}'
            message = message.encode('utf-8')
            try:
                message = encrypt(message, key)
            except:
                print(f'Message failed to send.')
            message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            client_socket.send(message_header + message)
        else:
            startper = packlen

        fdc_itr_num = 0

        # file_dataf = str(file_dataf)
        # file_dataf = file_dataf[2:]
        # file_dataf = file_dataf[:-1]
        file_datafcut = [file_dataf[i:i + packlen] for i in range(0, len(file_dataf), packlen)]
        # file_datafcut.append('') # add one so receiver will detect end




        while startper < endper:
            print(file_datafcut[fdc_itr_num])
            message = f'!file^^^{usenmtos}^^^{file_datafcut[fdc_itr_num]}^^^{filenamef}^^^{startper}^^^{endper}'
            # message = '!file^^^'.encode("utf-8") + usenmtos.encode("utf-8") + '^^^'.encode("utf-8") + file_datafcut[fdc_itr_num] + '^^^'.encode("utf-8") + filenamef.encode("utf-8") + '^^^'.encode("utf-8") + str(startper).encode("utf-8") + '^^^'.encode("utf-8") + str(endper).encode("utf-8")
            # Encode message to bytes, prepare header and convert to bytes then send
            message = message.encode('utf-8')
            try:
                message = encrypt(message, key)
            except:
                print(f'Message failed to send.')

            message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            while True:
                try:
                    client_socket.send(message_header + message)
                    fdc_itr_num += 1
                    startper += packlen
                    break
                except Exception as e:
                    print(str(e))
                    time.sleep(0.4)
            print(f'{fdc_itr_num}, {startper}, {endper}')
            time.sleep(sectoslep)



        print('Done sending!')


input('Press enter to exit...')




