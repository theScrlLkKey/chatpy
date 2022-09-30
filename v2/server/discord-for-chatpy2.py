import socket
import select
import errno
import time
import urllib.request
import keyboard
from cryptography.fernet import Fernet
import cv2
import pytesseract
import numpy as np
from PIL import ImageGrab
import time

time.sleep(2)
sentmes = ['you cant send this message via discord integration.', ' ']
lastmes = ''
pytesseract.pytesseract.tesseract_cmd = r'C:/Program Files/Tesseract-OCR/tesseract.exe'

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
my_username = 'Discord bridge'

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
            if 'joined the chat!' in message.decode('utf-8') or 'left the chat!' in message.decode('utf-8') or '!relog' in message.decode('utf-8') or '!req' in message.decode('utf-8'):
                message = message.decode('utf-8')
            else:
                try:
                    message = decrypt(message, key)
                    message = message.decode('utf-8')
                    rmessage = message
                except:
                    continue



            # Print message TOO: add more hidden commands
            if '!msg' in message:
                continue
            elif '@everyone' in message:
                continue
            elif message == '!chkusr':
                smessage = '!chkusrback'
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            else:
                print(f'<{username}> {message}')
                keyboard.write(f'<{username}> {message}\n')




            img = ImageGrab.grab(bbox=(310, 60, 1020, 910))  # discord: 310, 60, 1020, 910 (24px font)
            img_np = np.array(img)
            gray = cv2.cvtColor(img_np, cv2.COLOR_BGR2GRAY)
            # gray, img_bin = cv2.threshold(gray, 128, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
            # gray = cv2.bitwise_not(img_bin)
            cv2.imshow("frame", gray)
            if cv2.waitKey(1) & 0Xff == ord('q'):
                break

            kernel = np.ones((2, 1), np.uint8)
            img = cv2.erode(gray, kernel, iterations=1)
            img = cv2.dilate(img, kernel, iterations=1)
            out_below = pytesseract.image_to_string(img)
            # print(out_below)

            content = out_below

            content = content.split('\n')
            # print(content)
            content = list(filter(None, content))
            del content[-1]
            content = [x for x in content if "<" not in x]
            content = [x for x in content if ">" not in x]
            content = [x for x in content if "+" not in x]

            # print(lastmes + ' -l')
            if content[-1] != lastmes:
                print(content[-1] + ' -c')
                smessage = str(content[-1])
                message = smessage.encode('utf-8')
                message = encrypt(message, key)
                message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
                client_socket.send(message_header + message)
            lastmes = content[-1]








    except IOError as e:
        # This is normal on non blocking connections - when there are no incoming data error is going to be raised
        # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
        # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
        # If we got different error code - something happened
        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
            print('Reading error: {}'.format(str(e)))
            exit()

        # We just did not receive anything
        img = ImageGrab.grab(bbox=(310, 60, 1020, 910))  # discord: 310, 60, 1020, 910 (compact, 110% zoom)
        img_np = np.array(img)
        gray = cv2.cvtColor(img_np, cv2.COLOR_BGR2GRAY)
        # gray, img_bin = cv2.threshold(gray, 128, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
        # gray = cv2.bitwise_not(img_bin)
        cv2.imshow("frame", gray)
        if cv2.waitKey(1) & 0Xff == ord('q'):
            break

        kernel = np.ones((2, 1), np.uint8)
        img = cv2.erode(gray, kernel, iterations=1)
        img = cv2.dilate(img, kernel, iterations=1)
        out_below = pytesseract.image_to_string(img)
        # print(out_below)

        content = out_below

        content = content.split('\n')
        # print(content)
        content = list(filter(None, content))
        del content[-1]
        content = [x for x in content if ">" not in x]
        content = [x for x in content if "<" not in x]
        content = [x for x in content if "+" not in x]

        # print(lastmes + ' -l')
        if content[-1] != lastmes:
            print(content[-1] + ' -c')
            smessage = str(content[-1])
            message = smessage.encode('utf-8')
            message = encrypt(message, key)
            message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')
            client_socket.send(message_header + message)
        lastmes = content[-1]
