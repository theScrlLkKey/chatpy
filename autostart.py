import subprocess
import time
import os
from pynput.keyboard import Key, Controller

keyboard = Controller()

# change depending on your servers config
prog_to_launch = ['keep-alive-chatpy2.py', 'ban-for-chatpy2.py', 'bug-for-chatpy2.py', 'webmaster-for-chatpy2.py', 'post-bot-for-chatpy2.py', 'tumbleweed-for-chatpy2.py']
launchitr = 0
ip = input('ip: ')
port = input('port: ')

while True:
    # subprocess.call(['py', '-3', prog_to_launch[launchitr]], creationflags=subprocess.CREATE_NEW_CONSOLE)
    os.startfile(prog_to_launch[launchitr])
    # input port and ip
    time.sleep(0.5)
    keyboard.type(str(launchitr + 1))
    keyboard.press(Key.enter)
    keyboard.release(Key.enter)
    time.sleep(2)
    keyboard.type(ip)
    keyboard.press(Key.enter)
    keyboard.release(Key.enter)
    keyboard.type(port)
    keyboard.press(Key.enter)
    keyboard.release(Key.enter)

    launchitr += 1
