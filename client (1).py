import struct
import socket
import random
import pickle
import base64
import marshal
import types
import argparse
from sys import exit


def send_msg(sock, msg):
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)


def recv_msg(sock):
    raw_msglen = sock.recv(4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]

    return sock.recv(msglen)


def enc_msg(key, msg: bytes):
    if type(msg) == str:
        msg = msg.encode('utf-8')
    if type(key) == str:
        key = int(key)

    char_based_key = key % 256

    ret = []
    for char in msg:
        ret.append(char ^ char_based_key)
        char_based_key = (char_based_key + 13) % 256
    return bytes(ret)


def dec_msg(key, msg):
    return enc_msg(key, msg)


def whitefield_command(variables, variable, value):
    variables[variable] = value


def amir_command(variables, variable, value):
    if not variable in variables:
        variables[variable] = []
    variables[variable].append(value)


def exit_command(variables, variable, value):
    flag = ''
    enc_key = pickle.loads(base64.b64decode(value))
    enc_secret = variables[variable]

    # decrypt secret
    for i in range(len(enc_secret)):
        flag += chr(enc_secret[i] ^ enc_key[i])
    # print(flag)
    # exit(0)
    # variables['flag'] = flag


class CommandHandler:
    def __init__(self) -> None:
        self.variables = {}
        self.commands = {}
        self.commands['whitefield'] = whitefield_command
        self.commands['amir'] = amir_command
        self.commands['exit'] = exit_command
        self.commands['add_new_command'] = self.add_new_command

    def add_new_command(self, command, func):
        func = marshal.loads(base64.b64decode(func))
        self.commands[command] = types.FunctionType(func, globals(), command)

    def handle_command(self, command):
        if type(command) == bytes:
            command = command.decode('utf-8')
        command = command.split(' ')
        if len(command) == 0:
            return
        if command[0] == 'add_new_command':
            self.add_new_command(command[1], command[2])
            return
        if command[0] in self.commands:
            func_to_call = self.commands[command[0]]
            if command[0] != 'add_new_command' and command[0] != 'exit':
                command[2] = int(command[2])
            func_to_call(self.variables, command[1], command[2])
        else:
            print("Unknown command: ", command[0])


def main():
    # parser = argparse.ArgumentParser(description='Client for the AI nation of 0xearth')
    # parser.add_argument('--port', type=int, default=8097, help='Port to connect to')

    # args = parser.parse_args()

    # Create a socket object
    s = socket.socket()

    # Define the port on which you want to connect
    port = 8097  # args.port

    print(f'Connecting to port {port} on localhost')
    # connect to the server on local computer
    try:
        s.connect(('13.37.13.37', port))
    except ConnectionRefusedError:
        print("Connection refused, exiting...")
        exit()

    if not s.getsockname()[0].startswith('13.37'):
        exit()

    try:
        # Diffie Helman Key Swap
        modulus = int(recv_msg(s).decode())
        base = int(recv_msg(s).decode())
        # print(f"Received modulus: {modulus}, base: {base}")
        client_secret = (base + 2) * 15
        step_A = int(recv_msg(s).decode())
        step_B = pow(base, client_secret, modulus)
        send_msg(s, str(step_B).encode())
        key = pow(step_A, client_secret, modulus)
    except Exception as e:
        print("Error in key swap, exiting...")
        print(e)
        exit()

    handler = CommandHandler()
    handler.variables['key'] = key

    if not s.getsockname()[0].endswith('1'):
        exit()

    command_number = 0
    while True:
        msg = recv_msg(s)
        if not msg:
            break

        if msg == b"Invalid response":
            print("Invalid response, exiting...")
            break
        msg = dec_msg(key, msg)

        if msg == 'exit':
            break

        if type(msg) == bytes:
            msg = msg.decode()

        handler.handle_command(msg)
        key = handler.variables['key']
        command_number += 1
        response = "Command number " + str(command_number) + " completed"

        response = enc_msg(key, response.encode())
        send_msg(s, response)

    print("Closing connection... Bye!")


if __name__ == '__main__':
    main()
