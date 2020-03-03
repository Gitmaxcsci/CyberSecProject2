"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:



"""

import socket
import os
import pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

host = "localhost"
port = 10001


# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)


# TODO: Generate a cryptographically random AES key
def generate_key():
    # TODO: Implement this function
    rand_key = os.urandom(16)
    return rand_key


# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    # TODO: Implement this function
    server_public_key = RSA.import_key(open(os.path.dirname(__file__) + '/../Server/RSA_keys.pub').read())

    #Encrypt the session key with the servers public RSA key
    cipher_rsa = PKCS1_OAEP.new(server_public_key)
    return cipher_rsa.encrypt(session_key)


# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    # TODO: Implement this function
    message = pad_message(message)
    message = message.encode("utf-8")
    

    server_public_key = RSA.import_key(open(os.path.dirname(__file__) + '/../Server/RSA_keys.pub').read())

    #Encrypt the session key with the servers public RSA key
    cipher_rsa = PKCS1_OAEP.new(server_public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    #Encrypt the user and pass with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)

    return pickle.dumps([ciphertext, tag, cipher_aes.nonce])


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    # TODO: Implement this function
    message = pickle.loads(message)

    p_key = RSA.import_key(open(os.path.dirname(__file__) + '/../Server/RSA_keys.pub').read())

    cipher = PKCS1_OAEP.new(p_key)
    plainKey = session_key

    #Decrypt what we received from the server and print whether we were successfuly authenticated or not
    server_message = AES.new(plainKey, AES.MODE_EAX, message[2])
    returned_message = str(server_message.decrypt_and_verify(message[0], message[1]))
    print(returned_message[2:len(returned_message)-1])

    return


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)
        else:
            print("Received okay from server")

        # TODO: Encrypt message and send to server
        payload = encrypt_message(message, key)
        send_message(sock, payload)

        # TODO: Receive and decrypt response from server
        server_response = receive_message(sock)
        decrypt_message(server_response, key)

    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
