"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:



"""

import socket
from Crypto.Cipher import AES
import bcrypt

host = "localhost"
port = 10001


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    # TODO: Implement this function
    p_key = RSA.import_key(open("RSA_keys").read())

    cipher = PKCS1_OAEP.new(p_key)
    plainKey = cipher.decrypt(session_key)
    return plainKey


# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    # TODO: Implement this function
    client_message.split(' ', 1)

    p_key = RSA.import_key(open("RSA_keys").read())

    cipher = PKCS1_OAEP.new(p_key)
    plainKey = cipher.decrypt(session_key)

    userpassKey = AES.new(plainKey, AES.MODE_EAX)
    userpass = userpassKey.decrypt_and_verify(client_message[0], client_message[1])


    return userpass


# Encrypt a message using the session key
def encrypt_message(message, session_key):
    # TODO: Implement this function
    message = message.encode("utf-8")

    server_private_key = RSA.import_key(open("RSA_keys").read())

    #Encrypt the session key with the servers public RSA key
    cipher_rsa = PKCS1_OAEP.new(server_private_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    #Encrypt the user and pass with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    return ciphertext + " " + tag
    pass


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                # TODO: Generate the hashed password
                salt = bcrypt.gensalt(rounds=16)
                hashed_password = bcrypt.hashpw(password, salt)
                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # TODO: Decrypt message from client
                plain_message = decrypt_message(ciphertext_message, encrypted_key)
                # TODO: Split response from user into the username and password
                plain_message.split(' ', 1)
                # TODO: Encrypt response to client

                # Send encrypted response
                send_message(connection, ciphertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
