"""
	add_user.py - Stores a new username along with salt/password

	CSCI 3403
	Authors: Matt Niemiec and Abigail Fernandes
	The solution contains the same number of lines (plus imports)
"""
import hashlib
import time
import os

user = input("Enter a username: ")
password = input("Enter a password: ")
clearance = input("Enter the users clearance from 1-4 (high to low): ")

if(int(clearance)>4 or int(clearance)<0):
	print("Invalid clearance entered. Exiting")
	quit()

# TODO: Create a salt and hash the password
#Create a 32-byte salt from os.urandom and use it hash the password using SHA-256
salt = os.urandom(32)
hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

#Convert the salt and hashed password to hex to store it in the file
salt = salt.hex()
hashed_password = hashed_password.hex()


try:
	reading = open("passfile.txt", 'r')
	for line in reading.read().split('\n'):
		if line.split('\t')[0] == user:
			print("User already exists!")
			exit(1)
	reading.close()
except FileNotFoundError:
	pass

with open("passfile.txt", 'a+') as writer:
	writer.write("{0}\t{1}\t{2}\t{3}\n".format(user, salt, hashed_password, clearance))
	print("User successfully added!")
