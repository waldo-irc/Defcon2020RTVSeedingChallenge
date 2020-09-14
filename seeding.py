#!/usr/bin/env python3
import socket
import threading
import random
import string
import socket
import sys
import logging
from datetime import datetime

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='/var/logs/server/seedthing.log',
                    filemode='a')

if len(sys.argv) < 2:
        logging.debug("ALERT: Using default port 3000 since one wasnt provided.")
        logging.debug("EXAMPLE: You can do for example '%s 3050' to change the port if you'd like." % sys.argv[0])
        port = 3000
else:
	port = sys.argv[1]

try:
	port = int(port)
except ValueError:
	logging.debug("ERROR: Must provide an integer between 1 and 65535.")
	exit(0)

if port > 65535 or port < 1:
	logging.debug("ERROR: Must provide an integer between 1 and 65535.")
	exit(0)

def start_seed(max):
	random.seed(datetime.now())
	seed = random.randint(1,max)
	random.seed(seed)
	return seed

def get_random_string(length):
	key = 'ereselamordemivida'
	result_str = ''.join(random.choice(key) for i in range(length))
	return result_str

def get_x_iteration(x):
	for i in range (0,x):
		if i == x-1:
			return get_random_string(16)
		get_random_string(16)

class ThreadedServer(object):
	def __init__(self, host, port):
		self.host = host
		self.port = port
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind((self.host, self.port))

	def listen(self):
		self.sock.listen(5)
		while True:
			client, address = self.sock.accept()
			client.settimeout(5)
			threading.Thread(target = self.listenToClient,args = (client,address)).start()

	def listenToClient(self, client, address):
		size = 1024
		while True:
			try:
				host, port = client.getpeername()
				max = 100
				seed = start_seed(max)
				fourth = get_x_iteration(4)
				leet = get_x_iteration((1337-4))

				data = b"The seed is a number that can be from anywhere between 1 to %s.\n" % str.encode(str(max))
				data += b"The seed this run was: %s\n" % str.encode(str(seed))
				data += b"The fourth iteration of this key is: %s\n" % str.encode(fourth)
				data += b"\n"
				data += b"The first flag is the key.  What is the key?: "
				client.send(data)

				data = client.recv(size)
				try:
					data = data.decode('utf-8').strip('\r').strip('\n')
				except:
					data = data.strip('\r').strip('\n')
				logging.debug(b"RECEIVED KEY FROM %s: " % str.encode(str(host)) + str.encode(data))
				if data == 'ACTFKEYGOESHERE':
					logging.debug(b"VALID KEY FROM %s: " % str.encode(str(host)) + str.encode(str(data)))
					response = b"Correct!  Heres the flag flag{YouCanBruteForceAnything}\nMoving to next piece...\n"
					client.send(response)

					data = b"\nThe 1337th iteration of using the seed to randomize the key during runtime is the password.\n"
					data += b"Please enter it to continue: "
					client.send(data)

					data = client.recv(size)
					try:
						data = data.decode('utf-8').strip('\r').strip('\n')
					except:
						data = data.strip('\r').strip('\n')
					logging.debug(b"RECEIVED FINAL ANSWER FROM %s: %s" % (str.encode(str(host)), str.encode(data)))
					if data == leet:
						logging.debug(b"CORRECT FINAL ANSWER FROM %s: %s" % (str.encode(str(host)), str.encode(data)))
						data = b"Congratulations!!! Heres the last flag{IsthisCrypto?}\n"
						client.send(data)
						client.close()
					else:
						data = b"You're so close...try again!\n\n"
						client.send(data)
						logging.debug(b"INCORRECT FINAL ANSWER FROM %s: %s" % (str.encode(str(host)), str.encode(data)))
				elif data:
					logging.debug(b"INVALID KEY FROM %s: " % str.encode(str(host)) + str.encode(data))
					response = b"You entered %s..." % str.encode(data)
					response += b"This is incorrect, try again...\n\n"
					client.send(response)
				else:
					raise error('Client disconnected')
			except Exception as e:
				logging.debug(e)
				logging.debug("Error on line {}".format(sys.exc_info()[-1].tb_lineno))
				client.close()
				return False

if __name__ == "__main__":
	while True:
		port_num = port
		try:
			port_num = int(port_num)
			break
		except ValueError:
			pass

	logging.debug("Starting server on port: %s" % port_num)
	ThreadedServer('',port_num).listen()
