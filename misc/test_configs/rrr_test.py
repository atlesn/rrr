from rrr_helper import *
import time

def process(socket : rrr_socket, message: rrr_message):
	print ("Python3 got a message, forwarding")
	socket.send(message)
	return True
