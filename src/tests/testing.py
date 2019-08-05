from rrr_helper import *

def process(socket: rrr_socket, message: vl_message):
	print ("python3 timestamp before: " + str(message.timestamp_from))
	message.timestamp_from = message.timestamp_from + 1
	print ("python3 timestamp after : " + str(message.timestamp_from))
	socket.send(message)
	return True
