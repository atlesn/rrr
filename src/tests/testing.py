from rrr_helper import *

def process(socket: rrr_socket, message: vl_message):
#	print ("timestamp: " + str(message.timestamp_from))
	message.timestamp_from = message.timestamp_from + 1
	socket.send(message)
	return 0
