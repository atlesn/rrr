from rrr_helper import *

def process(socket: rrr_socket, message: vl_message):
	print ("python3 timestamp before: " + str(message.timestamp_from))
	message.timestamp_from = message.timestamp_from + 1
	print ("python3 timestamp after : " + str(message.timestamp_from))

	if (not message.has_array()):
		print ("python3 message did not have an array\n")
		return False

	array_old = message.get_array()
	array_new = rrr_array()

	message.discard_array()

	for item in array_old:
		array_new.append(item)

	message.set_array(array_new)

	socket.send(message)
	return True
