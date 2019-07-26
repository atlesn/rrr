from rrr_helper import *
import time

def process(socket : rrr_socket, message: vl_message):
	# modify the retrieved message as needed
	message.timestamp_from = message.timestamp_from + 1
	# queue the message to be sent back (optinal) for python to give to readers
	if not socket.send(message):
		return False
	return True

def source(socket : rrr_socket):
	# create a new message
	message = vl_message(1, 2, 3, 4, 5)
#, bytearray("abcdefg", encoding='utf8'))
	# queue the message to be sent back (optinal) for python to give to readers
	if not socket.send(message):
		return False
	# sleep to limit output rate
	time.sleep(0.1)
	return True

def config(socket : rrr_socket, setting : rrr_setting):
	# retrieve a setting from configuration file
	print ("Setting: " + setting.name + " - " + setting.get())
	# send setting back to update which have been read (optional)
	socket.send(setting)
	return True
