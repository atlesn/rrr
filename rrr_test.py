from rrr_helper import *
import time

def process(socket : rrr_socket, message: vl_message):
	# modify the retrieved message as needed
	message.timestamp_from = message.timestamp_from + 1
	# queue the message to be sent back (optinal) for python to give to readers
	socket.send(message)
	return True

def source(socket : rrr_socket):
	# create a new message
	message = vl_message(1, 2, 3, 4, 5)
#, bytearray("abcdefg", encoding='utf8'))
	print ("Source message created")
	# queue the message to be sent back (optinal) for python to give to readers
	socket.send(message)
	# sleep to limit output rate
	time.sleep(1)
	return True

def config(socket : rrr_socket, setting : rrr_setting):
	# retrieve a setting from configuration file
	print ("Setting: " + setting.name + " - " + setting.get())
	# send setting back to update which have been read (optional)
	socket.send(setting)
	return True
