from rrr import *
import time

def process(result : rrr_result, message: vl_message):
	# modify the retrieved message as needed
	message.timestamp_from = message.timestamp_from + 1
	# queue the message to be sent back (optinal) for python to give to readers
	result.put(message)
	return 0

def source(result : rrr_result):
	# create a new message
	message = vl_message(1, 2, 3, 4, 5, 6, bytearray("abcdefg", encoding='utf8'))
	# queue the message to be sent back (optinal) for python to give to readers
	result.put(message)
	# sleep to limit output rate
	time.sleep(1)
	return 0

def config(result : rrr_result, settings : rrr_instance_settings):
	# retrieve some custom settings from configuration file
	print ("1: " + settings['custom_config_argument_1'])
	print ("2: " + settings['custom_config_argument_2'])
	# send settings back to update which have been read (optional)
	result.put(settings)
	return 0
