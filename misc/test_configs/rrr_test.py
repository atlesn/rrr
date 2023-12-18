from rrr_helper import *
import time
import termios

def config (config : rrr_config):
	print ("Python3 in config custom setting is " + config.get("python3_custom_setting"));
	return True

def my_method(socket : rrr_socket, message: rrr_message):
	return True

def process(socket : rrr_socket, message: rrr_message, method: str):
	return True
