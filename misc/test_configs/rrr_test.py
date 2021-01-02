from rrr_helper import *
import time
import termios

def config (config : rrr_config):
	print ("Python3 in config custom setting is " + config.get("python3_custom_setting"));
	return True

def process(socket : rrr_socket, message: rrr_msg_msg):
	print ("Python3 got a message, forwarding")
	socket.send(message)
	return True

def source(socket : rrr_socket, message: rrr_msg_msg):
	print ("Python3 sourcing a message")

	my_array_value = rrr_array_value()
	my_array_value.set_tag("my_tag")
	my_array_value.set(0, "my_value")

	my_array = rrr_array()
	my_array.append(my_array_value)

	message.set_array(my_array)

	socket.send(message)

	time.sleep(1)

	return True
