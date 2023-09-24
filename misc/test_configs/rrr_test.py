from rrr_helper import *
import time
import termios

def config (config : rrr_config):
	print ("Python3 in config custom setting is " + config.get("python3_custom_setting"));
	return True

def my_method0(socket : rrr_socket, message: rrr_message):
	# print ("Python3 got a message, forwarding")

	socket.send(message)

	return True

def my_method1(socket : rrr_socket, message: rrr_message):
	return True
def my_method2(socket : rrr_socket, message: rrr_message):
	return True
def my_method3(socket : rrr_socket, message: rrr_message):
	return True
def my_method4(socket : rrr_socket, message: rrr_message):
	return True
def my_method5(socket : rrr_socket, message: rrr_message):
	return True
def my_method6(socket : rrr_socket, message: rrr_message):
	return True
def my_method7(socket : rrr_socket, message: rrr_message):
	return True
def my_method8(socket : rrr_socket, message: rrr_message):
	return True
def my_method9(socket : rrr_socket, message: rrr_message):
	return True
def my_method10(socket : rrr_socket, message: rrr_message):
	return True
def my_method11(socket : rrr_socket, message: rrr_message):
	return True
def my_method12(socket : rrr_socket, message: rrr_message):
	return True
def my_method13(socket : rrr_socket, message: rrr_message):
	return True
def my_method14(socket : rrr_socket, message: rrr_message):
	return True
def my_method15(socket : rrr_socket, message: rrr_message):
	return True
