import sys
import multiprocessing
import importlib
import time
from multiprocessing.pool import Pool
from multiprocessing import Lock, Pipe, Process
from queue import Queue
from rrr import *
from rrr_helper import *
from twisted.trial.test import moduleself

# TODO : Make configure generate 1024 number from  MSG_DATA_MAX_LENGTH_STR

# class vl_message:
# 	type=0
# 	m_class=0
# 	timestamp_from=0
# 	timestamp_to=0
# 	data_numeric=0
# 	length=0
# 	data=bytes(1024)
# 	def __init__(self, t, c, tf, tt, dn, l, d : bytearray):
# 		self.type = t
# 		self.m_class = c
# 		self.timestamp_from = tf
# 		self.timestamp_to = tt
# 		self.data_numeric = dn
# 		self.length = l
# 		self.data = d

def vl_message_new(*_args):
#t, c, tf, tt, dn, l, d : bytearray):
	result = _args[0]
	args = _args[1]
	ret =  vl_message(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
	result.put(ret)
	return 0

class rrr_result:
	data = None
	def put(self, d):
		self.data = d
	def get(self):
		ret = self.data
		self.data = None
		return ret
	def has_data(self):
		return (self.data != None)

class rrr_process_type:
	process = None

	def set_process(self, p):
		self.process = p

	def join(self):
		return self.process.join()

	def terminate(self):
		self.process.terminate()
		self.process.join()
		self.process = None
		self.pipe_to_process.close()
		self.pipe_from_process.close()

class rrr_process_pipe(rrr_process_type):
	pipe_to_process = None
	pipe_from_process = None

	def __init__(self, p_to_process, p_from_process):
		self.pipe_to_process = p_to_process
		self.pipe_from_process = p_from_process
		
	def to_process_send(self, data):
		return self.pipe_to_process.send(data)
	
	def to_process_recv(self, data):
		return self.pipe_to_process.recv()
	
	def to_process_poll(self):
		return self.pipe_to_process.poll()
	
	def from_process_send(self, data):
		return self.pipe_from_process.send(data)
	
	def from_process_recv(self, data):
		return self.from_from_process.recv()
	
	def from_process_poll(self):
		return self.pipe_from_process.poll()


class rrr_process_socket(rrr_process_type):
	socket = None

	def __init__(self, socket_filename = NoneType):
		if (socket_filename):
			self.socket = rrr_socket(socket_filename)
		else:
			self.socket = rrr_socket()
		
	def get_socket(self):
		return self.socket;

	def to_process_send(self, data):
		return socket.send(data)
	
	def to_process_recv(self, data):
		return socket.recv()
	
	def to_process_poll(self):
		return socket.poll()
	
	def from_process_send(self, data):
		return socket.send(data)
	
	def from_process_recv(self, data):
		return socket.recv()
	
	def from_process_poll(self):
		return socket.poll()

class rrr_send_buffer:
	max_in_buffer = 50
	max_in_transit = 50
	in_transit = 0
	queue = Queue(max_in_buffer)

	def sub_in_transit(self, count : int):
		self.in_transit = self.in_transit - count

	def inc_in_transit(self):
		self.in_transit = self.in_transit + 1
		return (self.in_transit > self.max_in_transit)

	def full_in_transit(self):
		return (self.in_transit >= self.max_in_transit)

	def get(self):
		if (self.queue.empty()):
			return False
		return self.queue.get_nowait()

	def put(self, m):
		if (self.queue.full()):
			return False
		self.queue.put_nowait(m)
		return True

	def full(self):
		return self.queue.full()

def rrr_process_start_persistent_readonly_intermediate(socket : rrr_process_socket, function):
	result = rrr_result()
	send_buffer = rrr_send_buffer()
	while True:
		# Read message counters from receiver
		received_count = 0
		while True:
			while pipe.pipe_to_process.poll():
				received_count = received_count + pipe.pipe_to_process.recv()
				send_buffer.sub_in_transit(received_count)
			if (send_buffer.full_in_transit()):
				time.sleep(0.01)
			else:
				break
		pass

		if not send_buffer.full():
			ret = function(result) 
			if ret == 0 and result.has_data():
				message = result.get()
				if (isinstance(message, vl_message)):
					send_buffer.put(message)
				else:
					print("Warning: Received non-vl_message " + str(message) + " in rrr_process_start_persistent_readonly_intermediate");
			if ret:
				print("Received error from function in rrr_process_start_persistent_readonly_intermediate")
				break
		pass

		if (not send_buffer.full_in_transit()):
			m = send_buffer.get()
			count = 0
			while m:
				pipe.pipe_from_process.send(m)
				if (send_buffer.inc_in_transit()):
					break;
				count += 1
				m = send_buffer.get()
		pass
	pass

def rrr_process_start_persistent_intermediate(socket : rrr_socket, function):
	result = rrr_result()
	data = socket.recv()
	while data:
		ret = 0
		if (isinstance(data, vl_message)):
			ret = function(result, data)
			if ret == 0 and result.has_data():
				data = socket.send(result.get())
		else:
			print("Warning: Received non-vl_message from main in rrr_process_start_persistent_intermediate");
		if ret:
			print("Received error from function in rrr_process_start_persistent_intermediate")
		data = socket.recv()
		
def rrr_process_start_single_intermediate(pipe : rrr_process_pipe, function):
	result = rrr_result()
	data = pipe.pipe_to_process.recv()
	if data:
		ret = function(result, data)
		if ret == 0:
			pipe.pipe_from_process.send(result.get()) # Always send, even when None
		else:
			print("Received error from function in rrr_process_start_single_intermediate")
	else:
		print("No data received in rrr_process_start_single_intermediate")
	
class rrr_process_dict:
	lock = Lock()
	process_pipes = []
	process_sockets = []

	def new_process_socket(self, module_str : str, function_str : str, start_function):
		mod = importlib.import_module(module_str)
		function = getattr(mod, function_str)

		main = rrr_process_socket();
		child = rrr_process_socket(main.get_filename());

		# For speed, we send in the raw socket type
		p = Process(target=start_function, args=(child.get_socket(), function))
		p.start()

		main.set_process(p)

		with self.lock:
			self.process_pipes.append(main)
		
	def new_process_pipe(self, module_str : str, function_str : str, start_function):
		mod = importlib.import_module(module_str)
		function = getattr(mod, function_str)
			
		a1, a2 = Pipe()
		b1, b2 = Pipe()

		main = rrr_process_pipe(a1, b1)
		child = rrr_process_pipe(a2, b2)

		p = Process(target=start_function, args=(child, function))
		p.start()
		
		main.set_process(p)

		with self.lock:
			self.process_pipes.append(main)
			
		return main

	def new_process_socket_persistent(self, module_str : str, function_str : str):
		return self.new_process_socket(module_str, function_str, rrr_process_start_persistent_intermediate)

	def new_process_pipe_persistent_readonly(self, module_str : str, function_str : str):
		return self.new_process_pipe(module_str, function_str, rrr_process_start_persistent_readonly_intermediate)

	def new_process_pipe_onetime(self, module_str : str, function_str : str):
		return self.new_process_pipe(module_str, function_str, rrr_process_start_single_intermediate)
	
#	def remove_process_pipe(self, pipe : rrr_process_pipe):
#		with self.lock:
#			idx = self.process_pipes.index(pipe)
#			self.process_pipes.pop(idx)
#			self.processes.pop(idx)

	def terminate_all(self):
		with self.lock:
			i = 0
			for p in self.process_pipes:
				i = i + 1
				if p.process:
					p.process.terminate()
			for p in self.process_sockets:
				i = i + 1
				if p.process:
					p.process.terminate()
			print ("Terminated " + str(i) + " processes")
			self.process_pipes.clear()
			self.process_sockets.clear()
		return 0

def rrr_persistent_thread_readonly_start(process_dict : rrr_process_dict, module_str : str, function_str : str):
	pipe = process_dict.new_process_socket_persistent_readonly(module_str, function_str)
	return pipe

def rrr_persistent_thread_start(process_dict : rrr_process_dict, module_str : str, function_str : str):
	pipe = process_dict.new_process_pipe_persistent(module_str, function_str)
	return pipe

def rrr_persistent_thread_send_data(pipe : rrr_process_type, data):
	return pipe.to_process_send(data)

def rrr_persistent_thread_send_new_vl_message(*args):
	to_send = []

	pipe = args[0]
	count = args[1][1]
		
	for i in range(2,count+2):
		message = args[1][i];
		new_message = vl_message(message[0], message[1], message[2], message[3], message[4], message[5], message[6]);
		to_send.append(new_message)
	return pipe.to_process_send(to_send)

def rrr_persistent_thread_recv_data(pipe : rrr_process_pipe):
	ret = pipe.from_process_recv()
	return ret

def rrr_persistent_thread_recv_data_nonblock(pipe : rrr_process_pipe):
	if pipe.pipe_from_process.poll():
		return pipe.from_process_recv()
	return None

def rrr_thread_terminate_all(process_dict : rrr_process_dict):
	return process_dict.terminate_all()

def rrr_onetime_thread_start(*args):
#result_queue : rrr_result_queue, module_str : str, function_str : str, argument, int : persistent):
#	Don't know why this has to be done, but things doesn't work otherwise
	str(dir(args))

	process_dict = args[0]
	module_str = args[1]
	function_str = args[2]
	argument = args[3]

	process_pipe = process_dict.new_process_pipe_onetime(module_str, function_str)
	process_pipe.to_process_send(argument)

	result = process_pipe.from_process_recv()
	process_pipe.terminate()
	return result

class rrr_setting:
	key = ""
	value = ""
	was_used = 0
	def __init__(self, k, v, w):
		self.key = k
		self.value = v
		self.was_used = w
	def get(self):
		self.was_used=1
		return self.value
	def check_used(self):
		return self.was_used

class rrr_instance_settings(dict):
	def __init__(self):
		super(rrr_instance_settings,self).__init__()

	def set(self, key, value, was_used):
		super(rrr_instance_settings,self).update({key: rrr_setting(key, value, was_used)})

	def get_class(self, key):
		return super(rrr_instance_settings,self).get(key)

	def get(self, key):
		return super(rrr_instance_settings,self).get(key).get()

	def __getitem__(self, key):
		return super(rrr_instance_settings,self).get(key).get()

	def check_used(self, key):
		l = dir(key)
		return super(rrr_instance_settings,self).get(key).check_used()

def rrr_settings_new():
	return rrr_instance_settings()

