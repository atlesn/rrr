import sys
import multiprocessing
import importlib
from multiprocessing.pool import Pool
from multiprocessing import Queue, Lock, Pipe, Process

# Fix for TypeError: AutoProxy() got an unexpected keyword argument 'manager_owned'
# old_autoproxy = multiprocessing.Manager.AutoProxy
# def new_autoproxy(token, serializer, manager=None, authkey=None, exposed=None, incref=True, manager_owned=True):
#     return old_autoproxy(token, serializer, manager, authkey, exposed, incref)
# multiprocessing.Manager.AutoProxy = new_autoproxy

# Source must be edited manually, in multiprocessing/managers.py replace 
# def AutoProxy(token, serializer, manager=None, authkey=None,
#          exposed=None, incref=True):
# with
# def AutoProxy(token, serializer, manager=None, authkey=None,
#          exposed=None, incref=True, manager_owned=True):

# TODO : Make configure generate 1024 number from  MSG_DATA_MAX_LENGTH_STR

sys.path.append(".")

class vl_message:
	type=0
	m_class=0
	timestamp_from=0
	timestamp_to=0
	data_numeric=0
	length=0
	data=bytes(1024)
	def __init__(self, t, c, tf, tt, dn, l, d : bytearray):
		self.type = t
		self.m_class = c
		self.timestamp_from = tf
		self.timestamp_to = tt
		self.data_numeric = dn
		self.length = l
		self.data = d

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

class rrr_process_pipe:
	pipe_to_process = None
	pipe_from_process = None
	process = None

	def __init__(self, p_to_process, p_from_process):
		self.pipe_to_process = p_to_process
		self.pipe_from_process = p_from_process

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

def rrr_process_start_persistent_intermediate(pipe : rrr_process_pipe, function):
	result = rrr_result()
	data = pipe.pipe_to_process.recv()
	while data:
		ret = 0
		if (isinstance(data, vl_message)):
			ret = function(result, data)
		else:
			for m in data:
				ret = function(result, m) + ret
				if ret == 0 and result.has_data():
					pipe.pipe_from_process.send(result.get())
		if ret:
			print("Received error from function in rrr_process_start_persistent_intermediate")
		data = pipe.pipe_to_process.recv()
		
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

	def new_process_pipe(self, module_str : str, function_str : str, persistent):
		mod = importlib.import_module(module_str)
		function = getattr(mod, function_str)
			
		a1, a2 = Pipe()
		b1, b2 = Pipe()

		main = rrr_process_pipe(a1, b1)
		child = rrr_process_pipe(a2, b2)

		if (persistent):
			p = Process(target=rrr_process_start_persistent_intermediate, args=(child, function))
			p.start()
		else:
			p = Process(target=rrr_process_start_single_intermediate, args=(child, function))
			p.start()
		
		main.set_process(p)

		with self.lock:
			self.process_pipes.append(main)
			
		return main
	
	def remove_process_pipe(self, pipe : rrr_process_pipe):
		with self.lock:
			idx = self.process_pipes.index(pipe)
			self.process_pipes.pop(idx)
			self.processes.pop(idx)

	def terminate_all(self):
		with self.lock:
			i = 0
			for p in self.process_pipes:
				i = i + 1
				if p.process:
					p.process.terminate()
			print ("Terminated " + str(i) + " processes")
			self.process_pipes.clear()
		return 0

def rrr_persistent_thread_start(process_dict : rrr_process_dict, module_str : str, function_str : str):
	pipe = process_dict.new_process_pipe(module_str, function_str, 1)
	return pipe

def rrr_persistent_thread_send_data(pipe : rrr_process_pipe, data):
	return pipe.send(data)

def rrr_persistent_thread_send_new_vl_message(*args):
	to_send = []

	pipe = args[0]
	count = args[1][1]
#	print ("Found " + str(count) + " messages");
		
	for i in range(2,count+2):
		message = args[1][i];
#		print ("New message " + str(message) + " timestamp " + str(message[2]))
		new_message = vl_message(message[0], message[1], message[2], message[3], message[4], message[5], message[6]);
#		print ("New New message : " + str(new_message))
		to_send.append(new_message)
	return pipe.pipe_to_process.send(to_send)

def rrr_persistent_thread_recv_data(pipe : rrr_process_pipe):
	ret = pipe.pipe_from_process.recv()
	return ret

def rrr_persistent_thread_recv_data_nonblock(pipe : rrr_process_pipe):
	if pipe.pipe_from_process.poll():
		return pipe.pipe_from_process.recv()
	return None

def rrr_persistent_thread_get_pipe_to_process(pipe : rrr_process_pipe):
	return pipe.pipe_to_process;

def rrr_persistent_thread_get_pipe_from_process(pipe : rrr_process_pipe):
	return pipe.pipe_from_process;

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

	process_pipe = process_dict.new_process_pipe(module_str, function_str, 0)
	process_pipe.pipe_to_process.send(argument)

	result = process_pipe.pipe_from_process.recv()
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
#		print(l)
		return super(rrr_instance_settings,self).get(key).check_used()

def rrr_settings_new():
	return rrr_instance_settings()

