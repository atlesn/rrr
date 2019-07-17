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
	pipe = None
	process = None
	timeout = 1

	def __init__(self, p):
		self.pipe = p

	def set_nonblock_timeout(self, t):
		self.timeout = t

	def set_process(self, p):
		self.process = p

	def send(self, data):
		if self.process and not self.process.is_alive():
			return -1
		try:
			self.pipe.send(data)
		except Exception as exc:
			return -1
		return 0

	def recv(self):
		if self.process and not self.process.is_alive():
			return -1
		return self.pipe.recv()
				
	def recv_nonblock(self):
		if self.process and not self.process.is_alive():
			return -2
		try:
			try:
				if (self.pipe.poll(self.timeout)):
					return self.pipe.recv()
				else:
					return 1
			except TimeoutException as exc:
				return 1
		except Exception:
			print("received exception in recv_nonblock")
			return -1
		return -1
		
	def join(self):
		return self.process.join()

	def terminate(self):
		self.process.terminate()
		self.process.join()
		self.process = None
		self.pipe.close()

def rrr_process_start_persistent_intermediate(pipe : rrr_process_pipe, function):
	result = rrr_result()
	data = pipe.recv()
	while data:
		ret = function(result, data)
		if ret == 0:
			if (result.has_data()):
				pipe.send(result.get())
		else:
			print("Received error from function in rrr_process_start_persistent_intermediate")
		data = pipe.recv()
		
def rrr_process_start_single_intermediate(pipe : rrr_process_pipe, function):
	result = rrr_result()
	data = pipe.recv()
	if data:
		ret = function(result, data)
		if ret == 0:
			pipe.send(result.get()) # Always send, even when None
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
			
		a, b = Pipe()

		main = rrr_process_pipe(a)
		child = rrr_process_pipe(b)

		if (persistent):
			p = Process(target=rrr_process_start_persistent_intermediate, args=(child, function))
			main.set_nonblock_timeout(0.03)
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

def rrr_persistent_thread_send_new_vl_message(pipe : rrr_process_pipe, *args):
	try:
		args[1] = args[1]
	except IndexError:
		args = args[0]
	message = vl_message(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
	return pipe.send(message)

def rrr_persistent_thread_recv_data(pipe : rrr_process_pipe):
	ret = pipe.recv()
	pipe.terminate()
	return ret

def rrr_persistent_thread_recv_data_nonblock(pipe : rrr_process_pipe):
	ret = pipe.recv_nonblock()
	return ret

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
	process_pipe.send(argument)
	
	result = process_pipe.recv()
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

