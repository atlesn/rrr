import rrr_objects
import time

def process(result : rrr_objects.rrr_result, message: rrr_objects.vl_message):
#	print ("timestamp: " + str(message.timestamp_from))
	message.timestamp_from = message.timestamp_from + 1
	result.put(message)
#	time.sleep(1)
	return 0

def source(result : rrr_objects.rrr_result):
	message = rrr_objects.vl_message(1, 2, 3, 4, 5, 6, bytearray("abcdefg", encoding='utf8'))
	message.timestamp = 1
#	print ("timestamp: " + str(message.timestamp_from))
	result.put(message)
#	time.sleep(1)
	return 0

def config(result : rrr_objects.rrr_result, settings : rrr_objects.rrr_instance_settings):
	print("Result: " + str(result) + " Argument: " + str(settings))
	print ("1: " + settings['custom_config_argument_1'])
	print ("2: " + settings['custom_config_argument_2'])
	module_setting = settings.get_class('module')
	return 0

