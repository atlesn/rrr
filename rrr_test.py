import rrr_objects

def process(result : rrr_objects.rrr_result, message: rrr_objects.vl_message):
#	print ("timestamp: " + str(message.timestamp_from))
	message.timestamp_from = message.timestamp_from + 1
	result.put(message)
	return 0

def config(result : rrr_objects.rrr_result, settings : rrr_objects.rrr_instance_settings):
	print("Result: " + str(result) + " Argument: " + str(settings))
	print ("1: " + settings['custom_config_argument_1'])
	print ("2: " + settings['custom_config_argument_2'])
	module_setting = settings.get_class('module')
	module_setting.was_used=0
	result.put(settings)
	return 0
