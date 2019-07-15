def process(message: vl_message):
#	print ("timestamp: " + str(message.timestamp_from))
	message.timestamp_from = message.timestamp_from + 1
	return message

def config(settings: rrr_instance_settings):
	print ("1: " + settings['custom_config_argument_1'])
	print ("2: " + settings['custom_config_argument_2'])
	module_setting = settings.get_class('module')
	module_setting.was_used=0
