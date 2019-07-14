def process(message: vl_message):
#	print ("timestamp: " + str(message.timestamp_from))
	message.timestamp_from = message.timestamp_from + 1
	return message
