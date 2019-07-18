import rrr_objects

def process(result: rrr_objects.rrr_result, message: rrr_objects.vl_message):
#	print ("timestamp: " + str(message.timestamp_from))
	message.timestamp_from = message.timestamp_from + 1
	result.put(message)
	return 0
