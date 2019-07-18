from rrr import *

def process(result: rrr_result, message: vl_message):
#	print ("timestamp: " + str(message.timestamp_from))
	message.timestamp_from = message.timestamp_from + 1
	result.put(message)
	return 0
