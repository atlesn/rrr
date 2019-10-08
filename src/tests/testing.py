from rrr_helper import *

def process(socket: rrr_socket, message: vl_message):
	print ("python3 timestamp before: " + str(message.timestamp_from))
	message.timestamp_from = message.timestamp_from + 1
	print ("python3 timestamp after : " + str(message.timestamp_from))

	if (not message.has_array()):
		print ("python3 message did not have an array\n")
		return False

	array_old = message.get_array()
	array_new = rrr_array()

	print ("python3 array has " + str(array_old.count()) + " members")

	message.discard_array()

	blob_item = array_old.get("blob8")
	blob_item.set_type(blob_item.TYPE_STR)

	for i in range(blob_item.count()):
		value = blob_item.get(i)
		if type(value) is bytearray:
			blob_item.set(i, value.decode("utf-8"))

	array_old.append(rrr_array_value(blob_item.TYPE_FIXP, 1<<25, 1<<16))

	for item in array_old:
		print ("python3 item of type " + item.get_type_str() +
			" type id " + str(item.get_type()) +
			" with tag " + item.get_tag() +
			" has " + str(item.count()) + " values")
		array_new.append(item)
		for value in item:
			print ("    " + str(value));

	message.set_array(array_new)

	socket.send(message)
	return True
