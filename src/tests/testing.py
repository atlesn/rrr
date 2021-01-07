from rrr_helper import *

persistent_setting_a = "not touched"
persistent_setting_b = "not touched"

def config(config : rrr_config):
	global persistent_setting_a
	global persistent_setting_b

	print("python3 setting b, value was '" + config.get("persistent_setting_b") + "'")
	config.replace("persistent_setting_b", "touched")
	print("python3 touched setting b, value is now '" + config.get("persistent_setting_b") + "'")

	config.add("persistent_setting_c_new", "produce_warning")

	persistent_setting_a = config.get("persistent_setting_a")
	persistent_setting_b = config.get("persistent_setting_b")

	return True

def source(socket: rrr_socket, message : rrr_message):
	global persistent_setting_a
	global persistent_setting_b

	if persistent_setting_b != "touched":
		print("python3 configuration error, persistent_setting_b was not touched during config, value was '" + persistent_setting_b + "'")
		return False

	return True

def process(socket: rrr_socket, message: rrr_message):
	global persistent_setting_a
	global persistent_setting_b

	if persistent_setting_b != "touched":
		print("python3 configuration error, persistent_setting_b was not touched during config, value was '" + persistent_setting_b + "'")
		return False

	print ("python3 timestamp before: " + str(message.timestamp))
	message.timestamp = message.timestamp + 1
	print ("python3 timestamp after : " + str(message.timestamp))

	if (not message.has_array()):
		print ("python3 message did not have an array\n")
		return False

	array_old = message.get_array()
	array_new = rrr_array()

	print ("python3 array has " + str(array_old.count()) + " members, persistent settings are " + persistent_setting_a + " and " + persistent_setting_b)

	for item in array_old:
		print ("\titem in array with tag " + item.get_tag())

	message.discard_array()

	blob_item = array_old.get("blob")
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
