function config()
	-- TODO : Test config stuff
	return true
end

function verify_defaults()
	message = RRR.Message:new()

	-- IP parameters
	message:ip_set("1.2.3.4", 5)
	ip, port = message:ip_get()
	assert (ip == "1.2.3.4")
	assert (port == 5)
	message:ip_clear()
	ip, port = message:ip_get()
	assert (ip == "")
	assert (port == 0)
	message:ip_set("1.2.3.4", 5)
	message:ip_set("", 123) -- Port is ignored, forced to be 0
	ip, port = message:ip_get()
	assert (ip == "")
	assert (port == 0)

	-- Other parameters
	assert (message.timestamp > 0 or message.timestamp == nil) -- Is nil if Lua integer is less than 8 bytes
	assert (message.topic == "")
	assert (message.ip_so_type == "")
	assert (message.data == "")
	assert (message.type == RRR.Message.MSG_TYPE_MSG)
	assert (message.class == RRR.Message.MSG_CLASS_DATA)

	-- Array manipulation
	-- str type
	message:push_tag_str("key", "value1")
	message:push_tag_str("key", "value2")
	assert(message:get_tag_all("key")[1] == "value1")
	assert(message:get_tag_all("key")[2] == "value2")
	assert(type(message:get_tag_all("key")[1]) == "string")
	assert(type(message:get_tag_all("key")[2]) == "string")
	message:clear_array()
	assert(message:get_tag_all("key")[1] == nil)
	message:push_tag_str("key", "value")
	message:push_tag_str("key", "value")
	message:clear_tag("key")
	assert(message:get_tag_all("key")[1] == nil)
	message:push_tag("key", "value")
	assert(message:get_tag_all("key")[1] == "value")
	message:clear_array()

	-- h type
	message:push_tag_h("key", 1)
	message:push_tag_h("key", -2)
	message:push_tag_h("key", "3")
	message:push_tag_h("key", "3.14")
	message:push_tag_h("key", 3.14)
	message:push_tag_h("key", "-111")

	assert(type(message:get_tag_all("key")[1]) == "number")
	assert(type(message:get_tag_all("key")[2]) == "number")
	assert(type(message:get_tag_all("key")[3]) == "number")
	assert(type(message:get_tag_all("key")[4]) == "number")
	assert(type(message:get_tag_all("key")[5]) == "number")
	assert(type(message:get_tag_all("key")[6]) == "number")

	assert(message:get_tag_all("key")[1] == 1)
	assert(message:get_tag_all("key")[2] == -2)
	assert(message:get_tag_all("key")[3] == 3)
	assert(message:get_tag_all("key")[4] == 3)
	assert(message:get_tag_all("key")[5] == 3)
	assert(message:get_tag_all("key")[6] == -111)

	message:clear_array()

	-- number/fixp type
	-- Convertible to fixp without loss of precision
	message:push_tag("key", 3.5)
	message:push_tag("key", 1.0/3.0)
	assert(type(message:get_tag_all("key")[1]) == "number")
	assert(message:get_tag_all("key")[1] == 3.5)
	assert(type(message:get_tag_all("key")[2]) == "string")
	assert(message:get_tag_all("key")[2]:sub(1, 5) == "0.333")
	message:clear_array()


	-- test push_tag_fixp function
	message:push_tag_fixp("key", 3.5)
	message:push_tag_fixp("key", 1.0/3.0)
	message:push_tag_fixp("key", "3.5");
	message:push_tag_fixp("key", "16#-0.000001");

	assert(type(message:get_tag_all("key")[1]) == "number")
	assert(type(message:get_tag_all("key")[2]) == "string")
	assert(type(message:get_tag_all("key")[3]) == "number")
	assert(type(message:get_tag_all("key")[4]) == "number")

	assert(message:get_tag_all("key")[1] == 3.5)
	assert(message:get_tag_all("key")[2]:sub(1, 5) == "0.333")
	assert(message:get_tag_all("key")[3] == 3.5)
	assert((string.format("%.16f", message:get_tag_all("key")[4])):sub(1, 16) == "-0.0000000596046")

	message:clear_array()

	-- nil/vain type
	message:push_tag("key", nil)
	assert(type(message:get_tag_all("key")[1]) == "nil")
	assert(message:get_tag_all("key")[1] == nil)
	message:clear_array()

	-- blob type
	message:push_tag_blob("key", "value1")
	assert(type(message:get_tag_all("key")[1]) == "string")
	assert(message:get_tag_all("key")[1] == "value1")
	message:clear_array()

	-- set tags blob, str, h, fixp, generic
	message:push_tag_blob("key", "value1")
	message:set_tag_blob("key", "value2")
	assert(message:get_tag_all("key")[1] == "value2")
	message:clear_array()

	message:push_tag_str("key", "value1")
	message:set_tag_str("key", "value2")
	assert(message:get_tag_all("key")[1] == "value2")
	message:clear_array()

	message:push_tag_h("key", 1)
	message:set_tag_h("key", 2)
	assert(message:get_tag_all("key")[1] == 2)
	message:clear_array()

	message:push_tag_fixp("key", 1.0/3.0)
	message:set_tag_fixp("key", 2.0/3.0)
	assert((string.format("%.16f", message:get_tag_all("key")[1])):sub(1, 6) == "0.6666")
	message:clear_array()

	message:push_tag("key", 1)
	message:set_tag("key", 2)
	assert(message:get_tag_all("key")[1] == 2)
	message:clear_array()
end

function process(message)
	print("type", type(message))
	for k, v in pairs(message) do
		print (k .. " =>", v)
	end

	verify_defaults()

	message.send()

	return true
end
