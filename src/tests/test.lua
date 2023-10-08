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
	message:clear_array();
	assert(message:get_tag_all("key")[1] == nil)
	message:push_tag_str("key", "value")
	message:push_tag_str("key", "value")
	message:clear_tag("key");
	assert(message:get_tag_all("key")[1] == nil)
	message:push_tag("key", "value")
	assert(message:get_tag_all("key")[1] == "value")
	message:clear_array();

	-- h type
end

function process(message)
	print("type", type(message))
	for k, v in pairs(message) do
		print (k .. " =>", v)
	end

	verify_defaults()

	return true
end
