local debug = RRR.Debug.new()

local my_config = {}

function config(config)
	-- Read configuration parameters and store them in the config table
	for _, k in pairs({"lua_param_a", "lua_param_b", "lua_param_c"}) do
		debug:msg(1, "key is: " .. k .. " and type of key is: " .. type(k) .. "\n")
		local value = config:get(k)
		if value == nil then
			debug:msg(0, "Configuration parameter '" .. k .. "' was not found\n")
			assert(false)
		end
		my_config[k] = value;
	end

	-- Verify values
	assert(my_config["lua_param_a"] == "a")
	assert(my_config["lua_param_b"] == "b")
	assert(my_config["lua_param_c"] == "c")

	-- Set a custom setting
	config:set("my_custom_setting", "5")

	-- Retrieve a custom setting
	my_config["my_custom_setting"] = config:get("my_custom_setting")
	assert(my_config["my_custom_setting"] == "5")
	debug:msg(1, "my_custom_setting is: " .. my_config["my_custom_setting"] .. "\n")

	-- Misc. tests
	debug:err("This is an error message to stderr\n")
	debug:dbg(1, "This is only printed if debug level 1 is enabled\n")

	return true
end

function verify_defaults()
	message = RRR.Message:new()

	-- Meta parameters
	assert (type(getmetatable(RRR)._rrr_lua) == "userdata")
	assert (type(getmetatable(RRR)._rrr_cmodule) == "userdata")

	-- iterate and print keys and values of RRR
	--for k, v in pairs(RRR) do
	--	print (k .. " =>", v)
	--end

	-- iterate and print keys and values of RRR metatable
	--for k, v in pairs(getmetatable(RRR)) do
	--	print (k .. " =>", v)
	--end

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

	-- IPv6
	message:ip_set("::1", 5)
	ip, port = message:ip_get()
	assert (ip == "::1")
	assert (port == 5)
	message:ip_clear()

	-- IPv4 mapped IPv6
	message:ip_set("::ffff:0.1.2.3", 5)
	ip, port = message:ip_get()
	assert (ip == "::ffff:0.1.2.3")
	assert (port == 5)
	message:ip_clear()

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
	assert(type(message:get_tag_all("key")[2]) == "number")
	assert(("" .. message:get_tag_all("key")[2]):sub(1, 5) == "0.333")
	message:clear_array()

	-- test push_tag_fixp function
	message:push_tag_fixp("key", 3.5)
	message:push_tag_fixp("key", 1.0/3.0)
	message:push_tag_fixp("key", "3.5");
	message:push_tag_fixp("key", "16#-0.000001");

	assert(type(message:get_tag_all("key")[1]) == "number")
	assert(type(message:get_tag_all("key")[2]) == "number")
	assert(type(message:get_tag_all("key")[3]) == "number")
	assert(type(message:get_tag_all("key")[4]) == "number")

	assert(message:get_tag_all("key")[1] == 3.5)
	assert(("" .. message:get_tag_all("key")[2]):sub(1, 5) == "0.333")
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

	-- Test push boolean using generic method.
	-- Bool will be stored as h.
	message:push_tag("key", true)
	message:push_tag("key", false)
	assert(type(message:get_tag_all("key")[1]) == "number")
	assert(type(message:get_tag_all("key")[2]) == "number")
	assert(message:get_tag_all("key")[1] == 1)
	assert(message:get_tag_all("key")[2] == 0)
	message:clear_array()

	-- Test iteration helpers
	message:push_tag("key1", 1)
	message:push_tag("", -1)
	message:push_tag("key2", 2)
	message:push_tag("", -2)

	assert(message:get_position(1)[1] == 1)
	assert(message:get_position(2)[1] == -1)
	assert(message:get_position(3)[1] == 2)
	assert(message:get_position(4)[1] == -2)
	assert(message:get_position(5) == nil)

	assert(message:count_positions() == 4)

	assert(message:get_tag_names()[1] == "key1")
	assert(message:get_tag_names()[2] == "")
	assert(message:get_tag_names()[3] == "key2")
	assert(message:get_tag_names()[4] == "")

	assert(message:get_tag_counts()[1] == 1)
	assert(message:get_tag_counts()[2] == 1)
	assert(message:get_tag_counts()[3] == 1)
	assert(message:get_tag_counts()[4] == 1)

	message:clear_array()

	-- Enable to test input validation
	-- message:push_tag_str("", {})
	-- message:push_tag_str("", {{}})
	-- message:push_tag_str("", {"a", {}})
	-- message:push_tag_str("", {"a", "aa"})

	-- Test push array of strings with both generic and specific method and set method
	message:push_tag_str("key", {"value1", "value2"})
	assert(message:get_tag_all("key")[1] == "value1")
	assert(message:get_tag_all("key")[2] == "value2")
	assert(message:get_position(1)[1] == "value1")
	assert(message:get_position(1)[2] == "value2")
	message:clear_array()

	message:push_tag("key", {"value1", "value2"})
	assert(message:get_tag_all("key")[1] == "value1")
	assert(message:get_tag_all("key")[2] == "value2")
	assert(message:get_position(1)[1] == "value1")
	assert(message:get_position(1)[2] == "value2")
	message:clear_array()

	-- Test push array of h's with both generic and specific method and set method
	message:push_tag_h("key", {1, 2, "3", -4})
	assert(message:get_tag_all("key")[1] == 1)
	assert(message:get_tag_all("key")[2] == 2)
	assert(message:get_tag_all("key")[3] == 3)
	assert(message:get_tag_all("key")[4] == -4)
	assert(message:get_position(1)[1] == 1)
	assert(message:get_position(1)[2] == 2)
	assert(message:get_position(1)[3] == 3)
	assert(message:get_position(1)[4] == -4)
	message:clear_array()

	message:push_tag("key", {1, 2, "3", -4})
	assert(message:get_tag_all("key")[1] == 1)
	assert(message:get_tag_all("key")[2] == 2)
	assert(message:get_tag_all("key")[3] == 3)
	assert(message:get_tag_all("key")[4] == -4)
	assert(message:get_position(1)[1] == 1)
	assert(message:get_position(1)[2] == 2)
	assert(message:get_position(1)[3] == 3)
	assert(message:get_position(1)[4] == -4)
	message:clear_array()

	-- Test pushing h values outside 64 bit signed range and which also
	-- cannot be held in lua double without loss of precision. It is not
	-- possible to loose precision for negative vales.
	message:push_tag_h("key", "18446744073709551615")
	message:push_tag_h("key", "-9223372036854775808")
	assert(type(message:get_tag_all("key")[1]) == "string")
	assert(type(message:get_tag_all("key")[2]) == "number")
	assert(message:get_tag_all("key")[1] == "18446744073709551615")
	assert(message:get_tag_all("key")[2] == -9223372036854775808)
	message:clear_array()

	-- Test push array of fixp's with both generic and specific method and set method
	message:push_tag_fixp("key", {1.0/3.0, 2.0/3.0, "3.0", "3.14"})

	assert((string.format("%.16f", message:get_tag_all("key")[1])):sub(1, 5) == "0.333")
	assert((string.format("%.16f", message:get_tag_all("key")[2])):sub(1, 6) == "0.6666")
	assert(                        message:get_tag_all("key")[3]             == 3)
	assert(                        message:get_tag_all("key")[4] > 3.13 and
	                               message:get_tag_all("key")[4] <= 3.14)

	assert((string.format("%.16f", message:get_position(1)[1])):sub(1, 5) == "0.333")
	assert((string.format("%.16f", message:get_position(1)[2])):sub(1, 6) == "0.6666")
	assert(                        message:get_position(1)[3]             == 3)
	assert(                        message:get_position(1)[4] > 3.13 and
	                               message:get_position(1)[4] <= 3.14)
	message:clear_array()

	message:push_tag("key", {1.0/3.0, 2.0/3.0})
	assert((string.format("%.16f", message:get_tag_all("key")[1])):sub(1, 5) == "0.333")
	assert((string.format("%.16f", message:get_tag_all("key")[2])):sub(1, 6) == "0.6666")
	assert((string.format("%.16f", message:get_position(1)[1])):sub(1, 5) == "0.333")
	assert((string.format("%.16f", message:get_position(1)[2])):sub(1, 6) == "0.6666")
	message:clear_array()

	-- Test push array of blobs with both generic and specific method and set method
	message:push_tag_blob("key", {"value1", "value2"})
	assert(message:get_tag_all("key")[1] == "value1")
	assert(message:get_tag_all("key")[2] == "value2")
	assert(message:get_position(1)[1] == "value1")
	assert(message:get_position(1)[2] == "value2")
	message:clear_array()

	-- Test array of bools. 0 and "" are true in Lua.
	message:push_tag("key", {true, false, 0, ""})
	assert(type(message:get_tag_all("key")[1]) == "number")
	assert(type(message:get_tag_all("key")[2]) == "number")
	assert(type(message:get_tag_all("key")[3]) == "number")
	assert(type(message:get_tag_all("key")[4]) == "number")
	assert(message:get_tag_all("key")[1] == 1)
	assert(message:get_tag_all("key")[2] == 0)
	assert(message:get_tag_all("key")[3] == 1)
	assert(message:get_tag_all("key")[4] == 1)
	message:clear_array()
end

function process_method(message, method)
	assert(method == nil, "method must be nil when direct dispatch is used")

	verify_defaults()

	-- TEST_DATA_ARRAY_DEFINITION=be4#int1,be3#int2,be2s#int3,be1#int4,sep1@1#sep1,le4@1#aaa,le3#bbb,le2s@1#ccc,le1#ddd,sep2#sep2,blob8@2#blob,msg#msg,str#emptystr,vain

	local tags = message:get_tag_names()
	for i = 1, message:count_positions() do
		local tag = tags[i]
		local values = message:get_position(i)
		print("pos " .. i .. " tag: " .. tag .. ":")
		for j = 1, #values do
			print(" - " .. values[j] .. "")
		end
	end

	local expected = {
		int1 = 1 << 24 | 2 << 8,
		int2 = 1 << 16 | 2 << 8,
		int3 = -33,
		int4 = 1,
		sep1 = ";",
		aaa = 1 << 24 | 2 << 8,
		bbb = 1 << 16 | 2 << 8,
		ccc = -33,
		ddd = 1,
		sep2 = "||",
		blob = {"abcdefg\0", "gfedcba\0"},
		emptystr = "",
	};
	local expected_keys = {"int1", "int2", "int3", "int4", "sep1", "aaa", "bbb", "ccc", "ddd", "sep2", "blob", "emptystr"};

	for _, k in pairs(expected_keys) do
		local v = expected[k]
		local values = message:get_tag_all(k)
		if type(v) == "table" then
			for i = 1, #v do
				print("string lengths are " .. #values[i] .. " == " .. #v[i])
				print("checking " .. k .. " value " .. values[i] .. " == " .. v[i])
				assert(values[i] == v[i])
			end
		else
			print("key is " .. k)
			print("type is " .. type(values[1]))
			print("v", v)
			print("values[1]", values[1])
			print("checking " .. k .. " value " .. values[1] .. " == " .. v)
			assert(values[1] == v)
		end
	end

	assert(message:get_tag_all("msg")[1]:len() == 31)
	assert(message:get_position(14)[1] == nil)
	assert(message.data == "")
	assert(message.type == RRR.Message.MSG_TYPE_MSG)
	assert(message.class == RRR.Message.MSG_CLASS_ARRAY)
	assert(message.topic == "socket/topic/a/b/c")
	assert(message.timestamp > 0)
	local ip, port = message:ip_get()
	assert(ip == "")
	assert(port == 0)
	assert(message.ip_so_type == "")

	message:send()

	return true
end

function process_fail(message, method)
	print("Incorrect method called, check method discerning")

	return false
end

function source(message)
	assert(message.timestamp > 0)
	assert(message.topic == "")
	assert(message.type == RRR.Message.MSG_TYPE_MSG)
	assert(message.class == RRR.Message.MSG_CLASS_DATA)
	assert(message:count_positions() == 0)

	return true
end
