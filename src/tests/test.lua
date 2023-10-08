function config()
	-- TODO : Test config stuff
	return true
end

function process(message)
	print("type", type(message))
	for k, v in pairs(message) do
		print (k .. " =>", v)
	end

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

	return true
end
