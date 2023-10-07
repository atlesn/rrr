function config()
	-- TODO : Test config stuff
	return true
end

function process(message)
	print("type", type(message))
	for k, v in pairs(message) do
		print (k, "=>", v)
	end

	message:ip_set("1.2.3.4", 5);

	assert(false, "STOP")
	return true
end
