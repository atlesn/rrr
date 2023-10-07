function config()
	return true
end

function process(message)
	print("type", type(message))
	for k, v in pairs(message) do
		print (k, "=>", v)
	end
	assert(false, "STOP")
	return true
end
