function config() {
	console.log("Config function\n");
}

function process(message) {
	console.log("Process function message " + message.ip_so_type + "\n");

	Object.keys(message).forEach((key) => {
		console.log("Key: " + key + "\n");
	});

	message.ip_set("1.2.3.4", "5");
	const [addr, port] = message.ip_get();
	console.log("Ip: " + addr + ", Port: " + port + "\n");
	if (addr !== "1.2.3.4" || port !== 5) {
		throw("Data mismatch\n");
	}

	// Let exceptions propagate causing test to fail
}
