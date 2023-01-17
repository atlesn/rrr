function config() {
	console.log("Config function\n");
}

function process(message) {
	let catched = false;

	console.log("Process function");

	Object.keys(message).forEach((key) => {
		console.log("Key: " + key + "\n");
	});

	// Let any exceptions propagate causing test to fail unless
	// we provoke the exception to be catch and test for that.

	// Test ip_set / ip_get
	message.ip_set("1.2.3.4", "5");
	const [addr, port] = message.ip_get();
	console.log("Ip: " + addr + ", Port: " + port + "\n");
	if (addr !== "1.2.3.4" || port !== 5) {
		throw("Data mismatch\n");
	}

	// Test ip_addr
	if (message.ip_addr === undefined) {
		throw("ip_addr did not return a value");
	}
	if (message.ip_addr.byteLength === undefined) {
		throw("ip_addr did not return an ArrayBuffer");
	}
	if (message.ip_addr.byteLength == 0) {
		throw("ip_addr did not a length > 0");
	}

	console.log("Length of IP: " + message.ip_addr.byteLength + "\n");

	catched = false;
	try {
		message.ip_addr = 0;
	}
	catch (e) {
		catched = true;
	}
	if (!catched) {
		throw("ip_addr did not refuse change");
	}

	// Test ip_so_type field
	catched = false;
	try {
		message.ip_so_type = "xxxx";
	}
	catch (e) {
		catched = true;
	}
	if (!catched) {
		throw("ip_so_type accepted invalid value\n");
	}
	message.ip_so_type = "udp";
	if (message.ip_so_type !== "udp") {
		throw("ip_so_type value mismatch\n");
	}

	// Message topic field
	catched = false;
	try {
		message.topic = "#/#/#";
	}
	catch (e) {
		catched = true;
	}
	if (!catched) {
		throw("topic field accepted invalid value\n");
	}
	message.topic = "";
	message.topic = "a/b/c";
	if (message.topic !== "a/b/c") {
		throw("topic value mismatch\n");
	}
	console.log("Message topic: " + message.topic + "\n");
}
