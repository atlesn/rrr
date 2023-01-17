function config() {
	console.log("Config function\n");
}
function process(message) {
	console.log("Process function message " + message.ip_so_type + "\n");
	Object.keys(message).forEach((key) => {
		console.log("Key: " + key + "\n");
	});
	try {
	 	const address = message.ip_get();
		console.log("Ip: " + address + "\n");
	}
	catch (e) {
		console.log("Exception " + typeof e + ": " + e + "\n");
	}
//	message.set_ip(ip, port);
}
