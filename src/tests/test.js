function config() {
	console.log("Config function\n");
}
function process(message) {
	console.log("Process function message " + message.ip_so_type + "\n");
	message.get_ip();
	const [ip, port] = message.get_ip();
	message.set_ip(ip, port);
}
