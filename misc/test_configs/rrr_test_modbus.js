console.log("Running module!!!!!!!\n");

export function source(message) {
	message.push_tag("modbus_server", "localhost");
	message.push_tag("modbus_interval_ms", "2");
	message.push_tag("modbus_function", "3");
	message.send();
}
