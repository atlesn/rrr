console.log("Running module!!!!!!!\n");

var pos = 0;

export function source(message) {
	message.push_tag("modbus_server", "localhost");
	message.push_tag("modbus_interval_ms", "50");
	message.push_tag("modbus_function", "3");
	message.push_tag("modbus_response_topic", "topic3");
	message.send();

	message.clear_tag("modbus_function");
	message.clear_tag("modbus_response_topic");

	message.push_tag("modbus_function", "2");
	message.push_tag("modbus_response_topic", "topic2");
	message.send();
}
