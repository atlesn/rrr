function process (message) {
//	console.log("Response\n");

	message.clear_array();
	message.push_tag("http_body", "Hello");
	message.send();
}
