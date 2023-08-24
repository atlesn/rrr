console.log("Running module!!!!!!!\n");

export function source(message) {
	message.push_tag("server", "localhost");
	message.send();
}
