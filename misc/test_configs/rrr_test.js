function config() {
	console.log("Config function\n");
}

function process(message) {
	let catched = false;

	console.log("Process function\n");

	const msg_a = new Message();
	const msg_b = new Message();

	msg_a.topic = "topic A";
	msg_b.topic = "topic B";
	console.log(msg_a.topic + "\n");
	console.log(msg_b.topic + "\n");

	const buf = new ArrayBuffer(65536);

	msg_a.push_tag("a", buf);
}
