function config() {
	console.log("Config function\n");
}

let timeouts = 0;

function process(message) {
//	console.log("Process function topic " + message.topic + "\n");

	for (let i = 0; i < 1000; i++) {
//		let message = new Message();
		let timeout = new Timeout(() => { timeouts++; }, 2000, 1, 2, 3, 4);
	}

	console.log("Timeouts: " + timeouts + "\n");

//	let timeout = setTimeout(() => {
//		console.log("Timeout\n");
//	}, 1000);

//	const msg_a = new Message();
	//const msg_b = new Message();

//	msg_a.topic = "topic A";
	//msg_b.topic = "topic B";
//	console.log(msg_a.topic + "\n");
//	console.log(msg_b.topic + "\n");

//	console.log("Process function topic " + msg_a.topic + "\n");

//	const buf = new ArrayBuffer(65536 * 16);
//	message.push_tag("a", buf);

	message.send();
}
