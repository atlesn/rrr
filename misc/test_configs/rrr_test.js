function config() {
	console.log("Config function\n");
}

let timeouts = 0;
	
for (let i = 0; i < 20; i++) {
//		let message = new Message();
		let timeout = new Timeout(function(i){return () => { console.log("Timeout " + 100*i*i + "\n"); timeouts++; }}(i), 100*i*i, 1, 2, 3, 4);
	}

function process(message) {
//	console.log("Process function topic " + message.topic + "\n");


//	console.log("Timeouts: " + timeouts + "\n");

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
