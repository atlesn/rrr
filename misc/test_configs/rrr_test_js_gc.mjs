console.log("Running module!!!!!!!\n");

export function config() {
	console.log("Config function\n");
	import("./rrr_test_module_dynamic.js").then((namespace) => {
		console.log("Loaded, now running: " + namespace.dynamic() + "\n");
		Object.keys(namespace.dynamic).forEach((key) => {
			console.log("Key: " + key + "\n");
		});
	}).catch((e) => {
		console.log("Rejected: " + e + "\n");
	});
}

let p = new Promise((resolve, reject) => {
	new Timeout(() => {resolve("Done\n")}, 1000);
}).then((msg) => {console.log(msg)});

const timeouts = {};
const buffers = {};
const args = {};
let timeout_i = 0;

export function source(message) {
	message.ip_set("127.0.0.1", "2001");
	message.push_tag("data", "dasdsadsadas\n");
	message.ip_so_type="TCP";
	message.send();

	// Garbe collection testing. When debugging is enabled in Persistent.cxx:
	// - The ArrayBuffers and Timeouts are expected to be GCed very quickly
	// - The booleans will not immediately get GCed, and all of them will
	//   most likely persist after this loop and timeouts are completed.
	for (let i = 0; i < 5 && timeout_i < 100; i++) {
		console.log("Create timeout " + timeout_i + "\n");
		buffers[timeout_i] = new ArrayBuffer(32 * 1024 * 1024);
		args[timeout_i] = true;
		timeouts[timeout_i] = new Timeout(function(timeout_i){return (n) => {
			console.log("Timeout " + timeout_i + "\n");
			delete timeouts[timeout_i];
			delete buffers[timeout_i];
			delete args[timeout_i];
		}}(timeout_i), 1500, buffers[timeout_i], args[timeout_i]);

		timeout_i++;
	}
}

export function process(message) {
//	console.log("Process function topic " + message.topic + "\n");

//	const msg_a = new Message();
	//const msg_b = new Message();

//	msg_a.topic = "topic A";
	//msg_b.topic = "topic B";
//	console.log(msg_a.topic + "\n");
//	console.log(msg_b.topic + "\n");

//	console.log("Process function topic " + msg_a.topic + "\n");

//	const buf = new ArrayBuffer(65536 * 16);
//	message.push_tag("a", buf);

//	message.send();
	//
	const [ip, port] = message.ip_get();
	const data = message.get_tag_all("data")[0];
	console.log("From: " + ip + ":" + port + " Data: " + data + "\n");
}
