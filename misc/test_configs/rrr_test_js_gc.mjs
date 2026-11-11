function log(msg) {
	console.log(msg + "\n");
}

// CLIENT

let request_index = 1;
const requests = {};

export function process_client(message) {
	if (requests[message.topic]) {
		// log("Response for " + message.topic);
		delete requests[message.topic];
	}
	else {
		// log("Stale response for " + message.topic);
	}
}

const max_size = 1024 * 1024;
const random_bytes = new Uint8Array(max_size);
for (let i = 0; i < max_size; i++) {
	random_bytes[i] = Math.floor(Math.random() * 256);
}

export function source_client(message) {
	message.topic = "request/" + request_index++;

	requests[message.topic] = {
		time: Date.now()
	};

	const random_size = Math.floor(Math.random() * max_size);
	const bytes = new Uint8Array(random_size);
	for (let i = 0; i < random_size; i++) {
		bytes[i] = random_bytes[i];
	}
	message.data = bytes.buffer;

	message.send();

	new Timeout(() => {
		if (requests[message.topic]) {
			// log("Timeout for request " + message.topic);
			delete requests[message.topic];
		}
	}, 2000);
}

// SERVER

let request_counter = 1;
export function process_server(message) {
	new Timeout(() => {
		message.send();
	}, Math.floor(Math.random() * 2500));
}
