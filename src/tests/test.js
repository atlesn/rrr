function config(config) {
	console.log("Config function\n");

	// Local Message objects
	const msg_a = new Message();
	const msg_b = new Message();

	msg_a.topic = "topic A";
	msg_b.topic = "topic B";
	console.log(msg_a.topic + "\n");

	// Local Config object
	let catched = false;
	try {
		config_local = new Config();
	}
	catch (e) {
		catched = true;
	}
	if (!catched) {
		throw("local new of Config did not throw error");
	}

	// Settings
	if (!config.has("custom_setting")) {
		throw("has() returned false");
	}

	if (config.get("custom_setting") !== "XXX") {
		throw("get() incorrect result");
	}
}

function check_array_buffer(buffer, check_buffer) {
	if (buffer.length != check_buffer.length) {
		throw("length mismatch");
	}
	for (let i = 0; i < check_buffer.length; i++) {
		if (buffer[i] != check_buffer[i]) {
			throw("data mismatch");
		}
	}
}

function message_tests() {
	const message = new Message();

	Object.keys(message).forEach((key) => {
		console.log("Message member: " + key + "\n");
	});

	// Let any exceptions propagate causing test to fail unless
	// we provoke the exception to be catch and test for that.

	let catched = false;

	// Test ip_set / ip_get
	message.ip_set("1.2.3.4", "5");
	const [addr, port] = message.ip_get();
	console.log("Ip: " + addr + ", Port: " + port + "\n");
	if (addr !== "1.2.3.4" || port !== 5) {
		throw("Data mismatch\n");
	}

	// Test ip_addr
	if (message.ip_addr === undefined) {
		throw("ip_addr did not return a value");
	}
	if (message.ip_addr.byteLength === undefined) {
		throw("ip_addr did not return an ArrayBuffer");
	}
	if (message.ip_addr.byteLength == 0) {
		throw("ip_addr did not a length > 0");
	}
	console.log("Length of IP: " + message.ip_addr.byteLength + "\n");

	catched = false;
	try {
		message.ip_addr = 0;
	}
	catch (e) {
		catched = true;
	}
	if (!catched) {
		throw("ip_addr did not refuse change");
	}

	// Test ip_so_type field
	catched = false;
	try {
		message.ip_so_type = "xxxx";
	}
	catch (e) {
		catched = true;
	}
	if (!catched) {
		throw("ip_so_type accepted invalid value\n");
	}
	message.ip_so_type = "UDP";
	if (message.ip_so_type !== "UDP") {
		throw("ip_so_type value mismatch\n");
	}
	console.log("sotype: " + message.ip_so_type + "\n");

	// Message topic field
	catched = false;
	try {
		message.topic = "#/#/#";
	}
	catch (e) {
		catched = true;
	}
	if (!catched) {
		throw("topic field accepted invalid value\n");
	}
	message.topic = "";
	message.topic = "a/b/c";
	if (message.topic !== "a/b/c") {
		throw("topic value mismatch\n");
	}
	console.log("Topic: " + message.topic + "\n");

	// Timestamp field
	catched = false;
	try {
		message.timestamp = "%%%";
	}
	catch (e) {
		catched = true;
	}
	if (!catched) {
		throw("timestamp field accepted invalid value\n");
	}
	const timestamp = BigInt(message.timestamp);
	message.timestamp += BigInt(1);
	if (message.timestamp - timestamp != 1) {
		throw("timestamp value mismatch\n");
	}
	console.log("Timestamp: " + message.timestamp + "\n");

	// Data field
	message.data = undefined;
	message.data = null;
	message.data = "aaa";
	catched = false;
	try {
		message.data = 123;
	}
	catch (e) {
		catched = true;
	}
	if (!catched) {
		throw("data field accepted invalid value\n");
	}
	const buffer = new ArrayBuffer(4);
	const buffer_u8 = new Int8Array(buffer);

	buffer_u8[0] = 65;
	buffer_u8[1] = 66;
	buffer_u8[2] = 67;
	buffer_u8[3] = 68;

	message.data = buffer;

	const check_buffer = message.data;
	const check_buffer_u8 = new Int8Array(buffer);

	try {
		check_array_buffer(buffer_u8, check_buffer_u8);
	}
	catch (e) {
		throw("data error: " + e + "\n");
	}

	console.log("Data: " + check_buffer_u8.join(",") + "\n");

	// Type field
	catched = false;
	try {
		message.type = 0;
	}
	catch (e) {
		catched = true;
	}
	if (!catched) {
		throw("type field accepted invalid value\n");
	}
	message.type = message.MSG_TYPE_MSG;
	message.type = message.MSG_TYPE_TAG;
	message.type = message.MSG_TYPE_GET;
	message.type = message.MSG_TYPE_PUT;
	message.type = message.MSG_TYPE_DEL;
	console.log("Type: " + message.type + "\n");

	// Class field
	catched = false;
	try {
		message.class = 1;
	}
	catch (e) {
		catched = true;
	}
	if (!catched) {
		throw("class field allowed modification\n");
	}
	message.push_tag();
	if (message.class !== message.MSG_CLASS_ARRAY) {
		throw("class was not ARRAY as expected\n");
	}
	message.clear_array();
	if (message.class !== message.MSG_CLASS_DATA) {
		throw("class was not DATA as expected\n");
	}
	console.log("Class: " + message.class + "\n");

	// Array values
	message.push_tag();              // [0]
	if (message.get_tag_all()[0] !== null) {
		throw("array data mismatch vain\n");
	}

	message.push_tag("tag", "bbb");  // [0]
	message.push_tag(null, "ccc");   // [1]
	message.push_tag_str("", "ddd"); // [2]
	if (message.get_tag_all("tag")[0] !== "bbb") {
		throw("array data mismatch bbb\n");
	}
	if (message.get_tag_all("")[1] !== "ccc") {
		throw("array data mismatch ccc\n");
	}
	if (message.get_tag_all()[2] !== "ddd") {
		throw("array data mismatch ddd 1st\n");
	}
	message.set_tag("", message.get_tag_all()[2]);
	if (message.get_tag_all()[0] !== "ddd") {
		throw("array data mismatch ddd 2nd\n");
	}
	message.clear_array();
	if (message.get_tag_all("tag")[0] !== undefined) {
		throw("array data mismatch undefined\n");
	}
	message.clear_array();

	catched = false;
	try {
		message.push_tag("blob", new ArrayBuffer());
	}
	catch (e) {
		catched = true;
	}
	if (!catched) {
		throw("blob allowed 0 byte push\n");
	}

	const blob = new ArrayBuffer(3);
	const blob_u8 = new Int8Array(blob);

	blob_u8[0] = 65;
	blob_u8[1] = 66;
	blob_u8[2] = 67;

	message.push_tag("blob", blob);
	message.push_tag_blob("blob", blob);

	const check_blob_u8_a = new Int8Array(message.get_tag_all("blob")[0]);
	const check_blob_u8_b = new Int8Array(message.get_tag_all("blob")[1]);

	try {
		check_array_buffer(blob_u8, check_blob_u8_a);
		check_array_buffer(blob_u8, check_blob_u8_b);
	}
	catch (e) {
		throw("blob error: " + e + "\n");
	}

	console.log("Data: " + check_blob_u8_a.join(",") + "\n");

	catched = false;
	try {
		message.push_tag_h("h", ")(*&^%$#@");
	}
	catch (e) {
		catched = true;
	}
	if (!catched) {
		throw("h allowed bogus data push\n");
	}

	message.push_tag("h", 12);
	message.push_tag_h("h", BigInt(34));
	message.push_tag("h", BigInt(56));
	message.push_tag_h("h", 78);
	message.push_tag_h("h", -9);
	message.push_tag("h", BigInt(8888888888888888));
	message.push_tag_h("h", BigInt("9999999999999999"));

	if (message.get_tag_all("h")[0] !== 12) {
		throw("h data mismatch 12");
	}
	if (message.get_tag_all("h")[1] !== 34) {
		throw("h data mismatch 34");
	}
	if (message.get_tag_all("h")[2] !== 56) {
		throw("h data mismatch 56");
	}
	if (message.get_tag_all("h")[3] !== 78) {
		throw("h data mismatch 78");
	}
	if (message.get_tag_all("h")[4] !== -9) {
		throw("h data mismatch -9");
	}
	if (message.get_tag_all("h")[5] !== BigInt(8888888888888888)) {
		throw("h data mismatch 8888888888888888");
	}
	if (message.get_tag_all("h")[6] !== BigInt("9999999999999999")) {
		throw("h data mismatch 9999999999999999");
	}

	console.log("H: " + message.get_tag_all("h").join(",") + "\n");

	message.push_tag("fixp", 22);
	message.push_tag("fixp", "33");
	message.push_tag("fixp", BigInt(44));

	if (message.get_tag_all("fixp")[0] !== 22) {
		throw("fixp data mismatch 22");
	}
	if (message.get_tag_all("fixp")[1] !== 33) {
		throw("fixp data mismatch 33");
	}
	if (message.get_tag_all("fixp")[2] !== 44) {
		throw("fixp data mismatch 44");
	}

	console.log("fixp: " + message.get_tag_all("fixp").join(",") + "\n");

	message.clear_array();
	if (message.get_tag_all()[0] !== undefined) {
		throw("Clear tag error E" + message.get_tag_all()[0]);
	}
	message.push_tag();
	message.push_tag("tag");

	if (message.get_tag_all()[0] !== null) {
		throw("Clear tag error A");
	}
	if (message.get_tag_all("tag")[0] !== null) {
		throw("Clear tag error B");
	}

	message.clear_tag();
	message.clear_tag("tag");

	if (message.get_tag_all()[0] !== undefined) {
		throw("Clear tag error C" + message.get_tag_all()[0]);
	}
	if (message.get_tag_all("tag")[0] !== undefined) {
		throw("Clear tag error D");
	}

	console.log("Values cleared\n");
}

function os_tests() {
	const os = new OS();
	Object.keys(os).forEach((key) => {
		console.log("OS member: " + key + "\n");
	});

	const hostname = os.hostname();
	console.log("Hostname is '" + hostname + "'\n");
	if (hostname.length < 1) {
		throw("Hostname length was 0");
	}
}

function data_tests() {
	const message = new Message();

	message.data = new ArrayBuffer(new Uint8Array([0xc3, 0xa6, 0xc3, 0xb8, 0xc3, 0xa5])); // æøå
	if (message.data_as_utf8() !== "æøå") {
		throw new Error("UTF-8 decoding failed for valid input.");
	}

	// {"key": "æøå"}
	message.data = new ArrayBuffer(new Uint8Array([
		0x7b,
		0x22, 0x6b, 0x65, 0x79, 0x22,
		0x3a,
		0x22, 0xc3, 0xa6, 0xc3, 0xb8, 0xc3, 0xa5, 0x22,
		0x7d
	]));
	if (message.data_as_json().key !== "æøå") {
		throw("JSON decoding failed for valid input.");
	}

	let did_throw = false;

	// Invalid UTF-8
	message.data = new ArrayBuffer(new Uint8Array([0xff, 0xff]));
	try {
		message.data_as_utf8();
	} catch (e) {
		did_throw = true;
	}
	if (!did_throw) {
		throw("UTF-8 decode did not fail as expected.");
	}

	did_throw = false;

	// "invalid" spelled out
	message.data = new ArrayBuffer(new Uint8Array([0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64]));
	try {
		message.data_as_json();
	} catch (e) {
		did_throw = true;
	}
	if (!did_throw) {
		throw("JSON decode did not fail as expected.");
	}
}

function my_method(message, method) {
	console.log("Process function\n");

	if (method !== undefined) {
		throw("Method to JS process function was not undefined");
	}

	message_tests();
	os_tests();
	data_tests();

	// Timeouts
	let done = {
		a: false,
		b: false
	};

	new Timeout(() => {
		console.log("Timeout C\n");
		if (!done["a"]) {
			throw("Incorrect timeout order, A did not run first");
		}
		if (!done["b"]) {
			throw("Incorrect timeout order, B did not run first");
		}
		console.log("Sending message\n");
		message.send();
	}, 200); // Should run last

	new Timeout((a) => {
		console.log("Timeout A\n");
		if (a !== "a") {
			throw("Value mismatch in timeout a");
		}
		done["a"] = true;
		new Timeout(() => {
			console.log("Timeout B\n");
			done["b"] = true;
		}, 1); // Should run first
	}, 100, "a");

	let timeout = new Timeout(() => {
		throw("Timeout was not cleared");
	}, 99);

	timeout.clear();
}
