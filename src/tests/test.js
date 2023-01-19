function config() {
	console.log("Config function\n");
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

function process(message) {
	let catched = false;

	console.log("Process function\n");

	Object.keys(message).forEach((key) => {
		console.log("Key: " + key + "\n");
	});

	// Let any exceptions propagate causing test to fail unless
	// we provoke the exception to be catch and test for that.

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
	message.ip_so_type = "udp";
	if (message.ip_so_type !== "udp") {
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
	// TODO : Verify that class changes when array is populated
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
		throw("array data mismatch ddd\n");
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

/*
  clear_array:   function(){},                  // Clear all array data
  push_tag_blob: function(tag=null, data){},    // Push array value of type blob
  push_tag_str:  function(tag=null, data){},    // Push array value of type string
  push_tag_h:    function(tag=null, data){},    // Push array value of type host (integer)
  push_tag_fixp: function(tag=null, data){},    // Push array value of type fixp (fixed pointer)
  push_tag:      function(tag=null, data){},    // Push array value and identify type automatically
  clear_tag:     function(tag=null){},          // Clear all array values with the given tag
  get_tag_all:   function(tag=null){return [];} // Get array of values with the given tag
 * */
}
