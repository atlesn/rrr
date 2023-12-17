var pos = 0;
const obj = {
	a: [1, 2, 3],
	b: {
		x: 4,
		y: 5,
		z: 6
	}
};

function equals(a, b) {
	if (typeof a !== typeof b) {
		console.log("Mismatch, a and b are not the same type\n");
		return false;
	}

	if (Array.isArray(a)) {
		if (!Array.isArray(b)) {
			console.log("Mismatch, b is not array\n");
			return false;
		}
		if (a.length !== b.length) {
			console.log("Mismatch, array length mismatch\n");
			return false;
		}
		for (let i = 0; i < a.length; i++) {
			if (!equals(a[i], b[i])) {
				return false;
			}
		}
	}

	switch (typeof a) {
		case "number":
		case "string":
			console.log("Compare primitives " + a + "<>" + b + "\n");
			return a === b;
		case "object":
			const a_keys = Object.keys(a);
			const b_keys = Object.keys(b);
			if (a_keys.length != b_keys.length) {
				console.log("Mismatch, number of keys differ " + a_keys.length + "<>" + b_keys.length + "\n");
				return false;
			}
			let result = true;
			a_keys.forEach((key) => {
				if (!(key in b)) {
					console.log("Mismatch, key '" + key + "' is not in b\n");
					result = false;
				}
				if (!equals(a[key], b[key])) {
					result = false
				}
			});
			if (!result)
				return false;
			break;
		default:
			throw "Unknown type " + typeof a + "\n";
	};

	return true;
}

export function source(message) {
	if (pos++ > 0)
		return;

	console.log("Generating test message\n");

	const cycle = {};
	cycle.cycle = cycle;

	let failed = false;
	try {
		message.push_tag("json", cycle);
	}
	catch (e) {
		// OK, cycle stringify failed
		failed = true;
	}

	if (!failed) {
		console.error("JSON stringify of cycled object did not fail as expected\n");
		return;
	}

	message.topic = "json";

	message.push_tag("json", obj);
	message.push_tag_object("json", obj);

	{
		const a = (message.get_tag_all("json"))[0];
		const b = (message.get_tag_all("json"))[1];

		if (!equals(a, b)) {
			console.error("Mismatch between push_tag and push_tag_object " +
				JSON.stringify(a) + "<>" +  JSON.stringify(b) + "\n");
			return;
		}
	}

	// The V8 JSON::Stringify might allow these values and produce
	// JSON output with just strings, ensure that RRR JS library
	// checks for this and rejects the values.
	try { message.push_tag_object("json_invalid", undefined); } catch (e) {
		console.log("Push failed as expected: " + e + "\n");
	}
	try { message.push_tag_object("json_invalid", 0); }         catch (e) {
		console.log("Push failed as expected: " + e + "\n");
	}
	try { message.push_tag_object("json_invalid", null); }      catch (e) {
		console.log("Push failed as expected: " + e + "\n");
	}
	try { message.push_tag_object("json_invalid", () => {}); }      catch (e) {
		console.log("Push failed as expected: " + e + "\n");
	}
	try { message.push_tag_object("json_invalid", BigInt(666)); }      catch (e) {
		console.log("Push failed as expected: " + e + "\n");
	}

	if ((message.get_tag_all("json_invalid"))[0] !== undefined) {
		console.error("Invalid objects were allowed to be pushed using push_tag_object\n");
		return;
	}

	message.send();
}

export function process(message) {
	console.log("Received test message back\n");

	const obj_cmp = (message.get_tag_all("json"))[0];

	console.log("Testing failing equals comparison\n");
	obj_cmp.c = "fail";
	if (equals(obj_cmp, obj) !== false) {
		console.error("Equals check did not fail as expected");
		return;
	}
	delete obj_cmp.c;

	console.log("Testing succeeding equals comparison\n");
	if (equals(obj_cmp, obj) !== true) {
		console.error("Equals check did not succeed as expected");
		return;
	}

	message.topic = "success";
	message.send();
}
