let ok = false;
await import("test.json").then((json) => {
	console.log("Text from JSON: " + json.foo + "\n");
	if (json.foo === "bar") {
		ok = true;
		console.log("Match\n");
	}
	else {
		console.log("Mismatch\n");
	}
}).catch((msg) => {
	console.log("Loading of JSON failed: " + msg);
});
if (!ok) {
	throw "Failed to load JSON file";
}
