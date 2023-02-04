// When running under NodeJS, critical() does not exist
if (console.critical === undefined) {
	console.critical = console.log;
}

import("./test_module_process.js", { assert: {type: "json"} }).then((mod) => {
	console.critical("Script was loaded despite JSON assertion being set\n");
}).catch((msg) => {
	console.log("Script loaded as JSON failed as expected: " + msg + "\n");
});

import("./test.json", { assert: {type: "json"} }).then((mod) => {
	if (mod.default.foo !== "bar") {
		console.log("" + mod.default.foo + "\n");
		console.critical("Mismatch in variable from JSON file. Value was '" + mod.foo + "'.\n");
	}
	console.log("Module as JSON load succeeded\n");
}).catch((msg) => {
	console.critical("Dynamic import of module as JSON failed: " + msg + "\n");
});
