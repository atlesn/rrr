console.critical = console.log;

import("failing import").then(() => {
	console.critical("Import did not fail as expected\n");
}).catch((msg) => {
	console.log("Script loaded as module failed as expected: " + msg + "\n");
});
	
import("./test_module_process.js").then((mod) => {
	if (mod.process == undefined) {
		console.critical("Function process not found in dynamic import\n");
	}
	console.log("Module as script load succeeded\n");
}).catch((msg) => {
	console.critical("Dynamic import of module as script failed: " + msg + "\n");
});
