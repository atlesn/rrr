import("./test_module_process.mjs").then((mod) => {
	if (mod.process == undefined) {
		console.critical("Function process not found in dynamic import\n");
	}
}).catch((msg) => {
	console.critical("Dynamic import of module as script failed: " + msg + "\n");
});
