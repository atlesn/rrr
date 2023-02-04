import("failing import").then(() => {
	console.error("Import did not fail as expected\n");
}).catch(() => {
	import("./test_module_process.js").then((mod) => {
		if (mod.process == undefined) {
			console.error("Function process not found in dynamic import");
		}
		else {
			console.error("OK\n");
		}
	});
});
