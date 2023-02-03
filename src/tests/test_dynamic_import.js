console.log("Test of dynamic import which fails\n");
let throwed = false;
await import("failing import").then().catch(() => {
	throwed = true;
});
if (!throwed) {
	throw "Import did not fail as expected\n";
}

let failed = false;
console.log("Test of dynamic import which succeeds\n");
await import("./test_module_process.js").then((mod) => {
	if (mod.process == undefined) {
		console.error("Function process not found in dynamic import");
		failed = true;
	}
}).catch(() => {
	failed = true;
});
if (failed) {
	throw "Import failed unexpectedly\n";
}
