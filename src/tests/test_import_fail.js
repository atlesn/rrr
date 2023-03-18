// When running under NodeJS, critical() does not exist
if (console.critical === undefined) {
	console.critical = console.log;
}

// File does not exist
import("/test_fail.mjs").then(() => {
	console.critical("Import of non-exsistent file did not fail as expected\n");
}).catch((msg) => {
	// OK
});

// File exists but must have ./ in front when loading
import("test_fail.mjs").then(() => {
	console.critical("Import of bare module name did not fail as expected\n");
}).catch((msg) => {
});
