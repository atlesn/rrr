import * as mod1 from "./test_import_once_module.mjs";

import * as mod2 from "../tests/test_import_once_module.mjs";

import * as mod3 from "./test_import_once_module.link.mjs";

function assertEquals(a, b) {
	if (a !== b) {
		throw("Mismatch");
	}
}

assertEquals(mod1, mod2);
assertEquals(mod2, mod3);
