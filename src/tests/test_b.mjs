import { cfunc } from "./test_c.mjs";

export function bfunc(n) {
	cfunc(n + 1);
}

console.log("B ran\n");
