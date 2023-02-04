console.log("Test of export keyword\n");
export function process(message) {
	console.log("Process function in module\n");
	message.send();
}
