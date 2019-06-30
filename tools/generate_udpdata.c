#include <stdint.h>
#include <unistd.h>
#include <endian.h>
#include <stdio.h>

// Matches the following string:
// be,4,be,4,be,4,be,4,be,4,be,4,be,4,array,10,be,4,array,10,be,4,be,4

int main (int argc, char **argv) {
	union {
		uint32_t num;
		uint8_t bytes[4];
	} num;

	for (int i = 0; i < 27; i++) {
		num.num = htobe32(i + 1);

//		printf("%02x-%02x-%02x-%02x\n", num.bytes[0], num.bytes[1], num.bytes[2], num.bytes[3]);
		write(1, &num, sizeof(num));
	}

	num.num = 1; // Endian indicator
	write(1, &num, sizeof(num));
}
