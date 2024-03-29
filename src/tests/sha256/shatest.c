/*
The Unlicense
=============
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this software, either in source code form or as a compiled binary, for any purpose, commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of this software dedicate any and all copyright interest in the software to the public domain. We make this dedication for the benefit of the public at large and to the detriment of our heirs and successors. We intend this dedication to be an overt act of relinquishment in perpetuity of all present and future rights to this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to http://unlicense.org

Zero Clause BSD License
=======================
© 2021 Alain Mosnier

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../lib/util/sha256.h"

#include "../../lib/rrr_config.h"
RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("sha");

struct string_vector {
	const char *input;
	const char *output;
};

static const struct string_vector STRING_VECTORS[] = {
    {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
     "a8ae6e6ee929abea3afcfc5258c8ccd6f85273e0d4626d26c7279f3250f77c8e"},
    {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
     "057ee79ece0b9a849552ab8d3c335fe9a5f1c46ef5f1d9b190c295728628299c"},
    {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
     "2a6ad82f3620d3ebe9d678c812ae12312699d673240d5be8fac0910a70000d93"},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
    {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
     "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"}};

// Keep disabled normally as allocation failure sometimes occurs causing test to fail
#define LARGE_MESSAGES 0

static uint8_t data1[] = {0xbd};
static uint8_t data2[] = {0xc9, 0x8c, 0x8e, 0x55};
static uint8_t data7[1000];
static uint8_t data8[1000];
static uint8_t data9[1005];
#if LARGE_MESSAGES
#define SIZEOF_DATA11 536870912
#define SIZEOF_DATA12 1090519040
#define SIZEOF_DATA13 1610612798
static uint8_t *data11;
static uint8_t *data12;
static uint8_t *data13;
#endif

struct vector {
	const uint8_t *input;
	size_t input_len;
	const char *output;
};

static struct vector vectors[] = {
    {data1, sizeof data1, "68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b"},
    {data2, sizeof data2, "7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504"},
    {data7, 55, "02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7"},
    {data7, 56, "d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb"},
    {data7, 57, "65a16cb7861335d5ace3c60718b5052e44660726da4cd13bb745381b235a1785"},
    {data7, 64, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"},
    {data7, sizeof data7, "541b3e9daa09b20bf85fa273e5cbd3e80185aa4ec298e765db87742b70138a53"},
    {data8, sizeof data8, "c2e686823489ced2017f6059b8b239318b6364f6dcd835d0a519105a1eadd6e4"},
    {data9, sizeof data9, "f4d62ddec0f3dd90ea1380fa16a5ff8dc4c54b21740650f24afc4120903552b0"}
#if LARGE_MESSAGES
    ,
    {NULL, 1000000, "d29751f2649b32ff572b5e0a9f541ea660a50f94ff0beedfb0b692b924cc8025"},
    {NULL, SIZEOF_DATA11, "15a1868c12cc53951e182344277447cd0979536badcc512ad24c67e9b2d4f3dd"},
    {NULL, SIZEOF_DATA12, "461c19a93bd4344f9215f5ec64357090342bc66b15a148317d276e31cbc20b53"},
    {NULL, SIZEOF_DATA13, "c23ce8a7895f4b21ec0daf37920ac0a262a220045a03eb2dfed48ef9b05aabea"}
#endif
};

static void construct_binary_messages(void)
{
	memset(data7, 0x00, sizeof data7);
	memset(data8, 0x41, sizeof data8);
	memset(data9, 0x55, sizeof data9);
#if LARGE_MESSAGES
	/*
	 * Heap allocation as a workaround for some linkers not liking large BSS segments.
	 */
	data11 = malloc(SIZEOF_DATA11);
	data12 = malloc(SIZEOF_DATA12);
	data13 = malloc(SIZEOF_DATA13);
	memset(data11, 0x5a, SIZEOF_DATA11);
	memset(data12, 0x00, SIZEOF_DATA12);
	memset(data13, 0x42, SIZEOF_DATA13);
	vectors[9].input = data12;
	vectors[10].input = data11;
	vectors[11].input = data12;
	vectors[12].input = data13;
#endif
}

static void destruct_binary_messages(void)
{
#if LARGE_MESSAGES
	free(data11);
	free(data12);
	free(data13);
#endif
}

static void hash_to_string(char string[65], const uint8_t hash[32])
{
	size_t i;
	for (i = 0; i < 32; i++) {
		string += sprintf(string, "%02x", hash[i]);
	}
}

static int string_test(const char input[], const char output[])
{
	uint8_t hash[32];
	char hash_string[65];
	rrr_sha256_calculate(hash, input, strlen(input));
	hash_to_string(hash_string, hash);
	printf("input: %s\n", input);
	printf("hash : %s\n", hash_string);
	if (strcmp(output, hash_string)) {
		printf("FAILURE!\n\n");
		return 1;
	} else {
		printf("SUCCESS!\n\n");
		return 0;
	}
}

/*
 * This define is only here to ease compared timing measurements between the non-streaming solution (former
 * implementation) and the streaming solution.
 */
/*
 * Note : Streaming interface not exposed, test singular method only
 */
#define CALC_IN_CHUNKS 0

#if CALC_IN_CHUNKS
static void calc_sha_256_in_chunks(uint8_t hash[SIZE_OF_SHA_256_HASH], const void *input, size_t len, size_t num_chunks)
{
	struct Sha_256 sha_256;
	sha_256_init(&sha_256, hash);

	if (num_chunks > 0) {
		const size_t chunk_size = len / num_chunks;
		const size_t last_chunk_size = len % num_chunks;
		const uint8_t *p = input;
		while (num_chunks-- > 0) {
			sha_256_write(&sha_256, p, chunk_size);
			p += chunk_size;
		}
		sha_256_write(&sha_256, p, last_chunk_size);
	}

	(void)sha_256_close(&sha_256);
}
#endif

/*
 * Limitation:
 * - The variable input_len will be truncated to its LONG_BIT least significant bits in the print output. This will
 *   never be a problem for values that in practice are less than 2^32 - 1. Rationale: ANSI C-compatibility and keeping
 *   it simple.
 */
#if CALC_IN_CHUNKS
static int test(const uint8_t *input, size_t input_len, const char output[], size_t num_chunks)
#else
static int test(const uint8_t *input, size_t input_len, const char output[])
#endif
{
	uint8_t hash[32];
	char hash_string[65];
	rrr_sha256_calculate(hash, input, input_len);
	hash_to_string(hash_string, hash);
	printf("input starts with 0x%02x, length %lu\n", *input, (unsigned long)input_len);
	printf("hash: %s\n", hash_string);
	if (strcmp(output, hash_string)) {
		printf("FAILURE!\n\n");
		return 1;
#if CALC_IN_CHUNKS
	} else {
		printf("SUCCESS!\n");
	}
	calc_sha_256_in_chunks(hash, input, input_len, num_chunks);
	hash_to_string(hash_string, hash);
	printf("hash in chunks: %s\n", hash_string);
	if (strcmp(output, hash_string)) {
		printf("FAILURE!\n\n");
		return 1;
#endif
	} else {
		printf("SUCCESS!\n\n");
		return 0;
	}
}

int main(void)
{
	size_t i;
	for (i = 0; i < (sizeof STRING_VECTORS / sizeof(struct string_vector)); i++) {
		const struct string_vector *vector = &STRING_VECTORS[i];
		if (string_test(vector->input, vector->output))
			return 1;
	}
	construct_binary_messages();
	for (i = 0; i < (sizeof vectors / sizeof(struct vector)); i++) {
		const struct vector *vector = &vectors[i];
#if CALC_IN_CHUNKS
		if (test(vector->input, vector->input_len, vector->output, 5)) {
#else
		if (test(vector->input, vector->input_len, vector->output)) {
#endif
			destruct_binary_messages();
			return 1;
		}
	}
	destruct_binary_messages();
#if CALC_IN_CHUNKS
	/* Test some silly corner cases. Only empty chunks and no chunk at all. */
	assert(strlen(STRING_VECTORS[0].input) == 0);
	if (test((const uint8_t *)STRING_VECTORS[0].input, strlen(STRING_VECTORS[0].input), STRING_VECTORS[0].output,
		 5))
		return 1;
	if (test((const uint8_t *)STRING_VECTORS[0].input, strlen(STRING_VECTORS[0].input), STRING_VECTORS[0].output,
		 0))
		return 1;
#endif
	return 0;
}
