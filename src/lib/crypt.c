/*

Voltage Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>

#include "vl_time.h"
#include "crypt.h"
#include "../global.h"

static volatile int is_locked = 0;

/* No functions may be used without this being called first */
void vl_crypt_global_lock() {
	CRYPTO_w_lock(CRYPTO_LOCK_DYNLOCK);
	is_locked = 1;
}

/* This should be added to pthread cleanup stack */
void vl_crypt_global_unlock(void *ret) {
	is_locked = 0;
	CRYPTO_w_unlock(CRYPTO_LOCK_DYNLOCK);
}

#define VL_CRYPT_CHECK_LOCKED() \
	do {if (is_locked != 1) { VL_MSG_ERR("Bug: Crypto functions were not locked\n"); exit (EXIT_FAILURE); }}while(0)

struct vl_crypt *vl_crypt_new() {
	VL_CRYPT_CHECK_LOCKED();

	struct vl_crypt *ret = malloc(sizeof(*ret));
	memset (ret, '\0', sizeof(*ret));

	if ((ret->evp_key = EVP_PKEY_new()) == NULL) {
		free(ret);
		return NULL;
	}

	uint64_t time = time_get_64();
	ret->random_seed = time & 0xffffffff;
	if (sizeof(ret->random_seed) == 8) {
		ret->random_seed = time & 0xffffffffffffffff;
	}

	return ret;
}

void vl_crypt_free(struct vl_crypt *crypt) {
	VL_CRYPT_CHECK_LOCKED();

	if (crypt->ctx != NULL) {
		  EVP_CIPHER_CTX_free(crypt->ctx);
	}

	EVP_PKEY_free(crypt->evp_key);
	free(crypt);
}

const char characters[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

void bin_to_string(const unsigned char *src, unsigned int src_length, unsigned char *dst, unsigned int dst_length) {
	if (dst_length < src_length * 2 + 1) {
    	VL_MSG_ERR("Bug: bin_to_string: Crypt string buffer too small\n");
    	exit(EXIT_FAILURE);
	}

    for (int i = 0; i < src_length; i++) {
    	sprintf(dst + i * 2, "%02x", src[i]);
    }

    dst[dst_length-1] = '\0';
}

int vl_crypt_load_key(struct vl_crypt *crypt, const char *filename) {
	VL_CRYPT_CHECK_LOCKED();

	int err = 0;
	FILE *file = fopen(filename, "r");

	VL_DEBUG_MSG_1("Loading symmetric key from file %s\n", filename);
	if (file == NULL) {
		VL_MSG_ERR("crypt: Could not open key file %s: %s\n", filename, strerror(errno));
		err = 1;
		goto out;
	}

	SHA512_CTX ctx;
	SHA512_Init(&ctx);

	int total_bytes = 0;
	int bytes;
	unsigned char buf[SHA512_DIGEST_LENGTH];
	do {
		bytes = fread(buf, 1, sizeof(buf), file);

		if (bytes < sizeof(buf)) {
			 break;
		}

		total_bytes += bytes;
		SHA512_Update(&ctx, buf, sizeof(buf));
	} while (1);

	if (total_bytes < sizeof(buf)) {
		if ((err = ferror(file)) != 0) {
			VL_MSG_ERR("Error while reading crypt file %s: %s", filename, strerror(err));
			err = 1;
			goto out_close;
		}
		else {
			VL_MSG_ERR("Not enough bytes in crypt file %s, need %lu bytes\n", filename, sizeof(crypt->key));
			err = 1;
			goto out_close;
		}
	}

    if (sizeof (crypt->key_bin) < SHA512_DIGEST_LENGTH) {
    	VL_MSG_ERR("Bug: Crypt key binary buffer too small\n");
    	exit(EXIT_FAILURE);
    }

    SHA512_Final(crypt->key_bin, &ctx);

    bin_to_string(crypt->key_bin, sizeof(crypt->key_bin), crypt->key, sizeof(crypt->key));

	VL_DEBUG_MSG_1("Crypt SHA512-ed %i bytes to generate the key\n", total_bytes);

	crypt->key[sizeof(crypt->key)-1] = '\0';

	VL_DEBUG_MSG_1("Crypt using key: %s\n", (unsigned char*) crypt->key);

	out_close:
	fclose (file);

	out:
	return err;
}

int vl_crypt_generate_iv(struct vl_crypt *crypt) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);

	for (int i = 0; i < sizeof(crypt->iv_bin); i++) {
		int buf = rand_r(&crypt->random_seed);
		SHA256_Update(&ctx, &buf, sizeof(buf));
	}

    if (sizeof (crypt->iv_bin) < SHA256_DIGEST_LENGTH) {
    	VL_MSG_ERR("Bug: Crypt IV key binary buffer too small\n");
    	exit(EXIT_FAILURE);
    }

    SHA256_Final(crypt->iv_bin, &ctx);

    bin_to_string(crypt->iv_bin, sizeof(crypt->iv_bin), crypt->iv, sizeof(crypt->iv));

	return 0;
}

// TODO : This may possible leak if we pthread_cancel in the middle
int vl_crypt_aes256 (
		struct vl_crypt *crypt,
		const void *source, unsigned int source_length,
		void **target, unsigned int *target_length
) {
	VL_CRYPT_CHECK_LOCKED();

	if (crypt->key[0] == 0) {
		VL_MSG_ERR("Bug: vl_crypt_aes256 called with no key being loaded first\n");
		exit (EXIT_FAILURE);
	}

	*target = NULL;
	*target_length = 0;

	if (vl_crypt_generate_iv(crypt) != 0) {
		VL_MSG_ERR("Error when generating random initialization vector\n");
		goto out;
	}

	VL_DEBUG_MSG_2("Crypt using IV: %s\n", crypt->iv);
	VL_DEBUG_MSG_2("Crypt using key: %s\n", crypt->key);
	VL_DEBUG_MSG_2("Crypt source length is: %u\n", source_length);

	if (crypt->ctx != NULL) {
		  EVP_CIPHER_CTX_free(crypt->ctx);
	}

	if (!(crypt->ctx = EVP_CIPHER_CTX_new())) goto error;

	if (EVP_EncryptInit_ex(crypt->ctx, EVP_aes_256_cbc(), NULL, crypt->key_bin, crypt->iv_bin) != 1)  {
		goto error_free;
	}

	unsigned int length = 0;
	unsigned int total_length = 0;

	unsigned const int tmp_size = source_length * 2;
	unsigned const int ret_size = tmp_size * 2 + 1;

	void *ret = malloc(ret_size);
	void *tmp = malloc(tmp_size);

	if (EVP_EncryptUpdate(crypt->ctx, tmp, &length, source, source_length) != 1) {
		goto error_free_target;
	}
	total_length += length;

	VL_DEBUG_MSG_3("crypt length after first update: %u\n", total_length);

	if (EVP_EncryptFinal_ex(crypt->ctx, tmp + total_length, &length) != 1) {
		goto error_free_target;
	}
	total_length += length;

	VL_DEBUG_MSG_3("crypt length after final update: %u\n", total_length);

	bin_to_string(tmp, total_length, ret, total_length * 2 + 1);

	success:
		*target = ret;
		*target_length = strlen(ret);
		free(tmp);
		EVP_CIPHER_CTX_free(crypt->ctx);
		crypt->ctx = 0;
		return 0;

	error_free_target:
		free(tmp);
		free(ret);

	error_free:
		EVP_CIPHER_CTX_free(crypt->ctx);
		crypt->ctx = 0;

	error:
		VL_MSG_ERR("OpenSSL error message: \n\t");
		ERR_print_errors_fp(stderr);

	out:
		return 1;
}
