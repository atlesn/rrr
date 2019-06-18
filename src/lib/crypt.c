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
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>

#include "../../config.h"
#include "vl_time.h"
#include "crypt.h"
#include "../global.h"

static int is_locked = 0;
static pthread_mutex_t openssl_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * This must only be called from main thread when NO OTHER threads are running.
 * It will reset the locking of OpenSSL in case we killed a thread which held
 * a lock.
 */
void vl_crypt_initialize_locks() {
	VL_DEBUG_MSG_4("Initialize crypt lock\n");
	pthread_mutex_init(&openssl_lock, NULL);
}

void vl_crypt_free_locks() {
	VL_DEBUG_MSG_4("Free crypt lock\n");
}

/*
 * Threads must this lock whenever using functions below which contain
 * VL_CRYPT_CHECK_LOCKED(). If the thread crashes, it
 * is not a big problem not to unlock, but we should use pthread cleanup stack
 * to minimize the delay when the other threads should exit so that we don't have
 * to kill them due to the lock not being available.
 */
int vl_crypt_global_lock() {
	VL_DEBUG_MSG_4("Lock crypt lock\n");
	if (pthread_mutex_lock(&openssl_lock) != 0) {
		return 1;
	}
	is_locked = 1;
	return 0;
}

void vl_crypt_global_unlock(void *arg) {
	VL_DEBUG_MSG_4("Unlock crypt lock\n");
	if (is_locked == 0) {
		VL_MSG_ERR("Bug: Crypt unlock was called without lock being held\n");
		exit(EXIT_FAILURE);
	}
	pthread_mutex_unlock(&openssl_lock);
	is_locked = 0;
}

/*
 * Crash if we forget to lock
 */
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

    dst[src_length * 2] = '\0';
}

int string_to_bin(const unsigned char *src, unsigned int src_length, unsigned char *dst, unsigned int dst_length) {
	if (dst_length < src_length / 2) {
    	VL_MSG_ERR("Bug: bin_to_string: Crypt string buffer too small (%u < %u)\n", dst_length, src_length / 2);
    	exit(EXIT_FAILURE);
	}

	unsigned long int step_size = sizeof(unsigned long int) * 2;
	unsigned char step[step_size+1];
	step[step_size] = '\0';

	unsigned int i = 0;
    for (i = 0; i < src_length; i += step_size) {
    	memcpy(step, src + i, step_size);
    	char *end;
    	unsigned long int tmp = strtoul(step, &end, 16);

    	if (*end != '\0') {
    		VL_MSG_ERR("crypt string_to_bin: Invalid charaters found in input stream, should be a-f0-9 only\n");
    		return 1;
    	}
    	VL_DEBUG_MSG_4 ("Writing from source %u to dst %i\n", i, i / 2);

#if __WORDSIZE == 64
    	tmp = htobe64(tmp);
#else
    	tmp = htobe32(tmp);
#endif

    	memcpy (dst + i / 2, &tmp, sizeof(tmp));
    }

    unsigned int leftover = i - src_length;
    if (leftover < step_size) {
    	i -= leftover;
    }

    step_size = sizeof(unsigned char) * 2;
    step[step_size] = '\0';

    /* If input is not dividable by sizeof(unsigned long int), process byte by byte */
    for (; i < src_length; i += step_size) {
    	memcpy(step, src + i, step_size);
    	char *end;
    	unsigned long int tmp = strtoul(step, &end, 16);
    	if (*end != '\0') {
    		VL_MSG_ERR("crypt string_to_bin: Invalid charaters found in input stream, should be a-f0-9 only\n");
    		return 1;
    	}
    	unsigned char tmp_c = (tmp & 0xff);
    	VL_DEBUG_MSG_4 ("Writing from source %u to dst %i\n", i, i / 2);
    	memcpy(dst + i / 2, &tmp_c, sizeof(tmp_c));
    }

    return 0;
}

/*
 * The key generated is too big for AES 256, but we might want other crypt
 * functions in the future.
 */
int vl_crypt_load_key(struct vl_crypt *crypt, const unsigned char *filename) {
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
	VL_CRYPT_CHECK_LOCKED();

	if (RAND_bytes (crypt->iv_bin, sizeof(crypt->iv_bin)) != 1) {
		VL_MSG_ERR("Error while generating random bytes for IV. OpenSSL error message: \n\t");
		ERR_print_errors_fp(stderr);
		return 1;
	}

    if (sizeof (crypt->iv_bin) < SHA256_DIGEST_LENGTH) {
    	VL_MSG_ERR("Bug: Crypt IV key binary buffer too small\n");
    	exit(EXIT_FAILURE);
    }

    bin_to_string(crypt->iv_bin, sizeof(crypt->iv_bin), crypt->iv, sizeof(crypt->iv));

	return 0;
}

int vl_crypt_set_iv_from_hex(struct vl_crypt *crypt, const unsigned char *iv_string) {
	if (sizeof(crypt->iv_bin) < strlen(iv_string) / 2) {
		VL_MSG_ERR("IV string was too long\n");
		return 1;
	}

    VL_DEBUG_MSG_3("IV converting string to bin: %s\n", iv_string);

	if (string_to_bin(iv_string, strlen(iv_string), crypt->iv_bin, sizeof(crypt->iv_bin)) != 0) {
		VL_MSG_ERR("Could not convert IV hex string to binary\n");
		return 1;
	}

    bin_to_string(crypt->iv_bin, sizeof(crypt->iv_bin), crypt->iv, sizeof(crypt->iv));

    VL_DEBUG_MSG_3("IV after converting bin->string: %s\n", crypt->iv);

	return 0;
}

int vl_decrypt_aes256 (struct vl_crypt *crypt,
		const void *source, unsigned int source_length,
		void **target, unsigned int *target_length
) {
	VL_CRYPT_CHECK_LOCKED();

	if (crypt->ctx != NULL) {
		  EVP_CIPHER_CTX_free(crypt->ctx);
	}

	if (!(crypt->ctx = EVP_CIPHER_CTX_new())) {
		goto error;
	}

	if (EVP_DecryptInit_ex(crypt->ctx, EVP_aes_256_cbc(), NULL, crypt->key_bin, crypt->iv_bin) != 1)  {
		goto error_free;
	}

	void *tmp = malloc(source_length / 2 + 1);
	void *ret = malloc(source_length * 2);
	int len = 0;
	int total_length = 0;

	if (string_to_bin(source, source_length, tmp, source_length / 2 + 1) != 0) {
		VL_MSG_ERR("crypt: Error while converting string to binary data\n");
		goto error_free_target;
	}

	if (EVP_DecryptUpdate(crypt->ctx, ret, &len, tmp, source_length / 2) != 1) {
		goto error_free_target;
	}
	total_length += len;

	if(EVP_DecryptFinal_ex(crypt->ctx, ret + len, &len) != 1) {
		goto error_free_target;
	}
	total_length += len;

	success:
		*target_length = total_length;
		*target = ret;
		free(tmp);
		EVP_CIPHER_CTX_free(crypt->ctx);
		crypt->ctx = NULL;
		return 0;

	error_free_target:
		free(ret);
		free(tmp);

	error_free:
		EVP_CIPHER_CTX_free(crypt->ctx);
		crypt->ctx = NULL;

	error:
		VL_MSG_ERR("OpenSSL error message: \n\t");
		ERR_print_errors_fp(stderr);

	return 1;
}

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

	VL_DEBUG_MSG_3("Crypt using IV: %s\n", crypt->iv);
	VL_DEBUG_MSG_3("Crypt using key: %s\n", crypt->key);
	VL_DEBUG_MSG_3("Crypt source length is: %u\n", source_length);

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
		crypt->ctx = NULL;
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
