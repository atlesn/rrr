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

#include <pthread.h>
#include <string.h>

#include "module_crypt.h"
#include "crypt.h"
#include "../global.h"

/*
 * Initialize crypt structure of a thread with the symmetric key read from crypt_file.
 * The file can contain any (random) data but must be >= 512 bytes long.
 */
int module_crypt_data_init(struct module_crypt_data *crypt_data, const char *file) {
	int ret = 0;

	if (vl_crypt_global_lock() != 0) {
		VL_MSG_ERR("Could not obtain OpenSSL lock\n");
		return 1;
	}
	pthread_cleanup_push(vl_crypt_global_unlock, NULL);

	crypt_data->crypt = vl_crypt_new();

	if (crypt_data->crypt == NULL) {
		VL_MSG_ERR("Could not allocate module crypt data\n");
		goto out;
	}

	VL_DEBUG_MSG_1("Loading crypt key from file %s\n", file);
	if (vl_crypt_load_key(crypt_data->crypt, file) != 0) {
		VL_MSG_ERR("Could not load crypt key from %s\n", file);
		vl_crypt_free(crypt_data->crypt);
		ret = 1;
	}

	out:
	pthread_cleanup_pop(1);
	return ret;
}

void module_crypt_data_cleanup(void *arg) {
	struct module_crypt_data *crypt_data = arg;
	if (crypt_data->crypt == NULL) {
		return;
	}

	int do_unlock = 1;
	if (vl_crypt_global_lock() != 0) {
		VL_MSG_ERR("Warning: Could not obtain OpenSSL lock while cleaning up crypt data\n");
		do_unlock = 0;
	}
	pthread_cleanup_push(vl_crypt_global_unlock, NULL);

	vl_crypt_free(crypt_data->crypt);

	crypt_data->crypt = NULL;

	pthread_cleanup_pop(do_unlock);
}

int module_encrypt_message (
		struct module_crypt_data *crypt_data,
		char *buf, unsigned int buf_length, unsigned int buf_size
) {
	struct vl_crypt *crypt = crypt_data->crypt;

	int ret = 0;

	unsigned int cipher_length = 0;
	void *cipher_string = NULL;

	if (vl_crypt_global_lock() != 0) {
		VL_MSG_ERR("Could not obtain OpenSSL lock while encrypting message\n");
		return 1;
	}
	pthread_cleanup_push(vl_crypt_global_unlock, NULL);
	if (vl_crypt_aes256 (
			crypt,
			buf, buf_length,
			&cipher_string, &cipher_length
	) != 0) {
		VL_MSG_ERR("Error while encrypting message\n");
		ret = 1;
		goto crypt_out;
	}

	pthread_cleanup_push(free, cipher_string);

	VL_DEBUG_MSG_3("encrypting message using key %s\n\tIV %s\n", crypt->key, crypt->iv);

	const unsigned int message_total_length =
			cipher_length + 1 + strlen(crypt->iv) + 1;

	if (message_total_length + 1 > buf_size) {
		VL_MSG_ERR("Bug: Encrypted message was too big\n");
		exit(EXIT_FAILURE);
	}

	((char*) cipher_string)[cipher_length] = '\0';

	sprintf(buf, "%s:%s", crypt->iv, (char*) cipher_string);

	pthread_cleanup_pop(1);

	crypt_out:
	pthread_cleanup_pop(1);
	return ret;
}

int module_decrypt_message (
		struct module_crypt_data *crypt_data,
		char *buf, unsigned int *buf_length, unsigned int buf_size
) {
	struct vl_crypt *crypt = crypt_data->crypt;

	int ret = 0;

	unsigned int decrypted_string_length = 0;
	void *decrypted_string = NULL;

	if (vl_crypt_global_lock() != 0) {
		VL_MSG_ERR("Could not obtain OpenSSL lock while decrypting message\n");
		return 1;
	}
	pthread_cleanup_push(vl_crypt_global_unlock, NULL);

	char *colon = memchr(buf, ':', *buf_length);
	if (*colon != ':') {
		VL_MSG_ERR("Could not find IV delimeter : in message for decryption");
		ret = 1;
		goto crypt_out;
	}

	*colon = '\0';
	const char *iv_string = buf;
	const char *ciphertext_string = colon + 1;

	unsigned int iv_length = strlen(iv_string);
	unsigned int cipher_length = *buf_length - iv_length - 1;

	if (iv_length + 1 + sizeof(unsigned int) >= *buf_length) {
		VL_MSG_ERR("Ciphertext of message was too short for decryption\n");
		ret = 1;
		goto crypt_out;
	}

	if (vl_crypt_set_iv_from_hex(crypt, iv_string) != 0) {
		VL_MSG_ERR("Unable to set IV for decryption\n");
		ret = 1;
		goto crypt_out;
	}

	VL_DEBUG_MSG_3("decrypting\n\t- message %s\n\t- using key %s\n\t- IV %s\n", ciphertext_string, crypt->key, crypt->iv);

	if (vl_decrypt_aes256 (
			crypt,
			ciphertext_string, cipher_length,
			&decrypted_string, &decrypted_string_length
	) != 0) {
		VL_MSG_ERR("Error while decrypting message\n");
		ret = 1;
		goto crypt_out;
	}

	pthread_cleanup_push(free, decrypted_string);

	VL_DEBUG_MSG_3("decrypting message using key %s IV %s\n", crypt->key, crypt->iv);

	if (decrypted_string_length + 1 > buf_size) {
		VL_MSG_ERR("Could not fit decrypted message in buffer (possible bug)\n");
		ret = 1;
		goto crypt_out_2;
	}

	memcpy(buf, decrypted_string, decrypted_string_length);
	buf[decrypted_string_length] = '\0';

	VL_DEBUG_MSG_3("Decrypted message: %s\n", buf);

	*buf_length = decrypted_string_length;

	crypt_out_2:
		pthread_cleanup_pop(1);
	crypt_out:
		pthread_cleanup_pop(1);
		return ret;
}
