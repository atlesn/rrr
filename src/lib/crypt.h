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
#include <openssl/sha.h>

#include "../global.h"

struct vl_crypt {
	EVP_PKEY *evp_key;
	unsigned char key_bin[SHA512_DIGEST_LENGTH];
	unsigned char key[SHA512_DIGEST_LENGTH * 2 + 1];
	unsigned char iv_bin[SHA256_DIGEST_LENGTH];
	unsigned char iv[SHA256_DIGEST_LENGTH * 2 + 1];
	EVP_CIPHER_CTX *ctx;
	int random_seed;
};

void vl_crypt_global_lock();
void vl_crypt_global_unlock(void *ret);
struct vl_crypt *vl_crypt_new();
void vl_crypt_free(struct vl_crypt *crypt);
int vl_crypt_load_key(struct vl_crypt *crypt, const char *filename);
int vl_crypt_aes256 (
		struct vl_crypt *crypt,
		const void *source, unsigned int source_length,
		void **target, unsigned int *target_length
);
