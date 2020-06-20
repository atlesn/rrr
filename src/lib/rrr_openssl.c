/*

Read Route Record

Copyright (C) 2020 Atle Solbakken atle@goliathdns.no

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
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#define RRR_OPENSSL_DEFAULT_CA_PATH "/etc/ssl/:/etc/ssl/certs/"

#include "log.h"
#include "rrr_openssl.h"

pthread_mutex_t rrr_openssl_global_lock = PTHREAD_MUTEX_INITIALIZER;
volatile int rrr_openssl_global_usercount = 0;

void rrr_openssl_global_register_user(void) {
	pthread_mutex_lock(&rrr_openssl_global_lock);
	if ((++rrr_openssl_global_usercount) == 1) {
		// Apparently this is not required with version >= 1.1
		// OPENSSL_init_ssl(0, NULL);
		// OPENSSL_config(NULL);
		RRR_DBG_1("OpenSSL initialized\n");
	}
	pthread_mutex_unlock(&rrr_openssl_global_lock);
}

void rrr_openssl_global_unregister_user(void) {
	pthread_mutex_lock(&rrr_openssl_global_lock);
	if ((--rrr_openssl_global_usercount) == 0) {
		(void)FIPS_mode_set(0);
		CONF_modules_unload(1);

		// Deprecated stuff in version >= 1.1.0
		// ENGINE_cleanup();
		// EVP_cleanup();
		// CRYPTO_cleanup_all_ex_data();
		// ERR_remove_state(); Deprectaded in version >= 1.0
		// ERR_remove_thread_state();
		// ERR_free_strings();
		RRR_DBG_1("OpenSSL cleaned up after last user finished\n");
	}
	if (rrr_openssl_global_usercount < 0) {
		RRR_BUG("Usercount below zero in rrr_openssl_global_unregister_user\n");
	}
	pthread_mutex_unlock(&rrr_openssl_global_lock);
}

int rrr_openssl_load_verify_locations (SSL_CTX *ctx, const char *ca_path) {
	int ret = 0;

	const char *ca_path_use = (ca_path != NULL ? ca_path : RRR_OPENSSL_DEFAULT_CA_PATH);

	RRR_DBG_1("Using path '%s' for CA certificates in OpenSSL\n", ca_path_use);

	// TODO : Add user-configurable cerfificates and paths
	if (SSL_CTX_load_verify_locations(ctx, NULL, ca_path_use) != 1) {
		RRR_SSL_ERR("Could not set certificate verification path\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

