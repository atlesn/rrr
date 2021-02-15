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

#ifndef RRR_OPENSSL_H
#define RRR_OPENSSL_H

#include <openssl/ssl.h>

#define RRR_SSL_ERR(msg)								\
	do {												\
		char buf[256];									\
		ERR_error_string_n(ERR_get_error(), buf, 256); 	\
		RRR_MSG_0(msg ": %s\n", buf);					\
	} while(0)

#define RRR_SSL_DBG_3(msg)								\
	do { if (RRR_DEBUGLEVEL_3) { 						\
		char buf[256];									\
		ERR_error_string_n(ERR_get_error(), buf, 256); 	\
		RRR_MSG_3(msg ": %s\n", buf);					\
	}} while(0)


void rrr_openssl_global_register_user(void);
void rrr_openssl_global_unregister_user(void);
int rrr_openssl_load_verify_locations (SSL_CTX *ctx, const char *ca_file, const char *ca_path);

#endif /* RRR_OPENSSL_H */
