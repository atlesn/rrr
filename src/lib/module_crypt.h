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

#ifndef VL_MODULE_CRYPT_H
#define VL_MODULE_CRYPT_H

#include "crypt.h"

struct module_crypt_data {
	const char *crypt_file;
	struct vl_crypt *crypt;
};

int module_crypt_data_init(struct module_crypt_data *crypt_data, const char *file);
void module_crypt_data_cleanup(void *arg);
int module_encrypt_message (
		struct module_crypt_data *crypt_data,
		char *buf, unsigned int buf_length, unsigned int buf_size
);
int module_decrypt_message (
		struct module_crypt_data *crypt_data,
		char *buf, unsigned int *buf_length, unsigned int buf_size
);

#endif
