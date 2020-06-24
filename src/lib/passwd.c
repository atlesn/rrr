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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <termios.h>

#ifdef RRR_WITH_OPENSSL
#	include <openssl/evp.h>
#	include <openssl/err.h>
#	include <openssl/rand.h>
#endif

#include "../global.h"
#include "parse.h"
#include "log.h"
#include "passwd.h"
#include "base64.h"
#include "rrr_socket.h"
#include "rrr_strerror.h"

#define RRR_PASSWD_HASH_MAX_LENGTH 512
#define RRR_PASSWD_HASH_KEY_LENGTH (RRR_PASSWD_HASH_MAX_LENGTH/2)
#define RRR_PASSWD_SALT_BYTES 32
#define RRR_PASSWD_HASH_ITERATIONS 20000

#define RRR_PASSWD_ENCTYPE_BASE64	'0'
#define RRR_PASSWD_ENCTYPE_OPENSSL	'1'

static void __rrr_passwd_permission_destroy (
		struct rrr_passwd_permission *permission
) {
	RRR_FREE_IF_NOT_NULL(permission->permission);
	free(permission);
}

void rrr_passwd_permission_collection_clear (
		struct rrr_passwd_permission_collection *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_passwd_permission, __rrr_passwd_permission_destroy(node));
}

static int __rrr_passwd_permission_new (
		struct rrr_passwd_permission **target,
		const char *permission_str
) {
	int ret = 0;

	*target = NULL;

	struct rrr_passwd_permission *permission = malloc(sizeof(*permission));

	if (permission == NULL) {
		RRR_MSG_0("Could not allocate memory for permission in __rrr_passwd_permission_new\n");
		ret = 1;
		goto out;
	}

	memset(permission, '\0', sizeof(*permission));

	if ((permission->permission = strdup(permission_str)) == NULL) {
		RRR_MSG_0("Could not allocate memory for permission string in  __rrr_passwd_permission_new\n");
		ret = 1;
		goto out_free;
	}

	*target = permission;
	permission = NULL;

	goto out;
	out_free:
		free(permission);
	out:
	return ret;
}

int rrr_passwd_permission_new_and_append (
		struct rrr_passwd_permission_collection *target,
		const char *permission_str
) {
	struct rrr_passwd_permission *permission = NULL;

	if (__rrr_passwd_permission_new(&permission, permission_str)) {
		return 1;
	}

	RRR_LL_APPEND(target, permission);

	return 0;
}

int rrr_passwd_permission_add_from_permissions (
		struct rrr_passwd_permission_collection *target,
		const struct rrr_passwd_permission_collection *source
) {
	RRR_LL_ITERATE_BEGIN(source, const struct rrr_passwd_permission);
		if (rrr_passwd_permission_new_and_append(target, node->permission) != 0) {
			return 1;
		}
	RRR_LL_ITERATE_END();
	return 0;
}

void rrr_passwd_permission_collection_remove_duplicates (
		struct rrr_passwd_permission_collection *target
) {
	RRR_LL_ITERATE_BEGIN(target, struct rrr_passwd_permission);
		struct rrr_passwd_permission *permission = node;

		int found_equal = 0;
		RRR_LL_ITERATE_BEGIN(target, struct rrr_passwd_permission);
			if (node != permission) {
				if (strcmp(permission->permission, node->permission) == 0) {
					found_equal = 1;
					RRR_LL_ITERATE_LAST();
				}
			}
		RRR_LL_ITERATE_END();

		if (found_equal) {
			RRR_LL_ITERATE_SET_DESTROY();
		}
	RRR_LL_ITERATE_END_CHECK_DESTROY(target, 0; __rrr_passwd_permission_destroy(node));
}

static int __rrr_passwd_check_base64 (
		const char *hash,
		const char *password
) {
	// Default is 1, not authenticated
	int ret = 1;

	size_t base64_tmp_length = 0;
	unsigned char *base64_tmp = NULL;

	if (strlen(password) > RRR_PASSWD_HASH_KEY_LENGTH) {
		RRR_MSG_0("Password too long in __rrr_passwd_check_base64, max length is %i\n", RRR_PASSWD_HASH_MAX_LENGTH / 2);
		goto out;
	}
	RRR_FREE_IF_NOT_NULL(base64_tmp);
	if ((base64_tmp = rrr_base64_encode((unsigned char *) password, strlen(password), &base64_tmp_length)) == NULL) {
		RRR_MSG_0("Base64 encoding failed for plaintext password in __rrr_passwd_check_base64\n");
		goto out;
	}

	if (memcmp(hash, base64_tmp, strlen(hash)) == 0) {
		ret = 0; // Authenticated
	}
	else {
		RRR_DBG_1("Authentication failed, password mismatch\n");
	}

	out:
	RRR_FREE_IF_NOT_NULL(base64_tmp);
	return ret;
}

#ifdef RRR_WITH_OPENSSL
static int __rrr_passwd_openssl_encrypt (
		unsigned char tmp[RRR_PASSWD_HASH_MAX_LENGTH + 1],
		const char *password_plain,
		const unsigned char *salt_base64
) {
	int ret = 0;

//	printf ("Password plain: %s\n", password_plain);
//	printf ("Salt base64: %s\n", salt_base64);

	if (strlen(password_plain) == 0) {
		RRR_BUG("BUG: Empty password to __rrr_passwd_openssl_encrypt\n");
	}
	if (strlen((const char *) salt_base64) == 0) {
		RRR_BUG("BUG: Empty salt to __rrr_passwd_openssl_encrypt\n");
	}

	size_t salt_bin_length = 0;
	unsigned char *salt_bin = rrr_base64_decode(salt_base64, strlen((const char *) salt_base64), &salt_bin_length);
	if (salt_bin == NULL) {
		RRR_MSG_0("base64 decode of salt failed in __rrr_passwd_openssl_encrypt\n");
		ret = 1;
		goto out;
	}

	if (salt_bin_length < RRR_PASSWD_SALT_BYTES) {
		RRR_BUG("BUG:Salt too short in __rrr_passwd_openssl_encrypt\n");
	}

	if (PKCS5_PBKDF2_HMAC (
			password_plain, strlen(password_plain),
			salt_bin, salt_bin_length,
			RRR_PASSWD_HASH_ITERATIONS,
			EVP_sha256(),
			RRR_PASSWD_HASH_KEY_LENGTH,
			tmp
	) != 1) {
		ERR_error_string_n(ERR_get_error(), (char *) tmp, RRR_PASSWD_HASH_MAX_LENGTH + 1);
		RRR_MSG_0("Could not encrypt password in rrr_passwd_encrypt: %s\n", tmp);
		ret = 1;
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(salt_bin);
	return ret;
}
#endif

static int __rrr_passwd_check_openssl (
		const char *salt,
		const char *hash,
		const char *password
) {
	// Default is 1, not authenticated
	int ret = 1;

#ifdef RRR_WITH_OPENSSL

	unsigned char tmp[RRR_PASSWD_HASH_MAX_LENGTH + 1];
	unsigned char *hash_raw = NULL;
	size_t hash_raw_length = 0;

	if ((hash_raw = rrr_base64_decode((unsigned char *) hash, strlen(hash), &hash_raw_length)) == NULL) {
		RRR_MSG_0("Hash decoding failed in __rrr_passwd_check_openssl\n");
		goto out;
	}

	if (__rrr_passwd_openssl_encrypt(tmp, password, (const unsigned char *) salt) != 0) {
		goto out;
	}

	if (memcmp(tmp, hash_raw, RRR_PASSWD_HASH_KEY_LENGTH) == 0) {
		ret = 0; // Authenticated
	}
	else {
		RRR_DBG_1("Authentication failed, password mismatch\n");
	}

	out:
	RRR_FREE_IF_NOT_NULL(hash_raw);

#else /* RRR_WITH_OPENSSL */

	(void)(salt);
	(void)(hash);
	(void)(password);

	RRR_MSG_0("OpenSSL enctype not supported for passwords, reset password for the user or re-compile RRR with OpenSSL enabled\n");
#endif /* RRR_WITH_OPENSSL */

	return ret;
}

struct passwd_check_callback_data {
	const char *password;
};

static int __rrr_passwd_check_callback (
		const char *elements[],
		size_t elements_count,
		void *arg
) {
	// Default is 1, not authenticated
	int ret = 1;

	struct passwd_check_callback_data *callback_data = arg;

	const char *password = callback_data->password;

	if (elements_count != 4) {
		RRR_MSG_0("Wrong number of $ in password hash\n");
		goto out;
	}

	if (*(elements[0]) != '\0') {
		RRR_MSG_0("Trash data '%s' before first $ in password hash\n", elements[0]);
		goto out;
	}

	const char *enctype = elements[1];
	const char *salt = elements[2];
	const char *hash = elements[3];

	// Empty hash not allowed (or user disabled)
	if (*hash == '\0') {
		RRR_MSG_0("Hash was empty, no password set for user.\n");
		goto out;
	}

	switch (*(enctype)) {
		case RRR_PASSWD_ENCTYPE_BASE64:
			if (*salt != '\0') {
				RRR_MSG_0("Error: Salt was not empty for base64 enctype\n");
				goto out;
			}
			return __rrr_passwd_check_base64(hash, password);
			break;
		case RRR_PASSWD_ENCTYPE_OPENSSL:
			if (*salt == '\0') {
				RRR_MSG_0("Error: Salt was empty for base64 enctype\n");
				goto out;
			}
			return __rrr_passwd_check_openssl(salt, hash, password);
			break;
		default:
			RRR_MSG_0("Enctype '%s' unknown for password\n", *enctype);
			break;
	};

	out:
	return ret;
}

int rrr_passwd_check (const char *hash, const char *password) {
	struct passwd_check_callback_data callback_data = { password };

	if (*password == '\0') {
		RRR_MSG_0("Authentication failure. Empty passwords not allowed.\n");
		return 1;
	}

	if (*hash == '\0') {
		RRR_MSG_0("Authentication failure. Hash was empty, user has no password.\n");
		return 1;
	}

	return rrr_parse_str_split(hash, '$', 4, __rrr_passwd_check_callback, &callback_data);
}

int rrr_passwd_encrypt (char **result, const char *password) {
	unsigned char *base64_tmp = NULL;
	size_t base64_tmp_length = 0;

	unsigned char tmp[RRR_PASSWD_HASH_MAX_LENGTH + 1];

	int ret = 0;

	*result = NULL;

	// Must be more than 256 to hold OpenSSL error strings
	char *final = malloc(RRR_PASSWD_HASH_MAX_LENGTH + 1);
	if (tmp == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_passwd_encrypt\n");
		ret = 1;
		goto out;
	}

	memset(final, '\0', RRR_PASSWD_HASH_MAX_LENGTH + 1);

#ifdef RRR_WITH_OPENSSL
	unsigned char salt[RRR_PASSWD_SALT_BYTES];
	if (RAND_bytes(salt, RRR_PASSWD_SALT_BYTES) != 1) {
		ERR_error_string_n(ERR_get_error(), (char *) tmp, RRR_PASSWD_HASH_MAX_LENGTH + 1);
		RRR_MSG_0("Could not generate salt in rrr_passwd_encrypt: %s\n", tmp);
		ret = 1;
		goto out;
	}

	if ((base64_tmp = rrr_base64_encode(salt, RRR_PASSWD_SALT_BYTES, &base64_tmp_length)) == NULL) {
		RRR_MSG_0("Base64 encoding failed for salt in rrr_passwd_encrypt\n");
		ret = 1;
		goto out;
	}

	sprintf(final, "$%c$%s$", RRR_PASSWD_ENCTYPE_OPENSSL, base64_tmp);

	if (__rrr_passwd_openssl_encrypt(tmp, password, (const unsigned char *) base64_tmp) != 0) {
		goto out;
	}

	RRR_FREE_IF_NOT_NULL(base64_tmp);
	if ((base64_tmp = rrr_base64_encode(tmp, RRR_PASSWD_HASH_KEY_LENGTH, &base64_tmp_length)) == NULL) {
		RRR_MSG_0("Base64 encoding failed for hash in rrr_passwd_encrypt\n");
		ret = 1;
		goto out;
	}

	char *hash_pos = final + strlen(final);
	sprintf(hash_pos, "%s", base64_tmp);

#else /* RRR_WITH_OPENSSL */
	if (strlen(password) > RRR_PASSWD_HASH_KEY_LENGTH) {
		RRR_MSG_0("Password too long for plaintext store in rrr_passwd_encrypt, max length is %i\n", RRR_PASSWD_HASH_MAX_LENGTH / 2);
		ret = 1;
		goto out;
	}
	RRR_FREE_IF_NOT_NULL(base64_tmp);
	if ((base64_tmp = rrr_base64_encode((unsigned char *) password, strlen(password), &base64_tmp_length)) == NULL) {
		RRR_MSG_0("Base64 encoding failed for plaintext password in rrr_passwd_encrypt\n");
		ret = 1;
		goto out;
	}
	sprintf(final, "$%c$$%s", RRR_PASSWD_ENCTYPE_BASE64, base64_tmp);
#endif /* RRR_WITH_OPENSSL */

//	printf("Encrpyted password: %s\n", final);

	*result = final;
	final = NULL;

	out:
	RRR_FREE_IF_NOT_NULL(base64_tmp);
	RRR_FREE_IF_NOT_NULL(final);
	return ret;
}

struct rrr_passwd_iterate_lines_split_callback_data {
	const char *line;
	int (*line_callback) (
			const char *line,
			const char *username,
			const char *hash_tmp,
			const char *permissions[],
			size_t permissions_count,
			void *arg
	);
	void *line_callback_arg;

	// Set by first callback
	const char *username;
	const char *permissions;
	const char *hash;
};

static int __rrr_passwd_iterate_lines_split_permissions_callback (
		const char *elements[],
		size_t elements_count,
		void *arg
) {
	struct rrr_passwd_iterate_lines_split_callback_data *callback_data = arg;

	return callback_data->line_callback(
			callback_data->line,
			callback_data->username,
			callback_data->hash,
			elements,
			elements_count,
			callback_data->line_callback_arg
	);
}

static int __rrr_passwd_iterate_lines_split_columns_callback (
		const char *elements[],
		size_t elements_count,
		void *arg
) {
	struct rrr_passwd_iterate_lines_split_callback_data *callback_data = arg;

	if (elements_count != 3) {
		RRR_MSG_0("%u elements found in password file, 3 expected.\n", elements_count);
		return RRR_PASSWD_ITERATE_ERR;
	}

	callback_data->username = elements[0];
	callback_data->permissions = elements[1];
	callback_data->hash = elements[2];

	return rrr_parse_str_split (
			callback_data->permissions,
			',',
			32,
			__rrr_passwd_iterate_lines_split_permissions_callback,
			arg
	);
}

int rrr_passwd_iterate_lines (
		const char *input_data,
		ssize_t input_data_size,
		int (*line_callback) (
				const char *line,
				const char *username,
				const char *hash_tmp,
				const char *permissions[],
				size_t permissions_count,
				void *arg
		),
		void *line_callback_arg
) {
	int ret = 0;

	char *line_tmp = NULL;

	struct rrr_parse_pos parse_pos;

	rrr_parse_pos_init(&parse_pos, input_data, input_data_size);

	struct rrr_passwd_iterate_lines_split_callback_data callback_data = {
			NULL,
			line_callback,
			line_callback_arg,
			NULL,
			NULL,
			NULL
	};

	while (!rrr_parse_check_eof(&parse_pos)) {
		int line_start = 0;
		int line_end = 0;

		rrr_parse_ignore_spaces_and_increment_line(&parse_pos);
		rrr_parse_non_newline (&parse_pos, &line_start, &line_end);

		if (line_end < line_start) {
			// Empty line
			continue;
		}

		RRR_FREE_IF_NOT_NULL(line_tmp);
		if (rrr_parse_extract_string(&line_tmp, &parse_pos, line_start, (line_end - line_start) + 1) != 0) {
			RRR_MSG_0("Could not allocate memory for line in process()\n");
			ret = 1;
			goto out;
		}

		callback_data.line = line_tmp;

		if ((ret = rrr_parse_str_split (
				line_tmp,
				':',
				3,
				__rrr_passwd_iterate_lines_split_columns_callback,
				&callback_data
		)) != 0) {
			if (ret != RRR_PASSWD_ITERATE_STOP) {
				RRR_MSG_0("Password file processing failed at line %i\n", parse_pos.line);
				ret = 1;
			}
			else {
				ret = 0;
			}
			goto out;
		}
	}

	out:
	RRR_FREE_IF_NOT_NULL(line_tmp);
	return ret;
}

struct rrr_passwd_authenticate_callback_data {
		const char *username;
		const char *password;
		const char *permission;
		int user_ok;
		int pass_ok;
		int permission_ok;
};

static int __rrr_passwd_authenticate_callback (
		const char *line,
		const char *username,
		const char *hash_tmp,
		const char *permissions[],
		size_t permissions_count,
		void *arg
) {
	struct rrr_passwd_authenticate_callback_data *callback_data = arg;

	(void)(line);

	int ret = RRR_PASSWD_ITERATE_OK;

	// Make sure these are 0. Callers MUST use these to figure out whether an
	// authentication request was successful or not.
	callback_data->user_ok = 0;
	callback_data->pass_ok = 0;
	callback_data->permission_ok = 0;

	if (strcmp(username, callback_data->username) != 0) {
		// Check next user
		ret = RRR_PASSWD_ITERATE_OK;
		goto out;
	}

	callback_data->user_ok = 1;

	if (rrr_passwd_check(hash_tmp, callback_data->password) != 0) {
		// Password mismatch
		ret = RRR_PASSWD_ITERATE_STOP;
		goto out;
	}

	callback_data->pass_ok = 1;

	if (callback_data->permission != NULL) {
		int ret_tmp = 1;
		for (size_t i = 0; i < permissions_count; i++) {
			if (strcmp(permissions[i], callback_data->permission) == 0) {
				ret_tmp = 0;
				break;
			}
		}
		if (ret_tmp == 0) {
			callback_data->permission_ok = 1;
		}
	}

	// We must return this to stop checking more users (the other users will fail)
	ret = RRR_PASSWD_ITERATE_STOP;
	goto out;

	out:
	return ret;
}

// TODO : Move to separate daemon

int rrr_passwd_authenticate (
		const char *filename,
		const char *username,
		const char *password,
		const char *permission_name
) {
	int ret = 0;

	ssize_t passwd_file_size = 0;
	char *passwd_file_contents = NULL;

	if (filename == NULL || *filename == '\0') {
		RRR_BUG("BUG: No filename in rrr_passwd_authenticate\n");
	}

	if (username == NULL || *username == '\0' || password == NULL || *password == '\0') {
		RRR_DBG_1("Username and/or password was not given in rrr_passwd_authenticate\n",
				username);
		ret = 1;
		goto out;
	}

	if (rrr_socket_open_and_read_file(&passwd_file_contents, &passwd_file_size, filename, O_RDONLY, 0) != 0) {
		ret = 1;
		goto out;
	}

	struct rrr_passwd_authenticate_callback_data callback_data = {
			username,
			password,
			permission_name,
			0,
			0,
			0
	};

	if ((ret = rrr_passwd_iterate_lines (
			passwd_file_contents,
			passwd_file_size,
			__rrr_passwd_authenticate_callback,
			&callback_data
	)) != 0) {
		RRR_MSG_0("Error encountered while authenticating user '%s' in rrr_passwd_authenticate using file '%s'\n",
				username, filename);
		ret = 1;
		goto out;
	}

	if (callback_data.user_ok != 1) {
		RRR_DBG_1("User '%s' not found while authenticating\n",
				username);
		// Hash a password once to stop timing attacks probing for usernames
		if (rrr_passwd_check (
				"$1$nppTQ1zkV5w1Xdfv/C2LNgQATi9waSLB3kFmZUyRnLU=$1J8AidhY+frcJq/TF7y5wpk0PXzLaO/rq1vq87DZPfitUcUjVLrBrLbXqwvcU5rZCEYRa9ECP0fQJWHoKeOtUsvDN+H/5xQKbId9NOiYoWJuBLimgSqNVT2m7qDex5/h/qwgaVPHYNlWEiAR4AMTVnwZzKSQRkqmlsAxMliwM68KJk1HmNhTWKttg+JYWaIwt87XlV9aMfMZMWBeTomIQS5XSKpRyfZrZlmIHxKt7de0pMi0f613mzykb63m1m59/SCLR14WDR4YB2QqulT/WGFsL9NIfZdiuZNakuROm+WkRaURKE2DapXCXDky2PgB4l9h65Ku6ZIfQ1/o76JHaA==",
				"rrr"
		) != 0) {
			RRR_MSG_0("Warning: Dummy password check failed in rrr_passwd_authenticate\n");
		}
		ret = 1;
		goto out;
	}
	else if (callback_data.pass_ok != 1) {
		RRR_DBG_1("Password mismatch for user '%s' while authenticating\n",
				username);
		ret = 1;
		goto out;
	}
	else if (callback_data.permission_ok != 1) {
		if (permission_name != NULL) {
			RRR_DBG_1("Permission request for '%s' failed for user '%s' while authenticating\n",
					permission_name, username);
			ret = 1;
			goto out;
		}
	}
	else if (!(callback_data.user_ok && callback_data.pass_ok && callback_data.permission_ok)) {
		RRR_MSG_0("Unknown authentication error in rrr_passwd_authenticate\n");
		ret = 1;
		goto out;
	}

	out:
	// Don't let hashes hang around in memory
	if (passwd_file_contents != NULL) {
		memset(passwd_file_contents, '\0', passwd_file_size);
	}
	RRR_FREE_IF_NOT_NULL(passwd_file_contents);
	return ret;
}

static int __rrr_passwd_read_password_from_terminal_prompt (
		char buf[RRR_PASSWD_MAX_INPUT_LENGTH],
		const char *msg
) {
	size_t password_length = 0;

	password_length = 0;
	buf[0] = '\0';
	printf ("%s", msg);

	while (1) {
		unsigned char c = fgetc(stdin);
		if (password_length + 1 >= RRR_PASSWD_MAX_INPUT_LENGTH) {
			printf("\n");
			RRR_MSG_0("Password was too long, max is %i characters\n", RRR_PASSWD_MAX_INPUT_LENGTH - 1);
			return 1;
		}

		if (c == '\n' || c == '\r') {
			break;
		}

		buf[password_length] = c;
		buf[password_length + 1] = '\0';

		password_length++;
	}

	printf("\n");

	return 0;
}

int rrr_passwd_read_password_from_terminal (
		char **result,
		int do_confirm
) {
	int ret = 0;

	struct termios t;
	struct termios t_orig;

	char buf[RRR_PASSWD_MAX_INPUT_LENGTH];
	char buf_control[RRR_PASSWD_MAX_INPUT_LENGTH];

	*buf = '\0';
	*buf_control = '\0';

	*result = NULL;

	if (tcgetattr(STDIN_FILENO, &t_orig) != 0) {
		RRR_MSG_0("Could not get terminal properties in read_password_stdin: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out_no_restore;
	}

	t = t_orig;
	t.c_lflag &= ~(ECHO);
	if (tcsetattr(STDIN_FILENO, TCSANOW, &t) != 0) {
		RRR_MSG_0("Could not set terminal properties in read_password_stdin: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out_no_restore;
	}

	retry:
	if (__rrr_passwd_read_password_from_terminal_prompt(buf, "Password: ")) {
		ret = 1;
		goto out;
	}

	if (do_confirm) {
		if (__rrr_passwd_read_password_from_terminal_prompt(buf_control, "Password (again): ")) {
			ret = 1;
			goto out;
		}

		if (strcmp(buf, buf_control) != 0) {
			printf("Password mismatch, try again\n");
			goto retry;
		}
	}

	*result = strdup(buf);
	if (*result == NULL) {
		RRR_MSG_0("Could not allocate memory in read_password_stdin\n");
		ret = 1;
		goto out;
	}

	out:
		tcsetattr(STDIN_FILENO, TCSANOW, &t_orig);
	out_no_restore:
		return ret;
}

int rrr_passwd_read_password_from_stdin (
		char **result
) {
	int ret = 0;

	*result = NULL;

	char buf[RRR_PASSWD_MAX_INPUT_LENGTH];

	ssize_t bytes = read(STDIN_FILENO, buf, RRR_PASSWD_MAX_INPUT_LENGTH - 1);

	if (bytes < 0) {
		RRR_MSG_0("Could not read password from stdin: %s\n", rrr_strerror(errno));
		ret = 1;
		goto out;
	}
	if (bytes == 0) {
		RRR_MSG_0("Password was empty while reading from standard input\n");
		ret = 1;
		goto out;
	}
	if (bytes >= RRR_PASSWD_MAX_INPUT_LENGTH - 1) {
		RRR_MSG_0("Password was too long while reading from standard input\n");
		ret = 1;
		goto out;
	}

	buf[bytes] = '\0';

	*result = strdup(buf);
	if (*result == NULL) {
		RRR_MSG_0("Could not allocate memory in rrr_passwd_read_password_from_stdin\n");
		ret = 1;
		goto out;
	}

	out:
	return ret;
}
