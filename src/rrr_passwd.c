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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "global.h"
#include "main.h"
#include "../build_timestamp.h"
#include "lib/rrr_strerror.h"
#include "lib/version.h"
#include "lib/socket/rrr_socket.h"
#include "lib/linked_list.h"
#include "lib/log.h"
#include "lib/gnu.h"
#include "lib/parse.h"
#include "lib/passwd.h"

RRR_GLOBAL_SET_LOG_PREFIX("rrr_passwd");

static const struct cmd_arg_rule cmd_rules[] = {
		{CMD_ARG_FLAG_NO_FLAG,		'\0',	"file",					"{PASSWORD_FILE}"},
		{CMD_ARG_FLAG_NO_FLAG,		'\0',	"username",				"{USERNAME}"},
		{CMD_ARG_FLAG_NO_ARGUMENT,	'c',	"create-user",			"[-c|--create-user]"},
		{CMD_ARG_FLAG_NO_ARGUMENT,	'r',	"remove-user",			"[-r|--remove-user]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT |
		 CMD_ARG_FLAG_SPLIT_COMMA |
		 CMD_ARG_FLAG_ALLOW_EMPTY,	'p',	"permissions",			"[-p|--permissions[=]permission1,permission2,...]"},
		{CMD_ARG_FLAG_NO_ARGUMENT,	'a',	"append-permissions",	"[-a|--append-permissions]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT |
		 CMD_ARG_FLAG_ALLOW_EMPTY,	'P',	"password",				"[-P|--password[=]PASSWORD]"},
		{CMD_ARG_FLAG_NO_ARGUMENT,	's',	"stdout",				"[-s|--stdout]"},
		{CMD_ARG_FLAG_NO_ARGUMENT,	'l',	"loglevel-translation",	"[-l|--loglevel-translation]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'd',	"debuglevel",			"[-d|--debuglevel[=]DEBUG FLAGS]"},
		{CMD_ARG_FLAG_HAS_ARGUMENT,	'D',	"debuglevel_on_exit",	"[-D|--debuglevel_on_exit[=]DEBUG FLAGS]"},
		{CMD_ARG_FLAG_NO_ARGUMENT,	'h',	"help",					"[-h|--help]"},
		{CMD_ARG_FLAG_NO_ARGUMENT,	'v',	"version",				"[-v|--version]"},
		{0,							'\0',	NULL,					NULL}
};

struct rrr_passwd_data {
	char *filename;
	char *username;
	char *password;

	int do_create_user;
	int do_remove_user;
	int do_append_permissions;
	int do_stdout;

	struct rrr_passwd_permission_collection permissions;
};

static void __rrr_passwd_data_init (struct rrr_passwd_data *data) {
	memset (data, '\0', sizeof(*data));
}

static void __rrr_passwd_destroy_data (struct rrr_passwd_data *data) {
	RRR_FREE_IF_NOT_NULL(data->filename);
	RRR_FREE_IF_NOT_NULL(data->username);
	RRR_FREE_IF_NOT_NULL(data->password);
	rrr_passwd_permission_collection_clear(&data->permissions);
}

static int __rrr_passwd_add_permissions_from_cmd (struct rrr_passwd_data *data, struct cmd_data *cmd) {
	for (int i = 0; 1; i++) {
		const char *permission_str = cmd_get_value(cmd, "permissions", i);
		if (permission_str != NULL) {
			for (int j = 0; 1; j++) {
				permission_str = cmd_get_subvalue(cmd, "permissions", i, j);
				if (permission_str != NULL) {
					if (rrr_passwd_permission_new_and_append(&data->permissions, permission_str)) {
						return 1;
					}
				}
				else {
					break;
				}
			}
		}
		else {
			break;
		}
	}
	return 0;
}

static int __rrr_passwd_validate_str (const char *str) {
	int ret = 0;

	if (strchr(str, ':') != NULL) {
		RRR_MSG_0("Invalid character ':'\n");
		ret = 1;
	}
	if (strchr(str, ',') != NULL) {
		RRR_MSG_0("Invalid character ','\n");
		ret = 1;
	}

	return ret;
}

static int __rrr_passwd_parse_config (struct rrr_passwd_data *data, struct cmd_data *cmd) {
	int ret = 0;

	const char *file = cmd_get_value(cmd, "file", 0);
	if (file != NULL && *file != '\0') {
		data->filename = strdup(file);
		if (data->filename == NULL) {
			RRR_MSG_0("Could not allocate memory in __rrr_passwd_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	const char *username = cmd_get_value(cmd, "username", 0);
	if (username != NULL && *username != '\0') {
		data->username = strdup(username);
		if (data->username == NULL) {
			RRR_MSG_0("Could not allocate memory in __rrr_passwd_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	// Empty password allowed
	const char *password = cmd_get_value(cmd, "password", 0);
	if (password != NULL) {
		data->password = strdup(password);
		if (data->password == NULL) {
			RRR_MSG_0("Could not allocate memory in __rrr_passwd_parse_config\n");
			ret = 1;
			goto out;
		}
	}

	if (data->filename == NULL || data->username == NULL || *(data->filename) == '\0' || *(data->username) == '\0') {
		RRR_MSG_0("Password filename and/or username not set\n");
		ret = 1;
		goto out;
	}

	// Create user
	if (cmd_exists(cmd, "create-user", 0)) {
		data->do_create_user = 1;
	}
	else {
		data->do_create_user = 0;
	}

	// Delete user
	if (cmd_exists(cmd, "remove-user", 0)) {
		data->do_remove_user = 1;
	}
	else {
		data->do_remove_user = 0;
	}

	// Append permissions
	if (cmd_exists(cmd, "append-permissions", 0)) {
		data->do_append_permissions = 1;
	}
	else {
		data->do_append_permissions = 0;
	}

	// Print to stdout
	if (cmd_exists(cmd, "stdout", 0)) {
		data->do_stdout = 1;
	}
	else {
		data->do_stdout = 0;
	}

	// Permissions
	if ((ret = __rrr_passwd_add_permissions_from_cmd(data, cmd)) != 0) {
		goto out;
	}

	// Empty -p given, user might wants to remove all permissions. Insert dummy
	// value.
	if (cmd_exists(cmd, "permissions", 0) && RRR_LL_COUNT(&data->permissions) == 0) {
		if ((ret = rrr_passwd_permission_new_and_append(&data->permissions, "")) != 0) {
			goto out;
		}
	}

	// Validate characters
	RRR_LL_ITERATE_BEGIN(&data->permissions, struct rrr_passwd_permission);
		if ((ret = __rrr_passwd_validate_str(node->permission)) != 0) {
			RRR_MSG_0("Invalid characters in permission string\n");
			goto out;
		}
	RRR_LL_ITERATE_END();

	if ((ret = __rrr_passwd_validate_str(username)) != 0) {
		RRR_MSG_0("Invalid characters in username\n");
		goto out;
	}

	// Validate option combinations
	if (data->do_remove_user != 0) {
		if (	data->do_create_user != 0 ||
				data->do_append_permissions ||
				RRR_LL_COUNT(&data->permissions) != 0 ||
				data->password != NULL
		) {
			RRR_MSG_0("Error: Other options specified along with -r (remove)\n");
			ret = 1;
			goto out;
		}
	}

	if (data->do_append_permissions) {
		if (RRR_LL_COUNT(&data->permissions) == 0) {
			RRR_MSG_0("Append permissions -a was specified but not permissions were specified with -p\n");
			ret = 1;
			goto out;
		}
	}

	out:
	return ret;
}

#define WRITE_AND_CHECK(str,len)													\
	if (write(fd, str, len) < 0) {													\
		RRR_MSG_0("Could not write to output file in process_line_callback\n");		\
		ret = 1;																	\
		goto out;																	\
	}

struct process_line_callback_data {
	struct rrr_passwd_data *data;
	const char *username_to_find;
	int output_fd;
	int username_was_found;
};

static int __rrr_passwd_write_user (
		int fd,
		struct rrr_passwd_data *data,
		const char *username,
		const char *permissions[],
		size_t permissions_count,
		const char *password_hash
) {
	int ret = 0;

	struct rrr_passwd_permission_collection permissions_tmp = {0};

	WRITE_AND_CHECK(username, strlen(username));
	WRITE_AND_CHECK(":", 1);

	if (data->do_append_permissions != 0 || RRR_LL_COUNT(&data->permissions) == 0) {
		for (size_t i = 0; i < permissions_count; i++) {
			if (rrr_passwd_permission_new_and_append(&permissions_tmp, permissions[i]) != 0) {
				RRR_MSG_0("Could not store original permission in write_user()\n");
				ret = 1;
				goto out;
			}
		}
	}

	if (rrr_passwd_permission_add_from_permissions(&permissions_tmp, &data->permissions)) {
		RRR_MSG_0("Could not store new permissions in write_user()\n");
		ret = 1;
		goto out;
	}

	rrr_passwd_permission_collection_remove_duplicates(&permissions_tmp);

	int permissions_total = 0;
	RRR_LL_ITERATE_BEGIN(&permissions_tmp, const struct rrr_passwd_permission);
		if (*(node->permission) != '\0') {
			if (permissions_total > 0) {
				WRITE_AND_CHECK(",", 1);
			}
			WRITE_AND_CHECK(node->permission, strlen(node->permission));
			permissions_total++;
		}
	RRR_LL_ITERATE_END();

	WRITE_AND_CHECK(":", 1);

	const char *hash = (password_hash != NULL ? password_hash : "\0");

	WRITE_AND_CHECK(hash, strlen(hash));

	out:
	rrr_passwd_permission_collection_clear(&permissions_tmp);
	return ret;
}

static int __rrr_passwd_process_line_callback (
		const char *line,
		const char *username,
		const char *password_hash,
		const char *permissions[],
		size_t permissions_count,
		void *arg
) {
	struct process_line_callback_data *callback_data = arg;
	struct rrr_passwd_data *data = callback_data->data;

	int fd = callback_data->output_fd;

	int ret = RRR_PASSWD_ITERATE_OK;

/*	printf ("%s - %lu - %s\n", username, permissions_count, password_hash);

	for (size_t i = 0; i < permissions_count; i++) {
		printf (" - P %s\n", permissions[i]);
	}*/

	if (callback_data->username_to_find != NULL && strcmp(username, callback_data->username_to_find) == 0) {
		if (data->do_create_user != 0) {
			RRR_MSG_0("User '%s' already exists, cannot create user (-c flag was given)\n", username);
			ret = RRR_PASSWD_ITERATE_ERR;
			goto out;
		}
		if (callback_data->username_was_found != 0) {
			RRR_MSG_0("User '%s' was defined more than once in password file\n", username);
			ret = RRR_PASSWD_ITERATE_ERR;
			goto out;
		}
		callback_data->username_was_found = 1;

		if (data->do_remove_user != 0) {
			// Simply don't write user to output file, also not \n
			ret = 0;
			goto out;
		}

		if ((ret = __rrr_passwd_write_user (
				fd,
				data,
				username,
				permissions,
				permissions_count,
				(data->password != NULL ? data->password : password_hash)
		)) != 0) {
			ret = RRR_PASSWD_ITERATE_ERR;
			goto out;
		}
	}
	else {
		WRITE_AND_CHECK(line, strlen(line));
	}

	WRITE_AND_CHECK("\n", 1);

	out:
	if (ret != 0 && ret != RRR_PASSWD_ITERATE_ERR) {
		ret = RRR_PASSWD_ITERATE_ERR;
	}
	return ret;
}

static int __rrr_passwd_process (
		struct rrr_passwd_data *data,
		const char *input_data,
		ssize_t input_data_size,
		int fd
) {
	int ret = 0;

	struct process_line_callback_data callback_data = {
			data,
			data->username,
			fd,
			0
	};

	if ((ret = rrr_passwd_iterate_lines (
			input_data,
			input_data_size,
			__rrr_passwd_process_line_callback,
			&callback_data
	)) != 0) {
		goto out;
	}

	if (data->do_create_user) {
		if ((ret = __rrr_passwd_write_user (
				fd,
				data,
				data->username,
				NULL,
				0,
				data->password
		)) != 0) {
			RRR_MSG_0("Could not write new user to output file\n");
			goto out;
		}
		WRITE_AND_CHECK("\n", 1);
	}
	else if (callback_data.username_was_found == 0) {
		RRR_MSG_0("Username '%s' not found, did you mean to create a user with -c?\n", data->username);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int main (int argc, const char *argv[]) {
	if (!rrr_verify_library_build_timestamp(RRR_BUILD_TIMESTAMP)) {
		RRR_MSG_0("Library build version mismatch.\n");
		exit(EXIT_FAILURE);
	}

	rrr_strerror_init();

	int ret = EXIT_SUCCESS;

	int fd_out = 0;
	ssize_t passwd_file_size = 0;
	char *passwd_file_contents = NULL;
	char *temporary_file_name = NULL;
	char *oldfile_name = NULL;

	struct cmd_data cmd;
	struct rrr_passwd_data data;

	cmd_init(&cmd, cmd_rules, argc, argv);
	__rrr_passwd_data_init(&data);

	if ((ret = main_parse_cmd_arguments(&cmd, CMD_CONFIG_DEFAULTS)) != 0) {
		goto out;
	}

	// Don't require arguments here, separate check in parse_config
	if (rrr_print_help_and_version(&cmd, 0) != 0) {
		goto out;
	}

	if ((ret = __rrr_passwd_parse_config(&data, &cmd)) != 0) {
		cmd_print_usage(&cmd);
		goto out;
	}

	// Only ask for password if no other actions are specified and if password is not
	// also not specified in -P. Also, do this prior to creating temporary file in
	// case of ctrl+c
	if ((data.password == NULL) && (
			(	data.do_append_permissions == 0 &&
				data.do_remove_user == 0 &&
				RRR_LL_COUNT(&data.permissions) == 0
			) || (
				data.do_create_user != 0
			)
	)) {
		if (rrr_passwd_read_password_from_terminal(&data.password, 1) != 0) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (rrr_socket_open_and_read_file(&passwd_file_contents, &passwd_file_size, data.filename, O_CREAT, S_IRUSR|S_IWUSR) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (rrr_asprintf(&temporary_file_name, "%s.XXXXXX", data.filename) < 0) {
		RRR_MSG_0("Could not create temporary file name\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	if (rrr_asprintf(&oldfile_name, "%s.old", data.filename) < 0) {
		RRR_MSG_0("Could not create oldfile name\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	if (data.do_stdout != 0) {
		fd_out = 0; // STDOUT
	}
	else {
		if ((fd_out = rrr_socket_mkstemp(temporary_file_name, "rrr_passwd")) <= 0) {
			RRR_MSG_0("mkstemp failed for temporary file %s: %s\n",
					temporary_file_name, rrr_strerror(errno));
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	if (data.password != NULL && *(data.password) == '\0') {
		RRR_MSG_0("Warning: Setting empty password, user becomes disabled\n");
	}

	if (data.password != NULL && *(data.password) != '\0') {
		char *hash_tmp = NULL;
		if (rrr_passwd_encrypt (&hash_tmp, data.password) != 0) {
			RRR_MSG_0("Password hashing failed\n");
			ret = EXIT_FAILURE;
			goto out;
		}

		rrr_parse_str_strip_newlines(hash_tmp);

//		printf("Password hash is '%s'\n", hash_tmp);

		if (rrr_passwd_check(hash_tmp, data.password) != 0) {
			RRR_BUG("BUG: Could not authenticate against newly generated hash\n");
		}

		RRR_FREE_IF_NOT_NULL(data.password);
		data.password = hash_tmp;
	}

	if (__rrr_passwd_process(&data, passwd_file_contents, passwd_file_size, fd_out) != 0) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (fd_out > 0) {
		if (rename(data.filename, oldfile_name) != 0) {
			RRR_MSG_0("Could not move original file '%s' ot '%s': %s\n",
					data.filename, oldfile_name, rrr_strerror(errno));
			ret = 1;
			goto out;
		}

		// After this, all gotos after errors are to restore_oldfile

		if (rename(temporary_file_name, data.filename) != 0) {
			RRR_MSG_0("Could not rename temporary file '%s' to '%s': %s\n",
					temporary_file_name, data.filename, rrr_strerror(errno));
			ret = 1;
			goto out_restore_oldfile;
		}

		// Oldfile gets unlinked below
	}

	goto out;

	out_restore_oldfile:
		if (rename(oldfile_name, data.filename)) {
			RRR_MSG_0("Warning: Could not restore oldfile '%s' to original file '%s' while recovering from error, this must be fixed manually. Original file is now missing.: %s\n",
					oldfile_name, data.filename, rrr_strerror(errno));
			// Make sure oldfile (which is now the original file) is not unlinked
			RRR_FREE_IF_NOT_NULL(oldfile_name);
		}
	out:
		RRR_FREE_IF_NOT_NULL(passwd_file_contents);
		// Looks like Linux unlinks the file in case we forget, but this does not
		// seem to be documented. Unlink here.
		if (temporary_file_name != NULL && *temporary_file_name != '\0' && fd_out > 0) {
			// Ignore results in case we attempt to unlink the XXXXXX version
			unlink(temporary_file_name);
		}
		if (oldfile_name != NULL && *oldfile_name != '\0') {
			unlink(oldfile_name);
		}

		RRR_FREE_IF_NOT_NULL(oldfile_name);
		RRR_FREE_IF_NOT_NULL(temporary_file_name);

		if (fd_out > 0) {
			rrr_socket_close(fd_out);
		}
		rrr_set_debuglevel_on_exit();
		__rrr_passwd_destroy_data(&data);
		cmd_destroy(&cmd);
		rrr_socket_close_all();
		rrr_strerror_cleanup();
		return ret;
}
