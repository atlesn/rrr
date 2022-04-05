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
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "../log.h"
#include "../allocator.h"

#include "mqtt_acl.h"
#include "mqtt_topic.h"

#include "../rrr_strerror.h"
#include "../socket/rrr_socket.h"
#include "../parse.h"
#include "../util/linked_list.h"
#include "../util/macro_utils.h"

#define RRR_MQTT_ACL_ACTION_TO_STR(action) \
	(action == RRR_MQTT_ACL_ACTION_RO ? "READ" : (action == RRR_MQTT_ACL_ACTION_RW ? "WRITE" : "DENY"))

#define RRR_MQTT_ACL_ACTION_RESULT_TO_STR(action) \
	(action == RRR_MQTT_ACL_RESULT_ALLOW ? "ALLOW" : (action == RRR_MQTT_ACL_RESULT_DENY ? "DENY" : (action == RRR_MQTT_ACL_RESULT_DISCONNECT ? "DISCONNECT" : "ERR")))

static void __rrr_mqtt_acl_user_entry_destroy (
		struct rrr_mqtt_acl_user_entry *entry
) {
	RRR_FREE_IF_NOT_NULL(entry->username);
	rrr_free(entry);
}

static int __rrr_mqtt_acl_user_entry_new_and_append (
		struct rrr_mqtt_acl_entry *target,
		const char *username,
		int action
) {
	int ret = 0;

	struct rrr_mqtt_acl_user_entry *user_entry = rrr_allocate(sizeof(*user_entry));

	if (user_entry == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memset(user_entry, '\0', sizeof(*user_entry));

	if ((user_entry->username = rrr_strdup(username)) == NULL) {
		RRR_MSG_0("Could not allocate memory for username in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	user_entry->action = action;

	RRR_LL_APPEND(target, user_entry);
	user_entry = NULL;

	goto out;
	out_free:
		rrr_free(user_entry);
	out:
		return ret;
}

static void __rrr_mqtt_acl_entry_destroy (
		struct rrr_mqtt_acl_entry *entry
) {
	RRR_LL_DESTROY(entry, struct rrr_mqtt_acl_user_entry, __rrr_mqtt_acl_user_entry_destroy(node));
	rrr_mqtt_topic_token_destroy(entry->first_token); // Checks for NULL
	RRR_FREE_IF_NOT_NULL(entry->topic_orig);
	rrr_free(entry);
}

void rrr_mqtt_acl_entry_collection_clear (
		struct rrr_mqtt_acl *collection
) {
	RRR_LL_DESTROY(collection, struct rrr_mqtt_acl_entry, __rrr_mqtt_acl_entry_destroy(node));
}

static int __rrr_mqtt_acl_entry_collection_push_new (
		struct rrr_mqtt_acl *collection,
		const struct rrr_mqtt_topic_token *first_token,
		const char *topic_orig
) {
	int ret = 0;

	struct rrr_mqtt_acl_entry *entry = NULL;

	if ((entry = rrr_allocate_zero(sizeof(*entry))) == NULL) {
		RRR_MSG_0("Could not allocate entry in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if (rrr_mqtt_topic_tokens_clone(&entry->first_token, first_token) != 0) {
		RRR_MSG_0("Could not clone topic tokens in %s\n", __func__);
		ret = 1;
		goto out_free;
	}

	if ((entry->topic_orig = rrr_strdup(topic_orig)) == NULL) {
		RRR_MSG_0("Could not duplicate topic string in %s\n", __func__);
		ret = 1;
		goto out_free_topic_tokens;
	}

	entry->default_action = RRR_MQTT_ACL_ACTION_DEFAULT;

	RRR_LL_APPEND(collection, entry);

	goto out;
	out_free_topic_tokens:
		rrr_mqtt_topic_token_destroy(entry->first_token);
	out_free:
		rrr_free(entry);
	out:
		return ret;
}

static void __rrr_mqtt_acl_parse_spaces_and_comments (
		struct rrr_parse_pos *pos
) {
	new_comment:
	rrr_parse_ignore_spaces_and_increment_line(pos);
	if (RRR_PARSE_CHECK_EOF(pos)) {
		return;
	}
	if (pos->data[pos->pos] == '#') {
		rrr_parse_comment(pos);
		goto new_comment;
	}
	rrr_parse_ignore_spaces_and_increment_line(pos);
}

static int __rrr_mqtt_acl_parse_require_newline_or_eof (
		struct rrr_parse_pos *pos
) {
	rrr_length pos_orig = pos->pos;
	rrr_length line_orig = pos->line;
	rrr_parse_ignore_spaces_and_increment_line(pos);

	// OK, end of file reached after value
	if (RRR_PARSE_CHECK_EOF(pos)) {
		return 0;
	}

	// Not ok, no space after value
	if (pos_orig == pos->pos) {
		goto err;
	}

	// OK, there was newlines after value
	if (line_orig != pos->line) {
		return 0;
	}

	// Not OK, no newline and not EOF after value

	err:
	RRR_MSG_0("Syntax error at line %i: Extra junk after value\n", pos->line);
	return 1;
}

static int __rrr_mqtt_acl_parse_require_space_then_non_newline (
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	rrr_length pos_orig = pos->pos;
	rrr_length line_orig = pos->line;
	rrr_parse_ignore_spaces_and_increment_line(pos);

	if (pos_orig == pos->pos || line_orig != pos->line) {
		RRR_MSG_0("Syntax error at line %i: Expected whitespace and then string after keyword\n", pos->line);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_mqtt_acl_parse_acl_action (
		int *action,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	*action = RRR_MQTT_ACL_ACTION_DEFAULT;

	if (rrr_parse_match_word_case(pos, "DENY") == 1) {
		*action = RRR_MQTT_ACL_ACTION_DENY;
	}
	else if (rrr_parse_match_word_case(pos, "READ") == 1) {
		*action = RRR_MQTT_ACL_ACTION_RO;
	}
	else if (rrr_parse_match_word_case(pos, "WRITE") == 1) {
		*action = RRR_MQTT_ACL_ACTION_RW;
	}
	else {
		RRR_MSG_0("Syntax error at line %i: Unknown ACL action, must be DENY, READ or WRITE\n", pos->line);
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

static int __rrr_mqtt_acl_parse_keyword_default (
		struct rrr_mqtt_acl_entry *entry,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	if (__rrr_mqtt_acl_parse_require_space_then_non_newline(pos) != 0) {
		ret = 1;
		goto out;
	}

	if (__rrr_mqtt_acl_parse_acl_action(&entry->default_action, pos) != 0) {
		ret = 1;
		goto out;
	}

	if (__rrr_mqtt_acl_parse_require_newline_or_eof(pos) != 0) {
		ret = 1;
		goto out;
	}

	out:
	if (ret != 0) {
		RRR_MSG_0("Syntax error at line %i: Error while parsing value for keyword 'DEFAULT'\n", pos->line);
	}
	return ret;
}

static int __rrr_mqtt_acl_parse_keyword_user (
		struct rrr_mqtt_acl_entry *entry,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	rrr_length username_start = 0;
	rrr_slength username_end = 0;

	int action = 0;
	char *username_tmp = NULL;

	rrr_parse_ignore_space_and_tab(pos);
	rrr_parse_match_letters (
			pos,
			&username_start,
			&username_end,
			RRR_PARSE_MATCH_LETTERS|RRR_PARSE_MATCH_NUMBERS
	);

	if (username_end < username_start) {
		RRR_MSG_0("Syntax error at line %i: Error while parsing username for keyword 'USER'\n", pos->line);
		ret = 1;
		goto out;
	}

	if ((ret = rrr_parse_str_extract (
			&username_tmp,
			pos,
			username_start,
			rrr_length_inc_bug_const(rrr_length_from_slength_sub_bug_const(username_end, username_start))
	)) != 0) {
		RRR_MSG_0("Could not extract username in %s\n", __func__);
		goto out;
	}

	if ((ret = __rrr_mqtt_acl_parse_require_space_then_non_newline(pos)) != 0) {
		goto out;
	}

	if ((ret = __rrr_mqtt_acl_parse_acl_action(&action, pos)) != 0) {
		goto out;
	}

	if ((ret = __rrr_mqtt_acl_parse_require_newline_or_eof(pos)) != 0) {
		goto out;
	}

	if (strlen(username_tmp) == 0) {
		RRR_BUG("Username length was 0 in __rrr_mqtt_acl_parse_keyword_user\n");
	}

	if ((ret = __rrr_mqtt_acl_user_entry_new_and_append(entry, username_tmp, action)) != 0) {
		RRR_MSG_0("Could not create/insert user entry in __rrr_mqtt_acl_parse_keyword_user\n");
		goto out;
	}

	out:
	RRR_FREE_IF_NOT_NULL(username_tmp);
	return ret;
}

static int __rrr_mqtt_acl_parse_topic_block_body (
		struct rrr_mqtt_acl_entry *entry,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	while (!RRR_PARSE_CHECK_EOF(pos)) {
		rrr_length pos_orig = pos->pos;

		__rrr_mqtt_acl_parse_spaces_and_comments(pos);

		if (RRR_PARSE_CHECK_EOF(pos)) {
			break;
		}

		if (rrr_parse_match_word_case(pos, "DEFAULT") == 1) {
			if (entry->default_action_is_set != 0) {
				RRR_MSG_0("Syntax error at line %i: More than one DEFAULT keyword found in topic block\n", pos->line);
				ret = 1;
				goto out;
			}
			if (__rrr_mqtt_acl_parse_keyword_default(entry, pos) != 0) {
				ret = 1;
				goto out;
			}
			entry->default_action_is_set = 1;
		}
		else if (rrr_parse_match_word_case(pos, "USER") == 1) {
			if (__rrr_mqtt_acl_parse_keyword_user(entry, pos) != 0) {
				ret = 1;
				goto out;
			}
		}
		else if (rrr_parse_match_word_case(pos, "TOPIC") == 1) {
			pos->pos = pos_orig; // Done, revert position
			goto out;
		}
		else {
			RRR_MSG_0("Syntax error at line %i: Expected keywords 'DEFAULT', 'USER' or 'TOPIC'\n", pos->line);
			ret = 1;
			goto out;
		}
	}


	out:
	return ret;
}

static int __rrr_mqtt_acl_parse_topic_blocks (
		struct rrr_mqtt_acl *target,
		struct rrr_parse_pos *pos
) {
	int ret = 0;

	char *topic_tmp = NULL;
	struct rrr_mqtt_topic_token *first_token_tmp = NULL;

	while (1) {
		__rrr_mqtt_acl_parse_spaces_and_comments(pos);

		if (RRR_PARSE_CHECK_EOF(pos)) {
			break;
		}

		if (rrr_parse_match_word_case(pos, "TOPIC") != 1) {
			RRR_MSG_0("Syntax error at line %i: Expected keyword 'TOPIC'.\n", pos->line);
			ret = 1;
			goto out;
		}

		if (__rrr_mqtt_acl_parse_require_space_then_non_newline(pos) != 0) {
			ret = 1;
			goto out;
		}

		rrr_length topic_start = 0;
		rrr_slength topic_end = 0;

		rrr_parse_non_newline(pos, &topic_start, &topic_end);

		if (topic_end < topic_start) {
			RRR_MSG_0("Syntax error at line %i: No topic found after keyword 'TOPIC'\n", pos->line);
			ret = 1;
			goto out;
		}

		RRR_FREE_IF_NOT_NULL(topic_tmp);
		if (rrr_parse_str_extract (
				&topic_tmp,
				pos,
				topic_start,
				rrr_length_inc_bug_const(rrr_length_from_slength_sub_bug_const(topic_end, topic_start))
		) != 0) {
			RRR_MSG_0("Parsing failed at line %i\n", pos->line);
			ret = 1;
			goto out;
		}

		if (rrr_mqtt_topic_filter_validate_name(topic_tmp) != 0) {
			RRR_MSG_0("Syntax error in topic string at line %i\n", pos->line);
			ret = 1;
			goto out;
		}

		rrr_mqtt_topic_token_destroy(first_token_tmp); // Checks for NULL
		if (rrr_mqtt_topic_tokenize(&first_token_tmp, topic_tmp) != 0) {
			RRR_MSG_0("Error while tokenizing topic string at line %i\n", pos->line);
			ret = 1;
			goto out;
		}

		if (__rrr_mqtt_acl_entry_collection_push_new(target, first_token_tmp, topic_tmp) != 0) {
			RRR_MSG_0("Error while storing tokens from topic at line %i\n", pos->line);
			ret = 1;
			goto out;
		}

		struct rrr_mqtt_acl_entry *entry = RRR_LL_LAST(target);
		if (__rrr_mqtt_acl_parse_topic_block_body(entry, pos) != 0) {
			ret = 1; // Error message already printed (hopefully)
			goto out;
		}

		RRR_DBG_1("MQTT ACL topic %s default action %s\n",
				topic_tmp, RRR_MQTT_ACL_ACTION_TO_STR(entry->default_action));

		RRR_LL_ITERATE_BEGIN(entry, struct rrr_mqtt_acl_user_entry);
			RRR_DBG_1("\tUSER '%s' action %s\n", node->username, RRR_MQTT_ACL_ACTION_TO_STR(node->action));
		RRR_LL_ITERATE_END();
	}

	out:
	rrr_mqtt_topic_token_destroy(first_token_tmp); // Checks for NULL
	RRR_FREE_IF_NOT_NULL(topic_tmp);
	return ret;
}

int rrr_mqtt_acl_entry_collection_populate_from_file (
		struct rrr_mqtt_acl *collection,
		const char *filename
) {
	int ret = 0;

	char *contents = NULL;
	rrr_biglength bytes = 0;

	if ((ret = rrr_socket_open_and_read_file (
			&contents,
			&bytes,
			filename,
			O_RDONLY,
			0
	)) != 0) {
		RRR_MSG_0("Error while reading from MQTT ACL file '%s'\n", filename);
		ret = 1;
		goto out;
	}

	if (contents == NULL || bytes <= 0) {
		RRR_MSG_0("Warning: MQTT ACL file '%s' was empty\n", filename);
		goto out;
	}
	else if (bytes > RRR_LENGTH_MAX) {
		RRR_MSG_0("Error: MQTT ACL file '%s' was too big\n", filename);
		ret = 1;
		goto out;
	}

	struct rrr_parse_pos parse_pos;
	rrr_parse_pos_init(&parse_pos, contents, rrr_length_from_biglength_bug_const(bytes));

	if ((ret = __rrr_mqtt_acl_parse_topic_blocks(collection, &parse_pos)) != 0) {
		RRR_MSG_0("Error while parsing MQTT ACL file '%s'\n", filename);
		ret = 1;
		goto out_clear_acl;
	}

	goto out;
	out_clear_acl:
		rrr_mqtt_acl_entry_collection_clear(collection);
	out:
		RRR_FREE_IF_NOT_NULL(contents);
		return ret;
}

int rrr_mqtt_acl_entry_collection_push_allow_all (
		struct rrr_mqtt_acl *collection
) {
	int ret = 0;

	struct rrr_mqtt_topic_token *token_tmp = NULL;

	if (rrr_mqtt_topic_tokenize(&token_tmp, "#") != 0) {
		RRR_MSG_0("Could not create token in %s\n", __func__);
		ret = 1;
		goto out;
	}

	if (__rrr_mqtt_acl_entry_collection_push_new(collection, token_tmp, "#") != 0) {
		RRR_MSG_0("Could not insert entry in %s\n", __func__);
		ret = 1;
		goto out;
	}

	RRR_LL_LAST(collection)->default_action = RRR_MQTT_ACL_ACTION_RW;

	out:
	rrr_mqtt_topic_token_destroy(token_tmp); // Checks for NULL
	return ret;
}

static int __rrr_mqtt_acl_check_access_single (
		int action,
		int requested_access_level
) {
	int ret = RRR_MQTT_ACL_RESULT_DENY;

	int allow_write = 0;
	int allow_read = 0;

	switch (action) {
		case RRR_MQTT_ACL_ACTION_RW:
			allow_write = 1;
			allow_read = 1;
			break;
		case RRR_MQTT_ACL_ACTION_RO:
			allow_read = 1;
			break;
		case RRR_MQTT_ACL_ACTION_DENY:
		default:
			break;
	};

	if (requested_access_level == RRR_MQTT_ACL_ACTION_RO) {
		if (allow_read != 0) {
			ret = RRR_MQTT_ACL_RESULT_ALLOW;
		}
	}
	else if (requested_access_level == RRR_MQTT_ACL_ACTION_RW) {
		if (allow_write != 0) {
			ret = RRR_MQTT_ACL_RESULT_ALLOW;
		}
	}
	else {
		RRR_BUG("Unknown access level %i to %s\n", requested_access_level, __func__);
	}

	return ret;
}

int rrr_mqtt_acl_check_access (
		const struct rrr_mqtt_acl *collection,
		const struct rrr_mqtt_topic_token *first_token,
		int requested_access_level,
		const char *username,
		int (*match_function) (
				const struct rrr_mqtt_topic_token *a,
				const struct rrr_mqtt_topic_token *b
		)
) {
	int ret = RRR_MQTT_ACL_RESULT_DENY;

	RRR_LL_ITERATE_BEGIN(collection, const struct rrr_mqtt_acl_entry);
		if (match_function(node->first_token, first_token) == RRR_MQTT_TOKEN_MATCH) {
			RRR_DBG_2 ("ACL matched %s requested level %s default action %s\n",
					node->topic_orig, RRR_MQTT_ACL_ACTION_TO_STR(requested_access_level), RRR_MQTT_ACL_ACTION_TO_STR(node->default_action));

			ret = __rrr_mqtt_acl_check_access_single(node->default_action, requested_access_level);

			RRR_DBG_2 ("ACL result is %s (after default)\n",
					RRR_MQTT_ACL_ACTION_RESULT_TO_STR(ret));

			if (username != NULL && *username != '\0') {
				const struct rrr_mqtt_acl_entry *entry = node;
				RRR_LL_ITERATE_BEGIN(entry, const struct rrr_mqtt_acl_user_entry);
					if (strcmp(node->username, username) == 0) {
						ret = __rrr_mqtt_acl_check_access_single(node->action, requested_access_level);
						RRR_DBG_2 ("ACL result is %s (after username %s match)\n",
								RRR_MQTT_ACL_ACTION_RESULT_TO_STR(ret), username);
					}
				RRR_LL_ITERATE_END();
			}
		}
	RRR_LL_ITERATE_END();

	return ret;
}
