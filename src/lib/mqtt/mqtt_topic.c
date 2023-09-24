/*

Read Route Record

Copyright (C) 2019-2023 Atle Solbakken atle@goliathdns.no

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

#include <string.h>
#include <stdlib.h>

#include "../allocator.h"
#include "../log.h"

#include "mqtt_topic.h"

#include "../rrr_types.h"
#include "../util/utf8.h"
#include "../util/macro_utils.h"

struct topic_name_seq {
	uint32_t c1;
	uint32_t c2;
	const char *orig;
};

static int __rrr_mqtt_topic_filter_char_is_ok(uint32_t c, void *arg) {
	int ret = 0;

	struct topic_name_seq *seq = arg;

	seq->c1 = seq->c2;
	seq->c2 = c;

	if (seq->c2 == '#' && seq->c1 != '/' && seq->c1 != '\0') {
		RRR_MSG_0("Wildcard '#' must be preceded by separator '/' or be at the beginning in mqtt topic filter '%s'\n",
				seq->orig);
		return 1;
	}
	if (seq->c2 == '+' && seq->c1 != '/' && seq->c1 != '\0') {
		RRR_MSG_0("Wildcard '+' must be preceded by separator '/' or be at the beginning in mqtt topic filter '%s'\n",
				seq->orig);
		return 1;
	}
	if (seq->c1 == '#') {
		RRR_MSG_0("Wildcard '#' must be at the very end in mqtt topic filter '%s'\n",
				seq->orig);
		return 1;
	}
	if (seq->c1 == '+' && seq->c2 != '/' && seq->c1 != '\0') {
		RRR_MSG_0("Wildcard '+' must precede separator '/' or be at the end in mqtt topic filter '%s'\n",
				seq->orig);
		return 1;
	}

	return ret;
}

static int __rrr_mqtt_topic_name_char_is_ok(uint32_t c, void *arg) {
	int ret = 0;

	struct topic_name_seq *seq = arg;

	if (c == '#' || c == '+') {
		RRR_MSG_0("mqtt topic name cannot contain '+' and '#', name was '%s'\n",
				seq->orig);
		return 1;
	}

	return ret;
}

int rrr_mqtt_topic_filter_validate_name (
		const char *topic_filter
) {
	struct topic_name_seq seq = { 0, 0, topic_filter };

	if (strlen(topic_filter) > 0xffff) {
		RRR_MSG_0("Topic filter too long in %s\n", __func__);
		return 1;
	}

	return rrr_utf8_validate_and_iterate (
			topic_filter,
			rrr_length_from_size_t_bug_const(strlen(topic_filter)),
			__rrr_mqtt_topic_filter_char_is_ok,
			&seq
	);
}

int rrr_mqtt_topic_validate_name_with_end (
		const char *topic_name,
		const char *end
) {
	if (topic_name == end) {
		return 1;
	}

	struct topic_name_seq seq = { 0, 0, topic_name };

	return rrr_utf8_validate_and_iterate (
			topic_name,
			rrr_length_from_ptr_sub_bug_const(end, topic_name),
			__rrr_mqtt_topic_name_char_is_ok,
			&seq
	);
}

int rrr_mqtt_topic_validate_name (
		const char *topic_name
) {
	if (topic_name == NULL || *topic_name == '\0') {
		return 1;
	}

	return rrr_mqtt_topic_validate_name_with_end (
			topic_name,
			topic_name + strlen(topic_name)
	);
}

// Only sub_token may contain # and +
int rrr_mqtt_topic_match_tokens_recursively (
		const struct rrr_mqtt_topic_token *sub_token,
		const struct rrr_mqtt_topic_token *pub_token
) {
	if (sub_token == NULL || pub_token == NULL) {
		return RRR_MQTT_TOKEN_MISMATCH;
	}

	if (*(sub_token->data) == '#') {
		if (strlen(sub_token->data) != 1) {
			RRR_BUG("topic filter with # had length != 1 '%s'\n", sub_token->data);
		}
		if (*(pub_token->data) == '$') {
			return RRR_MQTT_TOKEN_MISMATCH;
		}
		// # matches everything on this level and subsequent levels, return match
		return RRR_MQTT_TOKEN_MATCH;
	}

	if (*(sub_token->data) == '+') {
		if (strlen(sub_token->data) != 1) {
			RRR_BUG("topic filter with + had length != 1 '%s'\n", sub_token->data);
		}
		if (*(pub_token->data) == '$') {
			return RRR_MQTT_TOKEN_MISMATCH;
		}
		// + matches everything on this level, continue
	}
	else if (strcmp(sub_token->data, pub_token->data) != 0) {
		// no wildcard, string on levels must be identical
		return RRR_MQTT_TOKEN_MISMATCH;
	}

	if (sub_token->next == NULL && pub_token->next == NULL) {
		return RRR_MQTT_TOKEN_MATCH;
	}

	return rrr_mqtt_topic_match_tokens_recursively(sub_token->next, pub_token->next);
}

// Only sub_token may contain # and +
int rrr_mqtt_topic_match_topic_and_linear_with_end (
		const char *topic,
		const char *topic_end,
		const char *filter,
		const char *filter_end
) {
	assert (topic != NULL);
	assert (filter != NULL);
	assert (topic != topic_end);
	assert (filter != filter_end);

	const char *filter_pos, *topic_pos;
	char c1;
	int topic_token_pos = 0;
	int filter_token_pos = 0;

	for (filter_pos = filter, topic_pos = topic; filter_pos < filter_end; filter_pos++, filter_token_pos++, topic_token_pos++) {
		c1 = *filter_pos;

		if (c1 == '#') {
			assert(topic_token_pos == 0);
			assert(filter_token_pos == 0);

			if (*topic_pos == '$') {
				return RRR_MQTT_TOKEN_MISMATCH;
			}

			goto match;
		}

		if (c1 == '+') {
			assert(topic_token_pos == 0);
			assert(filter_token_pos == 0);

			if (*topic_pos == '$') {
				return RRR_MQTT_TOKEN_MISMATCH;
			}
			for (; topic_pos < topic_end; topic_pos++) {
				if (*topic_pos == '/') {
					topic_token_pos = -1;
					break;
				}
			}
			if (topic_pos == topic_end) {
				goto match;
			}
			continue;
		}

		if (topic_pos == topic_end) {
			return RRR_MQTT_TOKEN_MISMATCH;
		}

		if (c1 != *(topic_pos++)) {
			return RRR_MQTT_TOKEN_MISMATCH;
		}

		if (c1 == '/') {
			filter_token_pos = -1;
			topic_token_pos = -1;
		}
	}

	if (topic_pos != topic_end) {
		return RRR_MQTT_TOKEN_MISMATCH;
	}

	match:

	if (c1 != '#') {
		assert(topic_pos == topic_end);
	}

	return RRR_MQTT_TOKEN_MATCH;
}

int rrr_mqtt_topic_match_str_with_end (
		const char *sub_filter,
		const char *pub_topic,
		const char *pub_topic_end
) {
	int ret = RRR_MQTT_TOKEN_MISMATCH;

	struct rrr_mqtt_topic_token *sub_filter_tokens = NULL;
	struct rrr_mqtt_topic_token *pub_topic_tokens = NULL;

	if (rrr_mqtt_topic_tokenize(&sub_filter_tokens, sub_filter) != 0) {
		RRR_MSG_0("Failed to tokenize filter in %s\n", __func__);
		ret = RRR_MQTT_TOKEN_INTERNAL_ERROR;
		goto out;
	}

	if (rrr_mqtt_topic_tokenize_with_end(&pub_topic_tokens, pub_topic, pub_topic_end) != 0) {
		RRR_MSG_0("Failed to tokenize topic in %s\n", __func__);
		ret = RRR_MQTT_TOKEN_INTERNAL_ERROR;
		goto out;
	}

	ret = rrr_mqtt_topic_match_tokens_recursively(sub_filter_tokens, pub_topic_tokens);

	out:
	rrr_mqtt_topic_token_destroy(sub_filter_tokens);
	rrr_mqtt_topic_token_destroy(pub_topic_tokens);
	return ret;
}

int rrr_mqtt_topic_match_str (
		const char *sub_filter,
		const char *pub_topic
) {
	return rrr_mqtt_topic_match_str_with_end (
			sub_filter,
			pub_topic,
			pub_topic + strlen(pub_topic)
	);
}

// Both token trees may contain # and +
// The master token is usually an ACL entry and the slave a subscription request
// The # of a slave topic will only match the master topic if the master topic is also # on the same level
int rrr_mqtt_topic_match_tokens_recursively_acl (
		const struct rrr_mqtt_topic_token *token_master,
		const struct rrr_mqtt_topic_token *token_slave
) {
	if (token_master == NULL || token_slave == NULL) {
		return RRR_MQTT_TOKEN_MISMATCH;
	}

//	printf ("Match ACL %s vs %s\n", token_master->data, token_slave->data);

	if (*(token_master->data) == '#') {
//		printf ("Match by master #\n");
		return RRR_MQTT_TOKEN_MATCH;
	}
	else if (*(token_slave->data) == '#') {
//		printf ("Mismatch by slave #\n");
		return RRR_MQTT_TOKEN_MISMATCH;
	}
	else if (*(token_master->data) == '+' || *(token_slave->data) == '+') {
//		printf ("Preliminary match by slave or master +\n");
		if (*(token_master->data) == '$') {
//			printf ("Mismatch by master $\n");
			return RRR_MQTT_TOKEN_MISMATCH;
		}
		// + matches everything on this level, continue
	}
	else if (strcmp(token_master->data, token_slave->data) != 0) {
		// no wildcard, string on levels must be identical
//		printf ("Mismatch by token inequality\n");
		return RRR_MQTT_TOKEN_MISMATCH;
	}

	if (token_master->next == NULL && token_slave->next == NULL) {
//		printf ("Match by no more tokens\n");
		return RRR_MQTT_TOKEN_MATCH;
	}

//	printf ("Preliminary match by token equality\n");

	return rrr_mqtt_topic_match_tokens_recursively_acl(token_master->next, token_slave->next);
}

void rrr_mqtt_topic_token_destroy (
		struct rrr_mqtt_topic_token *first_token
) {
	if (first_token == NULL) {
		return;
	}
	if (first_token->next != NULL) {
		rrr_mqtt_topic_token_destroy(first_token->next);
	}

	// The data field is not a separate pointer, don't free

//	printf ("free token %p (destroy)\n", first_token);
	rrr_free(first_token);
}

int rrr_mqtt_topic_tokens_clone (
		struct rrr_mqtt_topic_token **target,
		const struct rrr_mqtt_topic_token *first_token
) {
	int ret = 0;

	*target = NULL;

	if (first_token == NULL) {
		goto out;
	}

	struct rrr_mqtt_topic_token *result = rrr_allocate(strlen(first_token->data) + sizeof(*result));
//	printf ("allocate token %p (clone)\n", result);
	if (result == NULL) {
		RRR_MSG_0("Could not allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	strcpy(result->data, first_token->data);

	ret = rrr_mqtt_topic_tokens_clone(&result->next, first_token->next);
	if (ret != 0) {
		RRR_MSG_0("Could not clone child topic token in %s\n", __func__);
		goto out_free;
	}

	*target = result;

	goto out;
	out_free:
//		printf ("free token %p (clone)\n", result);
		rrr_free(result);
		result = NULL;
	out:
		return ret;
}

static const char *__rrr_mqtt_topic_strnchr (
		const char *haystack,
		const char chr,
		const char *end
) {
	for (const char *pos = haystack; pos < end; pos++) {
		if (*pos == chr) {
			return pos;
		}
	}
	return NULL;
}

int rrr_mqtt_topic_tokenize_with_end (
		struct rrr_mqtt_topic_token **first_token,
		const char *topic,
		const char *end
) {
	const char *pos = topic;

	*first_token = NULL;

	struct rrr_mqtt_topic_token *token = NULL;

	int ret = 0;

	rrr_length len;

	if (pos < end) {
		const char *token_end = __rrr_mqtt_topic_strnchr(pos, '/', end);
		if (token_end == NULL) {
			token_end = end;
		}

		len = rrr_length_from_ptr_sub_bug_const (token_end, pos);

		if ((token = rrr_allocate(sizeof(*token) + len + 1)) == NULL) {
			RRR_MSG_0("Could not allocate memory in %s\n", __func__);
			ret = 1;
			goto out;
		}
		memset (token, '\0', sizeof(*token));
		memcpy (token->data, pos, len);
		token->data[len] = '\0';

		if (token_end == end - 1 && *token_end == '/') {
			const char* dummy = "";
			if ((ret = rrr_mqtt_topic_tokenize_with_end(&token->next, dummy, dummy + 1)) != 0) {
				goto out_cleanup;
			}
			len = 0;
			token_end = end;
		}
		else {
			pos += len + 1;

			if (pos < end) {
				if ((ret = rrr_mqtt_topic_tokenize_with_end(&token->next, pos, end)) != 0) {
					goto out_cleanup;
				}
			}
		}
	}

	*first_token = token;

	goto out;

	out_cleanup:
/*		if (token != NULL) {
				printf ("free token %p\n", token);
		}*/
		RRR_FREE_IF_NOT_NULL(token);
	out:
		return ret;
}

int rrr_mqtt_topic_tokenize (
		struct rrr_mqtt_topic_token **first_token,
		const char *topic
) {
	const char *end = topic + strlen(topic);
	return rrr_mqtt_topic_tokenize_with_end(first_token, topic, end);
}
