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
		const char *end,
		const struct rrr_mqtt_topic_linear *filter
) {
	const rrr_length topic_length = rrr_length_from_ptr_sub_bug_const(end, topic);

	if (topic == NULL || topic_length == 0)
		return RRR_MQTT_TOKEN_MISMATCH;

	assert (*topic != '\0');

	const struct rrr_mqtt_topic_linear_token *linear_token = (void *) filter->data;
	const rrr_u32 linear_token_head_size = sizeof(*linear_token) - sizeof(linear_token->data);
	const char *data_pos = filter->data;
	const char * const data_end = ((const void *) filter) + filter->data_size;
	size_t i = 0, j = 0;
	rrr_u32 token_length;
	char c1, c2;
	int token_match = 0;

	while (data_pos < data_end) {
		assert(linear_token->data_size > linear_token_head_size);

		token_length = linear_token->data_size - linear_token_head_size;

		for (i = 0; i < token_length; i++) {
			again:

			c1 = linear_token->data[i];
			printf("At c1 %c\n", c1);

			assert(c1 != '/');

			if (j == topic_length) {
				printf("Mismatch topic exhausted\n");
				return RRR_MQTT_TOKEN_MISMATCH;
			}

	/* TESTS
	 * topic               filter                result
	 * aaa                 #                     match
	 * a/a                 a/+                   match
	 * a/a                 +/a                   match
	 * a/                  +/+                   match
	 * /a                  +/+                   match
	 * //                  //                    match
	 * /                   //                    mismatch
	 * //                  /                     mismatch
	 */

			if (c1 == '#') {
				assert(i == 0 /* at token start */);
				assert(token_length == 1);
				assert((long long int) i == token_length - 1);
				goto match;
			}

			if (c1 == '+') {
				assert(i == 0 /* at token start */);
				assert(token_length == 1);
				token_match = 0;

				// Everything up to next / or end matches
				for (; j < topic_length; j++) {
					c2 = topic[j];
					printf("At c2 %c checking for slash\n", c2);
					if (c2 == '/') {
						token_match = 1;
						j++;
						break;
					}
				}
				if (j == topic_length) {
					token_match = 1;
				}
				if (!token_match) {
					printf("Mismatch after +\n");
					return RRR_MQTT_TOKEN_MISMATCH;
				}
				continue;
			}

			c2 = topic[j++];
			printf("At c2 %c checking for slash and first char of topic token %i\n", c2, i == 0);
			if (i == 0 && c2 == '/') {
				goto again;
			}

			printf("At c2 %c checking for equal\n", c2);
			if (c1 != c2) {
				printf("Mismatch at %c %c\n", c1, c2);
				return RRR_MQTT_TOKEN_MISMATCH;
			}
		}

		data_pos += linear_token->data_size;
		linear_token = (void *) data_pos;
	}

	assert(data_pos == data_end);

	if (j != topic_length) {
		printf("Mismatch topci not exhausted\n");
		return RRR_MQTT_TOKEN_MISMATCH;
	}

	match:
	printf("%p %p\n", data_pos, data_end);

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

	if (pos < end) {
		const char *token_end = __rrr_mqtt_topic_strnchr(pos, '/', end);
		if (token_end == NULL) {
			token_end = end;
		}

		rrr_length len = rrr_length_from_ptr_sub_bug_const (token_end, pos);
		token = rrr_allocate(sizeof(*token) + len + 1);
//		printf ("allocate token %p\n", token);
		if (token == NULL) {
			RRR_MSG_0("Could not allocate memory in %s\n", __func__);
			ret = 1;
			goto out;
		}
		memset (token, '\0', sizeof(*token));
		memcpy(token->data, pos, len);
		token->data[len] = '\0';

		pos += len + 1;

		if (pos < end) {
			ret = rrr_mqtt_topic_tokenize_with_end(&token->next, pos, end);
			if (ret != 0) {
				goto out_cleanup;
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

int rrr_mqtt_topic_token_to_linear (
		struct rrr_mqtt_topic_linear **target,
		const struct rrr_mqtt_topic_token *first_token
) {
	int ret = 0;

	struct rrr_mqtt_topic_linear *topic_linear;
	const struct rrr_mqtt_topic_token *token;
	struct rrr_mqtt_topic_linear_token linear_token_tmp;
	static const rrr_u32 linear_token_head_size = sizeof(linear_token_tmp) - sizeof(linear_token_tmp.data);
	static const rrr_u32 linear_head_size = sizeof(*topic_linear) - sizeof(topic_linear->data);
	rrr_u32 total_size = 0;
	void *wpos;

	token = first_token;
	for (token = first_token; token; token = token->next) {
		const size_t token_data_size = strlen(token->data);

		if (token_data_size > 0xffff) {
			RRR_MSG_0("Token size exceeds maximum in %s\n");
			ret = 1;
			goto out;
		}

		total_size += linear_token_head_size + token_data_size;

		if (total_size < linear_token_head_size || total_size < token_data_size) {
			RRR_MSG_0("Size overflow in %s\n", __func__);
			ret = 1;
			goto out;
		}
	}

	if ((topic_linear = rrr_allocate(linear_head_size + total_size)) == NULL) {
		RRR_MSG_0("Failed to allocate memory in %s\n", __func__);
		ret = 1;
		goto out;
	}

	RRR_ASSERT(sizeof(rrr_length) == sizeof(topic_linear->data_size),length_of_data_size_is_same_as_rrr_length);
	topic_linear->data_size = rrr_length_add_bug_const(rrr_length_from_biglength_bug_const(total_size), 4);
	wpos = &topic_linear->data;

	for (token = first_token; token; token = token->next) {
		const size_t token_data_size = strlen(token->data);

		linear_token_tmp.data_size = rrr_u16_from_biglength_bug_const(linear_token_head_size + token_data_size);
		memcpy(wpos, &linear_token_tmp, linear_token_head_size);
		wpos += linear_token_head_size;

		memcpy(wpos, token->data, token_data_size);
		wpos += token_data_size;
	}

	assert(wpos - (void *) topic_linear == topic_linear->data_size);

	*target = topic_linear;

	goto out;
//	out_free:
//	rrr_free(topic_linear);
	out:
	return ret;
}

int rrr_mqtt_topic_to_linear (
		struct rrr_mqtt_topic_linear **target,
		const char *topic
) {
	int ret = 0;

	struct rrr_mqtt_topic_token *token;

	if ((ret = rrr_mqtt_topic_tokenize (&token, topic)) != 0) {
		goto out;
	}

	if ((ret = rrr_mqtt_topic_token_to_linear (target, token)) != 0) {
		goto out_destroy;
	}

	out_destroy:
		rrr_mqtt_topic_token_destroy(token);
	out:
		return ret;
}
