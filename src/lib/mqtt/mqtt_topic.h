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

#ifndef RRR_MQTT_TOPIC_H
#define RRR_MQTT_TOPIC_H

#include "../rrr_inttypes.h"
#include "../read_constants.h"

struct rrr_mqtt_topic_token {
	struct rrr_mqtt_topic_token *next;

	// Must be last
	char data[1];
};

#define RRR_MQTT_TOKEN_OK                 RRR_READ_OK
#define RRR_MQTT_TOKEN_MATCH              RRR_READ_OK
#define RRR_MQTT_TOKEN_INTERNAL_ERROR     RRR_READ_HARD_ERROR
#define RRR_MQTT_TOKEN_MISMATCH           RRR_READ_UNSUCSESSFUL

int rrr_mqtt_topic_filter_validate_name (
		const char *topic_filter
);
int rrr_mqtt_topic_validate_name_with_end (
		const char *topic_name,
		const char *end
);
int rrr_mqtt_topic_validate_name (
		const char *topic_name
);
int rrr_mqtt_topic_match_tokens_recursively (
		const struct rrr_mqtt_topic_token *sub_token,
		const struct rrr_mqtt_topic_token *pub_token
);
int rrr_mqtt_topic_match_topic_and_linear_with_end (
		const char *topic,
		const char *topic_end,
		const char *filter,
		const char *filter_end
);
int rrr_mqtt_topic_match_str_with_end (
		const char *sub_filter,
		const char *pub_topic,
		const char *pub_topic_end
);
int rrr_mqtt_topic_match_str (
		const char *sub_filter,
		const char *pub_topic
);
int rrr_mqtt_topic_match_tokens_recursively_acl (
		const struct rrr_mqtt_topic_token *token_master,
		const struct rrr_mqtt_topic_token *token_slave
);
void rrr_mqtt_topic_token_destroy (
		struct rrr_mqtt_topic_token *first_token
);
int rrr_mqtt_topic_tokens_clone (
		struct rrr_mqtt_topic_token **target,
		const struct rrr_mqtt_topic_token *first_token
);
int rrr_mqtt_topic_tokenize_with_end (
		struct rrr_mqtt_topic_token **first_token,
		const char *topic,
		const char *end
);
int rrr_mqtt_topic_tokenize (
		struct rrr_mqtt_topic_token **first_token,
		const char *topic
);

#endif /* RRR_MQTT_TOPIC_H */
