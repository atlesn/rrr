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

#ifndef RRR_SNMP_H
#define RRR_SNMP_H

#include <inttypes.h>

#define RRR_SNMP_PACKET_HEAD	\
	int32_t version;			\
	int32_t community

struct rrr_snmp_packet {
	RRR_SNMP_PACKET_HEAD;
	char data[1];
} __attribute((__packed__));

struct rrr_snmp_packet_pdu_normal {
	RRR_SNMP_PACKET_HEAD;
	int32_t pdu_type;
	int32_t request_id;
	int32_t error_status;
	int32_t error_index;
	char variable_bindings[1];
} __attribute((__packed__));

struct rrr_snmp_packet_pdu_trap {
	RRR_SNMP_PACKET_HEAD;
	int32_t pdu_type;
	int32_t enterprise;
	int32_t agent_addr;
	int32_t generic_trap;
	int32_t specific_trap;
	int32_t time_trap;
	char variable_bindings[1];
} __attribute((__packed__));



#endif /* RRR_SNMP_H */
