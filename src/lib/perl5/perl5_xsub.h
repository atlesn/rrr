/*

Read Route Record

Copyright (C) 2019-2020 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_PERL5_XSUB_H
#define RRR_PERL5_XSUB_H

#include <sys/types.h>

struct AV;
struct SV;
struct HV;

unsigned int rrr_perl5_message_send (HV *hv);
unsigned int rrr_perl5_message_clear_array (HV *hv);
unsigned int rrr_perl5_message_push_tag_blob (HV *hv, const char *tag, const char *value, size_t size);
unsigned int rrr_perl5_message_push_tag_str (HV *hv, const char *tag, const char *str);
unsigned int rrr_perl5_message_push_tag_h (HV *hv, const char *tag, SV *sv);
unsigned int rrr_perl5_message_push_tag_fixp (HV *hv, const char *tag, SV *sv);
unsigned int rrr_perl5_message_push_tag (HV *hv, const char *tag, SV *values);
unsigned int rrr_perl5_message_set_tag_blob (HV *hv, const char *tag, const char *value, size_t size);
unsigned int rrr_perl5_message_set_tag_str (HV *hv, const char *tag, const char *str);
unsigned int rrr_perl5_message_set_tag_h (HV *hv, const char *tag, SV *values);
unsigned int rrr_perl5_message_set_tag_fixp (HV *hv, const char *tag, SV *values);
unsigned int rrr_perl5_message_clear_tag (HV *hv, const char *tag);
unsigned int rrr_perl5_message_ip_set (HV *hv, const char *ip, UV uv);
AV *rrr_perl5_message_ip_get (HV *hv);
unsigned int rrr_perl5_message_ip_clear (HV *hv);
SV *rrr_perl5_message_ip_get_protocol (HV *hv);
unsigned int rrr_perl5_message_ip_set_protocol (HV *hv, const char *protocol);
AV *rrr_perl5_message_get_tag (HV *hv, const char *tag);
SV *rrr_perl5_message_get_tag_at (HV *hv, const char *tag, size_t pos);
AV *rrr_perl5_message_get_tag_names (HV *hv);
AV *rrr_perl5_message_get_tag_counts (HV *hv);
SV *rrr_perl5_settings_get (HV *settings, const char *key);
int rrr_perl5_settings_set (HV *settings, const char *key, const char *value);
int rrr_perl5_debug_msg (HV *debug, int debuglevel, const char *string);
int rrr_perl5_debug_dbg (HV *debug, int debuglevel, const char *string);
int rrr_perl5_debug_err (HV *debug, const char *string);

#endif /* RRR_PERL5_XSUB_H */
