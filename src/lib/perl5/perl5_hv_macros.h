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

#ifndef RRR_PERL5_HV_MACROS_H
#define RRR_PERL5_HV_MACROS_H

#define RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(name,hv_name)							\
	SV *name = NULL;																\
	do {SV **tmp = hv_fetch(hv, RRR_QUOTE(name), strlen(RRR_QUOTE(name)), 1);		\
		if (tmp == NULL || *tmp == NULL) {											\
			RRR_MSG_0("Could not fetch SV from HV\n");								\
			ret = 1; goto out;														\
		}																			\
		name = *tmp; (void)(name);													\
	} while(0)
/*
#define RRR_PERL5_CHECK_IS_AV(name)																				\
	do {if (SvTYPE(name) != SVt_PVAV) {																			\
		check_av_error_count++;																					\
		RRR_MSG_0("Warning: " RRR_QUOTE(name) " was not a perl array while extracting array from perl5\n");		\
	}} while (0)
*/
#define RRR_PERL5_DEFINE_AND_FETCH_FROM_AV(name,av_name,i)											\
	SV *name = NULL;																				\
	do {SV **tmp = av_fetch(av_name, i, 1);															\
	if (tmp == NULL || *tmp == NULL) {																\
		RRR_MSG_0("Could not fetch SV from array in __rrr_perl5_hv_to_message_extract_array\n");	\
		ret = 1;																					\
		goto out;																					\
	}																								\
	name = *tmp; } while(0)

#define RRR_PERL5_DEFINE_AND_FETCH_ARRAY_PTR_FROM_HV(hv)				\
	RRR_PERL5_DEFINE_AND_FETCH_FROM_HV(rrr_array_ptr, hv);				\
	struct rrr_array *array = (struct rrr_array *) SvIV(rrr_array_ptr)

#endif /* RRR_PERL5_HV_MACROS_H */
