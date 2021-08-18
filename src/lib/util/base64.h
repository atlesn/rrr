/*

Read Route Record

Copyright (C) 2018-2019 Atle Solbakken atle@goliathdns.no

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

#ifndef RRR_BASE64_H
#define RRR_BASE64_H

#include "../rrr_types.h"

unsigned char *rrr_base64_encode (
		const unsigned char *src,
		rrr_biglength len,
		rrr_biglength *out_len
);
unsigned char *rrr_base64_decode (
		const unsigned char *src,
		rrr_biglength len,
		rrr_biglength *out_len
);
unsigned char *rrr_base64url_encode (
		const unsigned char *src,
		rrr_biglength len,
		rrr_biglength *out_len
);
unsigned char *rrr_base64url_decode (
		const unsigned char *src,
		rrr_biglength len,
		rrr_biglength *out_len
);

#endif /* RRR_BASE64_H */
