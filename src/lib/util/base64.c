/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * 
 * CHANGELOG:
 *  2019-09-24 Atle Solbakken <atle@goliathdns.no>
 *   - Small changes to fit RRR build (function names, headers)
 *  2020-11-04 Atle Solbakken <atle@goliathdns.no>
 *   - Added rrr_base64url_encode function
 *  2020-11-06 Atle Solbakken <atle@goliathdns.no>
 *   - Added rrr_base64url_decode function
 */

#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "../allocator.h"
#include "../rrr_types.h"

static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
unsigned char * rrr_base64_encode(const unsigned char *src, rrr_biglength len,
			      rrr_biglength *out_len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	rrr_biglength olen;
	int line_len;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len)
		return NULL; /* integer overflow */
	out = rrr_allocate(olen);
	if (out == NULL)
		return NULL;

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
		if (line_len >= 72) {
			*pos++ = '\n';
			line_len = 0;
		}
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	if (line_len)
		*pos++ = '\n';

	*pos = '\0';
	if (out_len)
		*out_len = (rrr_biglength) (pos - out);
	return out;
}


/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
unsigned char * rrr_base64_decode(const unsigned char *src, rrr_biglength len,
			      rrr_biglength *out_len)
{
	unsigned char dtable[256], *out, *pos, block[4], tmp;
	rrr_biglength i, count, olen;
	int pad = 0;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (unsigned char) i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return NULL;

	olen = count / 4 * 3;
	pos = out = rrr_allocate(olen);
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (unsigned char) ((block[0] << 2) | (block[1] >> 4));
			*pos++ = (unsigned char) ((block[1] << 4) | (block[2] >> 2));
			*pos++ = (unsigned char) ((block[2] << 6) | block[3]);
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					rrr_free(out);
					return NULL;
				}
				break;
			}
		}
	}

	*out_len = (rrr_biglength) (pos - out);
	return out;
}

static const unsigned char base64url_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/*
 * Same as above function but base64url scheme is used (no newlines, no =, and +/ becomes -_)
 */
unsigned char *rrr_base64url_encode(const unsigned char *src, rrr_biglength len,
			      rrr_biglength *out_len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	rrr_biglength olen;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len)
		return NULL; /* integer overflow */
	out = rrr_allocate(olen);
	if (out == NULL)
		return NULL;

	end = src + len;
	in = src;
	pos = out;
	while (end - in >= 3) {
		*pos++ = base64url_table[in[0] >> 2];
		*pos++ = base64url_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64url_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64url_table[in[2] & 0x3f];
		in += 3;
	}

	if (end - in) {
		*pos++ = base64url_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64url_table[(in[0] & 0x03) << 4];
		} else {
			*pos++ = base64url_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64url_table[(in[1] & 0x0f) << 2];
		}
	}

	*pos = '\0';
	if (out_len)
		*out_len = (rrr_biglength) (pos - out);
	return out;
}

unsigned char *rrr_base64url_decode(const unsigned char *src, rrr_biglength len,
			      rrr_biglength *out_len)
{
	unsigned char dtable[256], *out, *pos, block[4], tmp;
	rrr_biglength i, count, olen;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64url_table) - 1; i++)
		dtable[base64url_table[i]] = (unsigned char) i;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return NULL;

	olen = count / 4 * 3;
	pos = out = rrr_allocate(olen);
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (unsigned char) ((block[0] << 2) | (block[1] >> 4));
			*pos++ = (unsigned char) ((block[1] << 4) | (block[2] >> 2));
			*pos++ = (unsigned char) ((block[2] << 6) | block[3]);
			count = 0;
		}
	}

	*out_len = (rrr_biglength) (pos - out);
	return out;
}
