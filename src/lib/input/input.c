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

#include <stddef.h>

#include "../log.h"
#include "input.h"
#include "../read_constants.h"
#include "../socket/rrr_socket.h"

#ifdef RRR_WITH_LINUX_INPUT
#	include "linux.h"
#endif

#define LCTRL 29
#define LSHIFT 42
#define RSHIFT 54
#define LALT 56
#define CAPS 58
#define NUMLOCK 69
#define RALT 98
#define RCTRL 99

#define SPECIAL_LCTRL (1<<0)
#define SPECIAL_LSHIFT (1<<1)
#define SPECIAL_RSHIFT (1<<2)
#define SPECIAL_LALT (1<<3)
#define SPECIAL_CAPS (1<<4)
#define SPECIAL_NUMLOCK (1<<5)
#define SPECIAL_RCTRL (1<<6)

struct map {
	int key;
	const char *lower;
	const char *upper;
};

static const struct map map[] = {
//	{1, "[ESC]", "[ESC]"},
	{2, "1", "!"},
	{3, "2", "@"},
	{4, "3", "#"},
	{5, "4", "$"},
	{6, "5", "%"},
	{7, "6", "^"},
	{8, "7", "&"},
	{9, "8", "*"},
	{10, "9", "("},
	{11, "0", ")"},
	{12, "-", "_"},
	{13, "=", "+"},
//	{14, "[BACK]", "[BACK]"},
//	{15, "[TAB]", "[TAB]"},
	{16, "q", "Q"},
	{17, "w", "W"},
	{18, "e", "E"},
	{19, "r", "R"},
	{20, "t", "T"},
	{21, "y", "Y"},
	{22, "u", "U"},
	{23, "i", "I"},
	{24, "o", "O"},
	{25, "p", "P"},
	{26, "[", "{"},
	{27, "]", "}"},
	{28, "\r", "\r"},
//	{29, "[LCTRL]", "[LCTRL]"},
	{30, "a", "A"},
	{31, "s", "S"},
	{32, "d", "D"},
	{33, "f", "F"},
	{34, "g", "G"},
	{35, "h", "H"},
 	{36, "j", "J"},
	{37, "k", "K"},
	{38, "l", "L"},
	{39, ";", ":"},
	{40, "'", "\""},
	{41, "`", "~"},
//	{42, "[LSHIFT]", "[LSHIFT]"},
	{43, "\\", "|"},
	{44, "z", "Z"},
	{45, "x", "X"},
	{46, "c", "C"},
	{47, "v", "V"},
	{48, "b", "B"},
	{49, "n", "N"},
	{50, "m", "M"},
	{51, ",", "<"},
	{52, ".", ">"},
	{53, "/", "?"},
//	{54, "[RSHIFT]", "[RSHIFT]"},
	{55, "*", "*"},
//	{56, "[LALT]", "[LALT]"},
	{57, " ", " "},
//	{58, "[CAPS]", "[CAPS]"},
//	{59, "[F1]", "[F1]"},
//	{60, "[F2]", "[F2]"},
//	{61, "[F3]", "[F3]"},
//	{62, "[F4]", "[F4]"},
//	{63, "[F5]", "[F5]"},
//	{64, "[F6]", "[F6]"},
//	{65, "[F7]", "[F7]"},
//	{66, "[F8]", "[F8]"},
//	{67, "[F9]", "[F9]"},
//	{68, "[F10]", "[F10]"},
//	{69, "[NUMLOCK]", "[NUMLOCK]"},
//	{70, "[SCRL]", "[SCRL]"},
// Numlock control begin
//	{71, "[HOME]", "7"},
//	{72, "[UP]", "8"},
//	{73, "[PGUP]", "9"},
	{74, "", "-"},
//	{75, "[LEFT]", "4"},
	{76, "", "5"},
//	{77, "[RIGHT]", "6"},
	{78, "", "+"},
	{79, "", "1"},
	{80, "", "2"},
	{81, "", "3"},
	{82, "", "0"},
	{83, "", "."},
//	{84, "[PRTSCR]", "[PRTSCR]"},
//	{85, "", ""},
//	{86, "", ""},
//	{87, "[F11]", "[F11]"},
//	{88, "[F12]", "[F12]"},
	{89, "", ""},
//	{90, "[PAUSE]", "[PAUSE]"},
//	{91, "[INSERT]", "[INSERT]"},
//	{92, "[HOME]", "[HOME]"},
//	{93, "[PGUP]", "[PGUP]"},
	{94, "", "/"},
// Numlock control end
//	{95, "[DEL]", "[DEL]"},
//	{96, "[END]", "[END]"},
//	{97, "[PGDN]", "[PGDN]"},
//	{98, "[RALT]", "[RALT]"},
//	{99, "[RCTRL]", "[RCTRL]"},
//	{100, "[UP]", "[UP]"},
//	{101, "[LEFT]", "[LEFT]"},
//	{102, "[DOWN]", "[DOWN]"},
//	{103, "[RIGHT]", "[RIGHT]"},
	{104, "\r", "\r"},
//	{105, "[MOUSE]", "[MOUSE]"},
	{0, "", NULL}
};

static const char *__rrr_input_device_keytoc (
	struct rrr_input_special_key_state *special_key_state,
	int key,
	int is_down
) {
	int *flags = &special_key_state->flags_mode_active;
	int *flags_blocked = &special_key_state->flags_blocked;

	int flags_flip = 0;
	int flags_updown = 0;

	switch (key) {
		case LCTRL:
			flags_updown = SPECIAL_LCTRL;
			break;
		case LSHIFT:
			flags_updown = SPECIAL_LSHIFT;
			break;
		case RSHIFT:
			flags_updown = SPECIAL_RSHIFT;
			break;
		case LALT:
			flags_updown = SPECIAL_LALT;
			break;
		case CAPS:
			flags_flip = SPECIAL_CAPS;
			break;
		case NUMLOCK:
			flags_flip = SPECIAL_NUMLOCK;
			break;
		case RCTRL:
			flags_updown = SPECIAL_RCTRL;
			break;
		default:
			break;
	};

	if (flags_flip) {
		int cur = (*flags) & flags_flip;
		int blocked = (*flags) & flags_flip;
		if (is_down) {
			if (!cur) {
				(*flags) |= flags_flip;
				(*flags_blocked) |= flags_flip;
			}
		}
		else {
			if (cur && !blocked) {
				(*flags) &= ~flags_flip;
			}
			(*flags_blocked) &= ~flags_flip;
		}
	}
	else if (flags_updown) {
		if (is_down) {
			(*flags) |= flags_updown;
		}
		else {
			(*flags) &= ~flags_updown;
		}
	}
	else if (is_down) {
		for (int i = 0; map[i].key != 0; i++) {
			const struct map *def = &map[i];
			int is_upper = 0;
			if (key == def->key) {
				if (key > 71) {
					is_upper = (((*flags) & SPECIAL_NUMLOCK) != 0);
				}
				else {
					is_upper |= (((*flags) & SPECIAL_LSHIFT) != 0);
					is_upper |= (((*flags) & SPECIAL_RSHIFT) != 0);
					if ((*flags) & SPECIAL_CAPS) {
						is_upper = !is_upper;
					}
				}
				return (is_upper ? def->upper : def->lower);
			}
		}
	}

	return NULL;
}

int rrr_input_device_grab (int fd) {
#ifdef RRR_WITH_LINUX_INPUT
	return rrr_input_linux_device_grab(fd);
#else
	(void)(fd);
	return 0;
#endif
}

int rrr_input_device_read_key_character (
		char *c,
		int fd,
		int socket_read_flags
) {
	int ret = 0;

	*c = 0;

	struct rrr_input_special_key_state *special_key_state = rrr_socket_get_private_data_from_fd (
			fd,
			RRR_SOCKET_PRIVATE_DATA_CLASS_INPUT_DEVICE,
			sizeof(*special_key_state)
	);

	if (special_key_state == NULL) {
		RRR_MSG_0("Could not get private state in rrr_input_device_read_key_character\n");
		ret = RRR_READ_HARD_ERROR;
		goto out;
	}

	unsigned int key = 0;
	unsigned int is_down = 0;

#ifdef RRR_WITH_LINUX_INPUT
	if ((ret = rrr_input_linux_device_read_key (
			&key,
			&is_down,
			fd,
			socket_read_flags
	)) != 0) {
		goto out;
	}
/* Add elsif for other platforms here */
#else
	(void)(key);
	(void)(is_down);
	RRR_MSG_0("Error: Input device reading not implemented on this platform\n");
	ret = RRR_READ_HARD_ERROR;
	goto out;
#endif

#ifdef RRR_WITH_LINUX_INPUT /* Add OR for other platforms here */
	const char *result = __rrr_input_device_keytoc(special_key_state, key, is_down);
	if (result != NULL) {
		*c = *result;
	}
#endif

	out:
	return ret;
}

