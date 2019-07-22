/*

Block Device Logger

Copyright (C) 2018 Atle Solbakken atle@goliathdns.no

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

#ifndef BDL_DEFAULTS_H
#define BDL_DEFAULTS_H

/* Blocksystem version */
#define BDL_BLOCKSYSTEM_VERSION 4

/* Blocks are allocated on the stack, don't make them too big */
#define BDL_DEFAULT_BLOCKSIZE 512
#define BDL_MINIMUM_BLOCKSIZE 512
#define BDL_MAXIMUM_BLOCKSIZE 8192
#define BDL_BLOCKSIZE_DIVISOR 256

/* Default header pad 2kB */
#define BDL_DEFAULT_HEADER_PAD (256*1024)
#define BDL_MINIMUM_HEADER_PAD 1024
#define BDL_HEADER_PAD_DIVISOR 256

/* Maximum length of commands in session/stdin mode */
#define BDL_MAXIMUM_CMDLINE_LENGTH 4096

/* How much to write to memory map before syncing */
#define BDL_MMAP_SYNC_SIZE 65536

/*
 * Hint blocks are spread around on the device and tells us where we wrote
 * the last block. The hint block after an area contains information about
 * the last block written between it and the previous hint block. The hint
 * blocks are not initialized before used the first write, and if an invalid
 * hint block is found, we assume unused space and start to write directly
 * after the previous hint block.
 */

/* Default hint block spacing is 8MB, one is also placed at the very end */
#define BDL_DEFAULT_HINTBLOCK_SPACING (8 * 1024 * 1024)
#define BDL_HINTBLOCK_BACKUP_POSITION (-BDL_DEFAULT_HINTBLOCK_SPACING/2)

/* For devices smaller than 256MB, use up to four blocks plus one at the end */
#define BDL_SMALL_SIZE_THRESHOLD (256 * 1024 * 1024)
#define BDL_DEFAULT_HINT_BLOCK_COUNT_SMALL 4

#define BDL_DEFAULT_PAD_CHAR 0xff

#define BDL_NEW_DEVICE_BLANK_START_SIZE 1024

#endif
