# BLOCK DEVICE LOGGER README

## ABOUT

Block Device Logger which writes and reads directly to or from a
block device (e.g. USB-memory) without using a filesystem. It can
also use a fixed size file. BDL tries to minimize the strain on
individual parts of a device by using the whole device in a
round-robin fashion, with metadata to aid searcing spread around
at fixed points.

A BDL structure consist of a header at the start of the device
which is only written to when first initializing the device. Fixed
size blocks of data are then written after this header. A region
consists of many blocks (usually 128MB) before ending with a hint
block which contains information about where to find the most recent
block before it. The hint blocks and other blocks are not pre-
initialized, and BDL merely considers any block with invalid checksum
to be free space.

Backup hint blocks are placed half way inside each region. If a
hintblock is corrupt, we attempt to recover the backup.

The data blocks have a timestamp and a user defined identifier. When
writing a new entry, BDL searches the hint blocks to find unused
space. If the device was full, the oldest data block is overwritten,
and the rest of this region is also invalidated. The hint blocks are
always updated on writes. Timestamp of new entries must be larger than
all exisiting entries.

## INITIALIZATION

To initialize a device, the user must first overwrite the start of it
with zeros. This is to prevent accidental overwrites of filesystems.
It is possible to choose which block size to use, and data written
has to be less than the block size minus the block header size.

Only the master header is written at initialization, the rest of the
structure is created dynamically on data writes. If an existing
structure is present on a device, it can be used if the block size
happen to match the new blocksize. To prevent this, the hint blocks
has to be overwritten.

## CHECKSUMS

All blocks are checksummed with CRC32. If the master header is
corrupted, no operations may be performed. If a hint block or
data block is corrupted, it is considered free space.

## COMMANDS
### bdl init dev={DEVICE[@SIZE[kMG]]} [bs=NUM] [hpad=NUM] [padchar=HEX8]

Initializes a device by writing a new header.
```
dev		Device or file to initialize
		May specify @SIZE to reduce the space actually used
bs		The fixed size of blocks and hint blocks,
		must be dividable by 256
hpad		The size of the master header, can be used to change the
		position of hint blocks if desirable.
padchar		The character to use for padding blocks in hex, defaults to 0xff.
		Correct value may relieve strain on some memory chips.
```
### bdl write dev={DEVICE} [timestamp=NUM] [faketimestamp=NUM] [appdata=HEX64] {DATA} 

Write a new data block to the next free location or overwrite oldest entry.

```
appdata			Save application-specific data ignored by BDL. Default is 0.
timestamp		Set a timestamp manually in microseconds. Default is current time.
faketimestamp	If the timestamp is equal to the last entry, increment it by 1
				up to NUM times. Error occurs when NUM is exceeded.
```

### bdl read [ts_gteq=NUM]

Read blocks and print to STDOUT.

```
ts_gteq		Specifiy a minimum timestamp of blocks to print. Default is 0.
limit		Stop after this many entries are found. 0 means no limit (default).
```

### bdl open dev={DEVICE}

Opens an interactive session. Device specified is kept open until "close" is called.
Commands which require dev={DEVICE} now uses the open device instead, and attempts
to specify it will fail the program.

### bdl clear dev={DEVICE}

Clear all hint blocks
