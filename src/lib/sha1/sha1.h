/*
 *  sha1.h
 *
 *  Copyright (C) 1998, 2009
 *  Paul E. Jones <paulej@packetizer.com>
 *  All Rights Reserved
 *
 *****************************************************************************
 *  $Id: sha1.h 12 2009-06-22 19:34:25Z paulej $
 *****************************************************************************
 *
 *  Description:
 *      This class implements the Secure Hashing Standard as defined
 *      in FIPS PUB 180-1 published April 17, 1995.
 *
 *      Many of the variable names in the SHA1Context, especially the
 *      single character names, were used because those were the names
 *      used in the publication.
 *
 *      Please read the file sha1.c for more information.
 *
 *  Changelog:
 *     - 2020-09-17: Ensure integer sizes
 *       Atle Solbakken <atle@goliathdns.no>
 *     - 2020-09-17: Add SHA1toBE function
 *       Atle Solbakken <atle@goliathdns.no>
 *
 */

#ifndef _SHA1_H_
#define _SHA1_H_

#include <inttypes.h>

/* 
 *  This structure will hold context information for the hashing
 *  operation
 */
typedef struct rrr_SHA1Context
{
    uint32_t Message_Digest[5]; /* Message Digest (output)          */

    unsigned Length_Low;        /* Message length in bits           */
    unsigned Length_High;       /* Message length in bits           */

    unsigned char Message_Block[64]; /* 512-bit message blocks      */
    int Message_Block_Index;    /* Index into message block array   */

    int Computed;               /* Is the digest computed?          */
    int Corrupted;              /* Is the message digest corruped?  */
} rrr_SHA1Context;

/*
 *  Function Prototypes
 */
void rrr_SHA1Reset(rrr_SHA1Context *);
int rrr_SHA1Result(rrr_SHA1Context *);
void rrr_SHA1toBE(rrr_SHA1Context *context);
void rrr_SHA1Input( rrr_SHA1Context *,
                const unsigned char *,
                unsigned);

#endif
