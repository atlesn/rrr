/*
 *  sha.cpp
 *
 *  Copyright (C) 1998, 2009
 *  Paul E. Jones <paulej@packetizer.com>
 *  All Rights Reserved
 *
 *****************************************************************************
 *  $Id: sha.c 12 2009-06-22 19:34:25Z paulej $
 *****************************************************************************
 *
 *  Description:
 *      This utility will display the message digest (fingerprint) for
 *      the specified file(s).
 *
 *  Portability Issues:
 *      None.
 */

#include <stdio.h>
#include <string.h>
#ifdef WIN32
#include <io.h>
#endif
#include <fcntl.h>
#include "../../lib/sha1/sha1.h"

#include "../lib/rrr_config.h"
RRR_CONFIG_DEFINE_DEFAULT_LOG_PREFIX("sha");

/*
 *  Function prototype
 */
void usage(void);


/*  
 *  main
 *
 *  Description:
 *      This is the entry point for the program
 *
 *  Parameters:
 *      argc: [in]
 *          This is the count of arguments in the argv array
 *      argv: [in]
 *          This is an array of filenames for which to compute message
 *          digests
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *
 */
int main(int argc, char *argv[])
{
    rrr_SHA1Context sha;                /* SHA-1 context                 */
    FILE        *fp;                /* File pointer for reading files*/
    char        c;                  /* Character read from file      */
    int         i;                  /* Counter                       */
    int         reading_stdin;      /* Are we reading standard in?   */
    int         read_stdin = 0;     /* Have we read stdin?           */

    /*
     *  Check the program arguments and print usage information if -?
     *  or --help is passed as the first argument.
     */
    if (argc > 1 && (!strcmp(argv[1],"-?") ||
        !strcmp(argv[1],"--help")))
    {
        usage();
        return 1;
    }

    /*
     *  For each filename passed in on the command line, calculate the
     *  SHA-1 value and display it.
     */
    for(i = 0; i < argc; i++)
    {
        /*
         *  We start the counter at 0 to guarantee entry into the for
         *  loop. So if 'i' is zero, we will increment it now.  If there
         *  is no argv[1], we will use STDIN below.
         */
        if (i == 0)
        {
            i++;
        }

        if (argc == 1 || !strcmp(argv[i],"-"))
        {
#ifdef WIN32
            setmode(fileno(stdin), _O_BINARY);
#endif
            fp = stdin;
            reading_stdin = 1;
        }
        else
        {
            if (!(fp = fopen(argv[i],"rb")))
            {
                fprintf(stderr,
                        "sha: unable to open file %s\n",
                        argv[i]);
                return 2;
            }
            reading_stdin = 0;
        }

        /*
         *  We do not want to read STDIN multiple times
         */
        if (reading_stdin)
        {
            if (read_stdin)
            {
                continue;
            }

            read_stdin = 1;
        }

        /*
         *  Reset the SHA-1 context and process input
         */
        rrr_SHA1Reset(&sha);

        c = (char) fgetc(fp);
        while(!feof(fp))
        {
            rrr_SHA1Input(&sha, (const unsigned char *) &c, 1);
            c = (char) fgetc(fp);
        }

        if (!reading_stdin)
        {
            fclose(fp);
        }

        if (!rrr_SHA1Result(&sha))
        {
            fprintf(stderr,
                    "sha: could not compute message digest for %s\n",
                    reading_stdin?"STDIN":argv[i]);
        }
        else
        {
            printf( "%08X %08X %08X %08X %08X - %s\n",
                    sha.Message_Digest[0],
                    sha.Message_Digest[1],
                    sha.Message_Digest[2],
                    sha.Message_Digest[3],
                    sha.Message_Digest[4],
                    reading_stdin?"STDIN":argv[i]);
        }
    }

    return 0;
}

/*  
 *  usage
 *
 *  Description:
 *      This function will display program usage information to the
 *      user.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *
 */
void usage(void)
{
    printf("usage: sha <file> [<file> ...]\n");
    printf("\tThis program will display the message digest\n");
    printf("\tfor files using the Secure Hashing Algorithm (SHA-1).\n");
}
