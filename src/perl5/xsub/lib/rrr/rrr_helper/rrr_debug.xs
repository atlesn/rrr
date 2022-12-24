#define PERL_NO_GET_CONTEXT
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <stdlib.h>
#include <stdint.h>

#include "../../../../../lib/perl5/perl5_xsub.h"

MODULE = rrr::rrr_helper::rrr_debug PACKAGE = rrr::rrr_helper::rrr_debug PREFIX = rrr_perl5_debug_
PROTOTYPES: ENABLE

int
rrr_perl5_debug_msg(debug,level,string)
	HV *debug
	U8 level
	const char *string

int
rrr_perl5_debug_dbg(debug,level,string)
	HV *debug
	U8 level
	const char *string

int
rrr_perl5_debug_err(debug,string)
	HV *debug
	const char *string
