#define PERL_NO_GET_CONTEXT
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <stdlib.h>

#include "../../../../../lib/perl5/perl5.h"

MODULE = rrr::rrr_helper::rrr_message PACKAGE = rrr::rrr_helper::rrr_message PREFIX = rrr_perl5_message_
PROTOTYPES: ENABLE

unsigned int
rrr_perl5_message_send(message)
	HV *message