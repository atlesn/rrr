#define PERL_NO_GET_CONTEXT
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <stdlib.h>

#include "../../../../../lib/perl5.h"

MODULE = rrr::rrr_helper::rrr_settings PACKAGE = rrr::rrr_helper::rrr_settings PREFIX = rrr_perl5_settings_
PROTOTYPES: ENABLE

SV *
rrr_perl5_settings_get(settings,key)
	HV *settings
	const char *key
	
int
rrr_perl5_settings_set(settings,key,value)
	HV *settings
	const char *key
	const char *value