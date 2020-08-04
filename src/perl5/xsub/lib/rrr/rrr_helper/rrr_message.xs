#define PERL_NO_GET_CONTEXT
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <stdlib.h>

#include "../../../../../lib/perl5/perl5_xsub.h"

MODULE = rrr::rrr_helper::rrr_message PACKAGE = rrr::rrr_helper::rrr_message PREFIX = rrr_perl5_message_
PROTOTYPES: ENABLE

TYPEMAP: <<HERE
	AV* T_AVREF_REFCOUNT_FIXED
HERE

unsigned int
rrr_perl5_message_send(message)
	HV *message

unsigned int
rrr_perl5_message_push_tag_blob(message,tag,value,size)
 	HV *message
 	const char *tag
 	const char *value
 	size_t size
 
unsigned int
rrr_perl5_message_push_tag_str(message,tag,str)
	HV *message
	const char *tag
	const char *str
	
unsigned int
rrr_perl5_message_push_tag_h(message,tag,values)
	HV *message
	const char *tag
	SV *values

unsigned int
rrr_perl5_message_push_tag_fixp(message,tag,values)
	HV *message
	const char *tag
	SV *values
 
unsigned int
rrr_perl5_message_push_tag(message,tag,value)
	HV *message
	const char *tag
	SV *value

unsigned int
rrr_perl5_message_set_tag_blob(message,tag,value,size)
 	HV *message
 	const char *tag
 	const char *value
 	size_t size
 
unsigned int
rrr_perl5_message_set_tag_str(message,tag,str)
	HV *message
	const char *tag
	const char *str
	
unsigned int
rrr_perl5_message_set_tag_h(message,tag,values)
	HV *message
	const char *tag
	SV *values
	
unsigned int
rrr_perl5_message_set_tag_fixp(message,tag,values)
	HV *message
	const char *tag
	SV *values

AV *
rrr_perl5_message_get_tag(message,tag)
	HV *message
	const char *tag
	PPCODE:
		RETVAL = rrr_perl5_message_get_tag(message,tag);
		while (av_len(RETVAL) >= 0) {
			SV *test = av_shift(RETVAL);
			PUSHs(sv_2mortal(test));
		}
		SvREFCNT_dec((SV*)RETVAL);
		
SV *rrr_perl5_message_get_tag_at(message,tag,pos)
	HV *message
	const char *tag
	size_t pos