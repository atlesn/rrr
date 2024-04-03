#define PERL_NO_GET_CONTEXT
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <stdlib.h>

#include "../../../../../lib/perl5/perl5_xsub.h"
#include "../../../../../lib/messages/msg_msg_struct.h"

MODULE = rrr::rrr_helper::rrr_message PACKAGE = rrr::rrr_helper::rrr_message PREFIX = rrr_perl5_message_
PROTOTYPES: ENABLE

TYPEMAP: <<HERE
	AV* T_AVREF_REFCOUNT_FIXED
HERE

BOOT:
	{
		HV *stash = gv_stashpv("rrr::rrr_helper::rrr_message", 0 /* Don't create */);

		newCONSTSUB(stash, "MSG_TYPE_MSG", newSVuv(MSG_TYPE_MSG));
		newCONSTSUB(stash, "MSG_TYPE_TAG", newSVuv(MSG_TYPE_TAG));
		newCONSTSUB(stash, "MSG_TYPE_GET", newSVuv(MSG_TYPE_GET));
		newCONSTSUB(stash, "MSG_TYPE_PUT", newSVuv(MSG_TYPE_PUT));
		newCONSTSUB(stash, "MSG_TYPE_DEL", newSVuv(MSG_TYPE_DEL));
		newCONSTSUB(stash, "MSG_TYPE_OPT", newSVuv(MSG_TYPE_OPT));
		newCONSTSUB(stash, "MSG_TYPE_PAT", newSVuv(MSG_TYPE_PAT));
	}

unsigned int
rrr_perl5_message_send(message)
	HV *message

unsigned int
rrr_perl5_message_clear_array(message)
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

unsigned int
rrr_perl5_message_clear_tag(message,tag)
	HV *message
	const char *tag
	
unsigned int
rrr_perl5_message_ip_set (message,ip,port)
	HV *message
	const char *ip
	UV port

#define PPCODE_PUSH_AV_TO_STACK()                          \
    if (RETVAL == NULL) {                                  \
        EXTEND(SP, 1);                                     \
        XSRETURN_UNDEF; /* Push undef and return */        \
    }                                                      \
    int len = av_len(RETVAL) + 1;                          \
    if (len > 0) {                                         \
        EXTEND(SP, len);                                   \
        for (int i = 0; i < len; i++) {                    \
            PUSHs(sv_2mortal(av_shift(RETVAL)));           \
        }                                                  \
    }                                                      \
    SvREFCNT_dec((SV*)RETVAL)                              \

AV *
rrr_perl5_message_ip_get (message)
	HV *message
	PPCODE:
		RETVAL = rrr_perl5_message_ip_get(message);
		PPCODE_PUSH_AV_TO_STACK();

unsigned int
rrr_perl5_message_ip_clear (message)
	HV *message

SV *
rrr_perl5_message_ip_get_protocol (message)
	HV *message

unsigned int
rrr_perl5_message_ip_set_protocol (message, protocol)
	HV *message
	const char *protocol

UV
rrr_perl5_message_type_get (message)
	HV *message

unsigned int
rrr_perl5_message_type_set (message, type)
	HV *message
	UV type

AV *
rrr_perl5_message_get_tag_all(message,tag)
	HV *message
	const char *tag
	PPCODE:
		RETVAL = rrr_perl5_message_get_tag_all(message,tag);
		PPCODE_PUSH_AV_TO_STACK();
		
AV *
rrr_perl5_message_get_position (message,pos)
	HV *message
	UV pos
	PPCODE:
		RETVAL = rrr_perl5_message_get_position(message,pos);
		PPCODE_PUSH_AV_TO_STACK();

SV *
rrr_perl5_message_count_positions (message)
	HV *message

AV *rrr_perl5_message_get_tag_names (message)
	HV *message
	PPCODE:
		RETVAL = rrr_perl5_message_get_tag_names(message);
		PPCODE_PUSH_AV_TO_STACK();

AV *rrr_perl5_message_get_tag_counts (message)
	HV *message
	PPCODE:
		RETVAL = rrr_perl5_message_get_tag_counts(message);
		PPCODE_PUSH_AV_TO_STACK();
