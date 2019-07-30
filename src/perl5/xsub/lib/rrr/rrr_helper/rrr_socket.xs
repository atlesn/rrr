#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <stdlib.h>

MODULE = rrr::rrr_helper::rrr_socket PACKAGE = rrr::rrr_helper::rrr_socket
PROTOTYPES: ENABLE

unsigned int
rand()
