#if defined(__linux__) 
#include <endian.h>
#elif defined(__OpenBSD__) || defined(__FreeBSD__)
#include <sys/endian.h>
#endif
