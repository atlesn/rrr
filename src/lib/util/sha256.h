#ifndef RRR_SHA256_H
#define RRR_SHA256_H

#include <stdint.h>
#include <stdlib.h>

#define RRR_SHA256_SIZE 32

void rrr_sha256_calculate (uint8_t hash[RRR_SHA256_SIZE], const void *input, size_t len);

#endif
