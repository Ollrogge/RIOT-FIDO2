
#ifndef CTAP_UTILS_H
#define CTAP_UTILS_H

#define ENABLE_DEBUG    (1)
#include "debug.h"

#include "xtimer.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void print_hex(uint8_t* data, size_t size);

uint32_t timestamp(void);

#ifdef __cplusplus
}
#endif
#endif