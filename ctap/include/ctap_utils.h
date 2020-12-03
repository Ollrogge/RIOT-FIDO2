#ifndef CTAP_UTILS_H
#define CTAP_UTILS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void print_hex(uint8_t* data, size_t size);

int timestamp(void);

#ifdef __cplusplus
}
#endif
#endif