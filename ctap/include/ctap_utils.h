#ifndef CTAP_UTILS_H
#define CTAP_UTILS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void print_hex(const uint8_t* data, size_t size);

int timestamp(void);

bool hexstr_to_array(const char* str, uint8_t* arr, size_t len);

#ifdef __cplusplus
}
#endif
#endif