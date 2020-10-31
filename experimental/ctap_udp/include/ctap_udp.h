#ifndef CTAP_UDP_H
#define CTAP_UDP_H

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

void ctap_udp_create(void);

int ctap_udp_read_timeout(void *buffer, size_t len, uint32_t timeout);

void ctap_udp_write(const void* buffer, size_t len);

#ifdef __cplusplus
}
#endif
#endif