#ifndef CTAP_UDP_H
#define CTAP_UDP_H

#include <stdint.h>
#include <stdio.h>

#include "ctap_trans.h"

#ifdef __cplusplus
extern "C" {
#endif

void ctap_udp_create(ctap_trans_cb_t cb);

void ctap_udp_write(const void* buffer, size_t len);

#ifdef __cplusplus
}
#endif
#endif