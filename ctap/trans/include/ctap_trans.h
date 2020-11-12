#ifndef CTAP_TRANS_H
#define CTAP_TRANS_H

#include <stdint.h>
#include "mutex.h"
#include "timex.h"

#include "ctap_trans_hid.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CTAP_TRANS_USB 0x1
#define CTAP_TRANS_NFC 0x2
#define CTAP_TRANS_BLE 0x3
#define CTAP_TRANS_UDP 0x4

void ctap_trans_init(void);

uint8_t ctap_trans_create(uint8_t type, void* data, size_t len);

int ctap_trans_read_timeout(uint8_t type, void* buffer, size_t size,
                            uint32_t timeout);

int ctap_trans_write(uint8_t type, const void *buffer, size_t len);
void ctap_trans_write_keepalive(uint8_t type, uint8_t status);

#ifdef __cplusplus
}
#endif
#endif