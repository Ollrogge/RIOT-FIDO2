#ifndef CTAP_TRANS_H
#define CTAP_TRANS_H

#include <stdint.h>
#include "mutex.h"
#include "timex.h"

#ifdef CONFIG_CTAP_USB
#include "ctap_trans_hid.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CTAP_TRANS_USB 0x1
#define CTAP_TRANS_NFC 0x2
#define CTAP_TRANS_BLE 0x3
#define CTAP_TRANS_UDP 0x4

typedef void (*ctap_trans_cb_t)(uint8_t *data, size_t len);

typedef struct ctap_trans_data ctap_trans_data_t;

typedef struct ctap_trans_io_t
{
    ctap_trans_cb_t in;
    ctap_trans_cb_t out;
};

struct ctap_trans_data
{
    uint8_t trans_type;
    uint8_t req_buf[256];
    size_t size;
    bool (*should_cancel)(void);
};

void ctap_trans_init(void);

uint8_t ctap_trans_create(uint8_t type, void* data, size_t len,
                            ctap_trans_cb_t cb);

int ctap_trans_read_timeout(uint8_t type, void* buffer, size_t size,
                            uint32_t timeout);

int ctap_trans_write(uint8_t type, const void *buffer, size_t len);
void ctap_trans_write_keepalive(uint8_t type, uint8_t status);

#ifdef __cplusplus
}
#endif
#endif