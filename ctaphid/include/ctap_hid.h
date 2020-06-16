#ifndef CTAP_HID_H
#define CTAP_HID_H

#include <stdint.h>
#include "usb/usbus/hid.h"

#define CTAP_HID_INIT_PAYLOAD_SIZE  (CONFIG_USBUS_HID_INTERRUPT_EP_SIZE-7)   /* endpoint size - init packet metadata */
#define CTAP_HID_CONT_PAYLOAD_SIZE  (CONFIG_USBUS_HID_INTERRUPT_EP_SIZE-5)   /* endpoint size - cont packet metadata */

#define CTAP_HID_PROTOCOL_VERSION 0x02

#define CTAP_HID_INIT_PACKET 0x80
#define CTAP_HID_CONT_PACKET 0x00

#define CTAP_HID_COMMAND_PING (0x01 | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_MSG (0x03 | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_LOCK (0x04 | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_INIT (0x06 | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_WINK (0x08 | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_CBOR (0x10 | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_CANCEL (0x11 | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_KEEPALIVE (0x3b | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_ERROR (0x3f | CTAP_HID_INIT_PACKET)

#define CTAP_HID_CAPABILITY_WINK 0x01       /* If set to 1, authenticator implements CTAPHID_WINK function */
#define CTAP_HID_CAPABILITY_CBOR 0x04       /* If set to 1, authenticator implements CTAPHID_CBOR function */
#define CTAP_HID_CAPABILITY_NMSG 0x08       /* If set to 1, authenticator DOES NOT implement CTAPHID_MSG function (CTAP1 / U2F) */

#define CTAP_HID_BROADCAST_CID 0xffffffff

#define CTAP_HID_ERROR_INVALID_CMD 0x01         /* The command in the request is invalid */
#define CTAP_HID_ERROR_INVALID_PAR 0x02         /* The parameter(s) in the request is invalid */
#define CTAP_HID_ERROR_INVALID_LEN 0x03         /* The length field (BCNT) is invalid for the request */
#define CTAP_HID_ERROR_INVALID_SEQ 0x04         /* The sequence does not match expected value */
#define CTAP_HID_ERROR_MSG_TIMEOUT 0x05         /* The message has timed out */
#define CTAP_HID_ERROR_CHANNEL_BUSY 0x06        /* The device is busy for the requesting channel */
#define CTAP_HID_ERROR_LOCK_REQUIRED 0x0a       /* Command requires channel lock */
#define CTAP_HID_ERROR_INVALID_CHANNEL 0x0b     /* CID is not valid. */
#define CTAP_HID_ERROR_OTHER 0x7f               /* Unspecified error */

#define CTAP_HID_CIDS_MAX 0x08

void ctap_hid_handle_packet(uint8_t* pkt_raw);

typedef struct
{
    uint8_t cmd;
    uint8_t bcnth;
    uint8_t bcntl;
    uint8_t payload[CTAP_HID_INIT_PAYLOAD_SIZE];
} ctap_hid_init_pkt_t;

typedef struct
{
    uint8_t seq;
    uint8_t payload[CTAP_HID_CONT_PAYLOAD_SIZE];
} ctap_hid_cont_pkt_t;

typedef struct
{
    uint32_t cid;
    union {
        ctap_hid_init_pkt_t init;
        ctap_hid_cont_pkt_t cont;
    };
} ctap_hid_pkt_t;

typedef struct __attribute__((packed))
{
    uint8_t nonce[8];
    uint32_t cid;
    uint8_t protocol_version;
    uint8_t version_major;
    uint8_t version_minor;
    uint8_t build_version;
    uint8_t capabilities;
} ctap_hid_init_resp_t;

typedef struct
{
    uint8_t taken;
    uint32_t cid;
} ctap_hid_cid_t;

#endif