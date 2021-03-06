/*
 * Copyright (C) 2020 Nils Ollrogge
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    CTAP2 implementation
 * @ingroup     FIDO2
 * @brief       CTAP2 implementation
 *
 * @{
 *
 * @file
 * @brief       CTAP2 interface
 *
 * @author      Nils Ollrogge <nils-ollrogge@outlook.de>
 */

#ifndef CTAP_HID_H
#define CTAP_HID_H

#include <stdint.h>
#include "mutex.h"
#include "timex.h"

#ifdef CONFIG_CTAP_NATIVE
#define CONFIG_USBUS_HID_INTERRUPT_EP_SIZE 0x40
#include <stdbool.h>
#else
#include "usb/usbus/hid.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name CTAP_HID packet type payload sizes
 *
 * @{
 */
#define CTAP_HID_INIT_PAYLOAD_SIZE  (CONFIG_USBUS_HID_INTERRUPT_EP_SIZE-7)   /**< endpoint size - init packet metadata */
#define CTAP_HID_CONT_PAYLOAD_SIZE  (CONFIG_USBUS_HID_INTERRUPT_EP_SIZE-5)   /**< endpoint size - cont packet metadata */
/** @} */

/**
 * @brief CTAP_HID protocol version
 */
#define CTAP_HID_PROTOCOL_VERSION 0x02

/**
 * @name CTAP_HID packet type identifiers
 *
 * @{
 */
#define CTAP_HID_INIT_PACKET 0x80
#define CTAP_HID_CONT_PACKET 0x00
/** @} */

/* todo: both timeouts are arbitrary */
#define CTAP_HID_TRANSACTION_TIMEOUT    (0.75 * US_PER_SEC) /**< cont packet not sent in time */

/**
 * @brief CTAP_HID max message payload size
 *
 * CTAP specification (version 20190130) section 8.2.4.
 */
#define CTAP_HID_BUFFER_SIZE 7609

/**
 * @name CTAP_HID commands
 *
 * @{
 */
#define CTAP_HID_COMMAND_PING       (0x01 | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_MSG        (0x03 | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_LOCK       (0x04 | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_INIT       (0x06 | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_WINK       (0x08 | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_CBOR       (0x10 | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_CANCEL     (0x11 | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_KEEPALIVE  (0x3b | CTAP_HID_INIT_PACKET)
#define CTAP_HID_COMMAND_ERROR      (0x3f | CTAP_HID_INIT_PACKET)
/** @} */

/**
 * @name CTAP_HID capability flags
 *
 * @{
 */
#define CTAP_HID_CAPABILITY_WINK 0x01   /**< If set, authenticator implements CTAPHID_WINK function */
#define CTAP_HID_CAPABILITY_CBOR 0x04   /**< If set, authenticator implements CTAPHID_CBOR function */
#define CTAP_HID_CAPABILITY_NMSG 0x08   /**< If set, authenticator DOES NOT implement CTAPHID_MSG function (CTAP1 / U2F) */
/** @} */

/**
 * @name CTAP_HID error codes
 *
 * @{
 */
#define CTAP_HID_OK                   0x00    /**< Success */
#define CTAP_HID_ERR_INVALID_CMD      0x01    /**< The command in the request is invalid */
#define CTAP_HID_ERR_INVALID_PAR      0x02    /**< The parameter(s) in the request is invalid */
#define CTAP_HID_ERR_INVALID_LEN      0x03    /**< The length field (BCNT) is invalid for the request */
#define CTAP_HID_ERR_INVALID_SEQ      0x04    /**< The sequence does not match expected value */
#define CTAP_HID_ERR_MSG_TIMEOUT      0x05    /**< The message has timed out */
#define CTAP_HID_ERR_CHANNEL_BUSY     0x06    /**< The device is busy for the requesting channel */
#define CTAP_HID_ERR_LOCK_REQUIRED    0x0a    /**< Command requires channel lock */
#define CTAP_HID_ERR_INVALID_CHANNEL  0x0b    /**< CID is not valid. */
#define CTAP_HID_ERR_OTHER            0x7f    /**< Unspecified error */
/** @} */

/**
 * @name CTAP_HID status codes
 *
 * @{
 */
#define CTAP_HID_STATUS_PROCESSING 0x01
#define CTAP_HID_STATUS_UPNEEDED   0x02
/** @} */

/**
 * @brief CTAP_HID max number of channels
 *
 */
#define CTAP_HID_CIDS_MAX 0x08

/**
 * @brief CTAP_HID broadcast channel identifier
 *
 */
#define CTAP_HID_BROADCAST_CID 0xffffffff

/**
 * @name CTAP_HID buffer status
 *
 * @{
 */
#define CTAP_HID_BUFFER_STATUS_BUFFERING    0x00
#define CTAP_HID_BUFFER_STATUS_DONE         0x01
#define CTAP_HID_BUFFER_STATUS_ERROR        0x02
/** @} */

/**
 * @brief CTAP_HID initialization packet struct
 *
 */
typedef struct
{
    uint8_t cmd;
    uint8_t bcnth;
    uint8_t bcntl;
    uint8_t payload[CTAP_HID_INIT_PAYLOAD_SIZE];
} ctap_hid_init_pkt_t;

/**
 * @brief CTAP_HID continuation packet struct
 *
 */
typedef struct
{
    uint8_t seq;
    uint8_t payload[CTAP_HID_CONT_PAYLOAD_SIZE];
} ctap_hid_cont_pkt_t;

/**
 * @brief CTAP_HID packet struct
 *
 */
typedef struct
{
    uint32_t cid;
    union {
        ctap_hid_init_pkt_t init;
        ctap_hid_cont_pkt_t cont;
    };
} ctap_hid_pkt_t;

/**
 * @brief CTAP_HID initialization response struct
 *
 */
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

/**
 * @brief CTAP_HID channel identifier struct
 *
 */
typedef struct
{
    uint8_t taken;
    uint32_t cid;
    uint64_t last_used;
} ctap_hid_cid_t;

/**
 * @brief CTAP_HID buffer struct
 *
 */
typedef struct
{
    uint32_t cid;
    uint8_t buffer[CTAP_HID_BUFFER_SIZE];
    uint8_t cmd;
    uint16_t offset;
    int16_t seq;
    uint16_t bcnt;
    uint8_t err;
    bool is_locked;
    bool should_cancel;
    mutex_t should_cancel_mutex;
} ctap_hid_buffer_t;

/**
 * @brief Initialize USB, create needed threads
 *
 */
void ctap_trans_hid_create(void);

/**
 * @brief Handle CTAP_HID packet
 *
 * @param[in] pkt_raw   CTAP_HID packet
 *
 */
void ctap_trans_hid_handle_packet(void *pkt_raw);

/**
 * @brief Send keepalive packet
 *
 * @param[in] status    CTAP_HID status code
 *
 */
void ctap_trans_hid_send_keepalive(uint8_t status);


void ctap_trans_hid_check_timeouts(void);

#ifdef __cplusplus
}
#endif
#endif