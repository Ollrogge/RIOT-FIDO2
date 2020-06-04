#ifndef USB_CTAP_HID_H
#define USB_CTAP_HID_H

#include <stdint.h>
#include "usb/usbus/hid.h"


#define USB_HID_CTAP_PROTOCOL_VERSION 2


#define CTAPHID_INIT_PAYLOAD_SIZE  (CONFIG_USBUS_HID_INTERRUPT_EP_SIZE-7)
#define CTAPHID_CONT_PAYLOAD_SIZE  (CONFIG_USBUS_HID_INTERRUPT_EP_SIZE-5)

#define USB_HID_CTAP_INIT_PACKET 0x80
#define USB_HID_CTAP_CONT_PACKET 0x00

#define USB_HID_CTAP_COMMAND_PING 0x01
#define USB_HID_CTAP_COMMAND_MSG 0x03
#define USB_HID_CTAP_COMMAND_LOCK 0x04
#define USB_HID_CTAP_COMMAND_INIT 0x06
#define USB_HID_CTAP_COMMAND_WINK 0x08
#define USB_HID_CTAP_COMMAND_CBOR 0x10
#define USB_HID_CTAP_COMMAND_CANCEL 0x11
#define USB_HID_CTAP_COMMAND_KEEPALIVE 0x3b
#define USB_HID_CTAP_COMMAND_ERROR 0x3f

#define USB_HID_CTAP_CAPABILITY_WINK 0x01 // If set to 1, authenticator implements CTAPHID_WINK function
#define USB_HID_CTAP_CAPABILITY_CBOR 0x04 // If set to 1, authenticator implements CTAPHID_CBOR function 
#define USB_HID_CTAP_CAPABILITY_NMSG 0x08 // If set to 1, authenticator DOES NOT implement CTAPHID_MSG function (CTAP1 / U2F)

#define USB_HID_CTAP_BROADCAST_CID 0xffffffff


void hid_ctap_handle_packet(uint8_t* pkt_raw);

typedef struct 
{
    uint8_t cmd;
    uint8_t bcnth;
    uint8_t bcntl;
    uint8_t payload[CTAPHID_INIT_PAYLOAD_SIZE];
} usb_hid_ctap_init_pkt_t;

typedef struct 
{
    uint8_t seq;
    uint8_t payload[CTAPHID_CONT_PAYLOAD_SIZE];
} usb_hid_ctap_cont_pkt_t;

typedef struct
{
    uint32_t cid;
    union {
        usb_hid_ctap_init_pkt_t init;
        usb_hid_ctap_cont_pkt_t cont;
    } pkt;
} usb_hid_ctap_pkt_t;

typedef struct __attribute__((packed))
{
    uint8_t nonce[8];
    uint32_t cid;
    uint8_t protocol_version;
    uint8_t version_major;
    uint8_t version_minor;
    uint8_t build_version;
    uint8_t capabilities;
} usb_hid_ctap_init_resp_t;

#endif